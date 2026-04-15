"""
SentinelScan - FastAPI REST API v2
====================================
Day 4 additions:
  - API key authentication on all scan endpoints
  - In-memory rate limiting (tracks requests per IP)
  - Async scan engine: POST /scan/async + GET /scan/{id}
  - Scan history: GET /scans (last 10 scans)
  - Better error handling with structured error responses

New endpoints:
  POST /scan/async          Start scan in background, return scan_id immediately
  GET  /scan/{scan_id}      Poll for status + results  
  GET  /scans               List recent scans
  GET  /health              No auth required (uptime monitors need this)
  GET  /                    No auth required (info page)

Async scan flow (how the dashboard uses this):
  1. POST /scan/async → { scan_id: "abc-123", status: "queued" }
  2. Poll GET /scan/abc-123 every 2s → { status: "running", progress: {...} }
  3. Eventually  GET /scan/abc-123 → { status: "complete", result: {...} }

Learning goals:
  - FastAPI BackgroundTasks for non-blocking endpoints
  - Threading: running CPU-bound tasks without blocking the event loop
  - In-memory state management (scan results dict)
  - UUID generation for unique scan IDs
  - Structured error responses (not just strings)
"""

import time
import uuid
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from scanner.core import SentinelCore, normalize_target, validate_target
from scanner.models import Severity
from api.auth import require_api_key


# ─────────────────────────────────────────────────────────────────────────────
#  IN-MEMORY RATE LIMITER
#  Tracks request timestamps per IP address.
#  Simple sliding window algorithm: count requests in last N seconds.
#
#  Why not use slowapi/Redis?
#  For a portfolio project, a simple in-memory limiter is easier to understand
#  and deploy. In production at scale, you'd use Redis + slowapi.
# ─────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Sliding window rate limiter using Python's collections.deque.

    deque(maxlen=N) is a double-ended queue that auto-drops old items.
    We store request timestamps and count how many fall within our window.

    Usage:
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        if not limiter.allow(client_ip):
            raise HTTPException(429)
    """

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # ip -> deque of timestamps
        self._buckets: Dict[str, deque] = defaultdict(lambda: deque())
        self._lock = threading.Lock()

    def allow(self, client_ip: str) -> bool:
        """Returns True if request is allowed, False if rate limited."""
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets[client_ip]
            # Remove timestamps outside the window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            # Check if under limit
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True

    def remaining(self, client_ip: str) -> int:
        """How many requests remaining in the current window."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._buckets[client_ip]
            active = sum(1 for t in bucket if t >= cutoff)
            return max(0, self.max_requests - active)


# Rate limiters — different limits for different endpoints
# Full scan: 5 per minute (scans are expensive)
# Quick scan: 20 per minute
# Status/info: 60 per minute (polling is expected)
scan_limiter       = RateLimiter(max_requests=5,  window_seconds=60)
quick_limiter      = RateLimiter(max_requests=20, window_seconds=60)
status_limiter     = RateLimiter(max_requests=60, window_seconds=60)


def get_client_ip(request: Request) -> str:
    """Extract client IP, respecting proxy headers (Cloudflare, nginx)."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  IN-MEMORY SCAN STORE
#  Maps scan_id -> scan state dict
#  In production: replace with Redis or a database
# ─────────────────────────────────────────────────────────────────────────────

# scan_id -> {status, started_at, completed_at, target, result, error, progress}
_scans: Dict[str, Dict[str, Any]] = {}
# Keep only last 50 scans in memory to prevent unbounded growth
_scan_history: deque = deque(maxlen=50)
_scans_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
#  PYDANTIC SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL", example="https://example.com")
    timeout: int = Field(default=10, ge=3, le=30)
    include_threat_intel: bool = Field(default=True)
    modules: Optional[List[str]] = Field(default=None)


class FindingResponse(BaseModel):
    title: str
    severity: str
    cvss_score: float
    description: str
    recommendation: str
    evidence: str


class ModuleResponse(BaseModel):
    module: str
    findings: List[FindingResponse]
    passed_checks: List[str]
    error: str


class ScanSummary(BaseModel):
    overall_risk: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    modules_run: List[str]
    scan_duration_seconds: float


class ScanResponse(BaseModel):
    sentinelscan_version: str = "2.0"
    target: str
    scan_time: str
    summary: ScanSummary
    modules: List[ModuleResponse]


class AsyncScanStarted(BaseModel):
    scan_id: str
    status: str
    target: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str  # queued | running | complete | failed
    target: str
    started_at: str
    completed_at: Optional[str] = None
    progress: Optional[Dict[str, Any]] = None
    result: Optional[ScanResponse] = None
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
#  FASTAPI APP
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelScan API",
    description=(
        "Web security vulnerability scanner API. Checks targets for misconfigurations, "
        "CVEs, injection vulnerabilities, and enriches results with real threat intelligence.\n\n"
        "**Authentication:** Pass your API key in the `X-API-Key` header.\n"
        "Default dev key: `sentinel-dev-key-2024`\n\n"
        "**IMPORTANT:** Only scan systems you own or have written permission to test."
    ),
    version="2.0.0",
    contact={"name": "SentinelScan", "url": "https://github.com/shree-aru/sentinelscan"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
#  HELPER: Convert ScanReport to dict for JSON response
# ─────────────────────────────────────────────────────────────────────────────

def report_to_dict(report, duration: float) -> dict:
    modules_out = []
    for result in report.results:
        modules_out.append({
            "module": result.module_name,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "cvss_score": f.cvss_score,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
            "passed_checks": result.passed,
            "error": result.error,
        })

    return {
        "sentinelscan_version": "2.0",
        "target": report.target,
        "scan_time": report.scan_time,
        "summary": {
            "overall_risk": report.risk_rating(),
            "total_findings": report.total_findings(),
            "critical": report.critical_count(),
            "high": report.high_count(),
            "medium": report.medium_count(),
            "low": report.low_count(),
            "modules_run": report.modules_run,
            "scan_duration_seconds": round(duration, 2),
        },
        "modules": modules_out,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  BACKGROUND SCAN WORKER
#  This function runs in a background thread (via FastAPI BackgroundTasks).
#  It updates the shared _scans dict as the scan progresses.
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan_background(scan_id: str, target: str, req: ScanRequest):
    """
    Background worker for async scans.

    FastAPI's BackgroundTasks runs this in a separate thread so the HTTP
    response returns immediately, and the scan runs concurrently.

    The _scans dict is updated with progress and results which the
    polling endpoint reads.
    """
    start_time = time.time()

    with _scans_lock:
        _scans[scan_id]["status"] = "running"

    try:
        scanner = SentinelCore(
            timeout=req.timeout,
            modules=req.modules,
            include_threat_intel=req.include_threat_intel,
        )
        report = scanner.scan(target)
        duration = time.time() - start_time
        result = report_to_dict(report, duration)

        with _scans_lock:
            _scans[scan_id]["status"] = "complete"
            _scans[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
            _scans[scan_id]["result"] = result
            _scans[scan_id]["progress"] = {
                "modules_complete": report.modules_run,
                "total_findings": report.total_findings(),
            }

    except Exception as e:
        with _scans_lock:
            _scans[scan_id]["status"] = "failed"
            _scans[scan_id]["error"] = str(e)[:300]
            _scans[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES — Public (no auth required)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Info"])
async def root():
    """API information — no authentication required."""
    return {
        "name": "SentinelScan API",
        "version": "2.0.0",
        "auth": "Required on scan endpoints. Pass X-API-Key header. Dev key: sentinel-dev-key-2024",
        "endpoints": {
            "POST /scan/async":      "Start async scan (recommended for dashboard)",
            "GET  /scan/{id}":       "Poll scan status / get results",
            "GET  /scans":           "List recent scans",
            "POST /scan":            "Synchronous scan (blocks until complete)",
            "POST /scan/quick":      "Quick scan (headers, SSL, CORS only)",
            "GET  /health":          "Health check",
            "GET  /docs":            "Swagger UI (interactive docs)",
        },
        "rate_limits": {
            "/scan and /scan/async": "5 requests per minute per IP",
            "/scan/quick":           "20 requests per minute per IP",
            "/scan/{id}":            "60 requests per minute per IP",
        },
        "github": "https://github.com/shree-aru/sentinelscan",
    }


@app.get("/health", tags=["Info"])
async def health_check():
    """Health check — no authentication required."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "active_scans": sum(1 for s in _scans.values() if s.get("status") == "running"),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  ROUTES — Authenticated scan endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/scan/async", response_model=AsyncScanStarted, tags=["Scanner"])
async def start_async_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    _key: str = Depends(require_api_key),
):
    """
    Start a security scan in the background. Returns a scan_id immediately.

    Poll GET /scan/{scan_id} to check progress and retrieve results.

    This is the recommended endpoint for the dashboard since scans
    take 30-120 seconds and you don't want the browser to hang waiting.
    """
    client_ip = get_client_ip(http_request)
    if not scan_limiter.allow(client_ip):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max 5 full scans per minute per IP. "
                   f"Try /scan/quick for faster scans."
        )

    target = normalize_target(request.target)
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        raise HTTPException(status_code=422, detail=f"Invalid target: {error_msg}")

    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    with _scans_lock:
        _scans[scan_id] = {
            "status": "queued",
            "target": target,
            "started_at": started_at,
            "completed_at": None,
            "result": None,
            "error": None,
            "progress": {},
        }
        _scan_history.appendleft(scan_id)

    # Schedule the scan to run in background (non-blocking)
    background_tasks.add_task(_run_scan_background, scan_id, target, request)

    return AsyncScanStarted(
        scan_id=scan_id,
        status="queued",
        target=target,
        message=f"Scan started. Poll GET /scan/{scan_id} for results.",
    )


@app.get("/scan/{scan_id}", tags=["Scanner"])
async def get_scan_status(
    scan_id: str,
    http_request: Request,
    _key: str = Depends(require_api_key),
):
    """
    Get the status and results of an async scan.

    Status values:
    - queued   : scan is waiting to start
    - running  : scan is in progress
    - complete : scan finished, result is available
    - failed   : scan encountered an error
    """
    client_ip = get_client_ip(http_request)
    if not status_limiter.allow(client_ip):
        raise HTTPException(status_code=429, detail="Too many status polls. Max 60/minute.")

    with _scans_lock:
        if scan_id not in _scans:
            raise HTTPException(
                status_code=404,
                detail=f"Scan ID '{scan_id}' not found. Scans are kept in memory — "
                       "if the server restarted, the scan is lost."
            )
        scan = dict(_scans[scan_id])

    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "target": scan["target"],
        "started_at": scan["started_at"],
        "completed_at": scan.get("completed_at"),
        "progress": scan.get("progress", {}),
        "result": scan.get("result"),
        "error": scan.get("error"),
    }


@app.get("/scans", tags=["Scanner"])
async def list_recent_scans(_key: str = Depends(require_api_key)):
    """List the most recent 10 scans with their status and summary."""
    recent = []
    with _scans_lock:
        for scan_id in list(_scan_history)[:10]:
            if scan_id in _scans:
                s = _scans[scan_id]
                entry = {
                    "scan_id": scan_id,
                    "target": s.get("target", ""),
                    "status": s.get("status", ""),
                    "started_at": s.get("started_at", ""),
                }
                if s.get("result"):
                    entry["risk"] = s["result"].get("summary", {}).get("overall_risk", "")
                    entry["total_findings"] = s["result"].get("summary", {}).get("total_findings", 0)
                recent.append(entry)
    return {"scans": recent, "count": len(recent)}


@app.post("/scan", tags=["Scanner"])
async def run_full_scan(
    request: ScanRequest,
    http_request: Request,
    _key: str = Depends(require_api_key),
):
    """
    Synchronous full scan. Blocks until complete (30-120s).

    Prefer /scan/async for dashboard use. Use this for direct API calls
    and CI/CD pipeline integrations where you want to wait for results.
    """
    client_ip = get_client_ip(http_request)
    if not scan_limiter.allow(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit: 5 full scans per minute.")

    target = normalize_target(request.target)
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        raise HTTPException(status_code=422, detail=f"Invalid target: {error_msg}")

    start_time = time.time()
    try:
        scanner = SentinelCore(
            timeout=request.timeout,
            modules=request.modules,
            include_threat_intel=request.include_threat_intel,
        )
        report = scanner.scan(target)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)[:200]}")

    return report_to_dict(report, time.time() - start_time)


@app.post("/scan/quick", tags=["Scanner"])
async def run_quick_scan(
    request: ScanRequest,
    http_request: Request,
    _key: str = Depends(require_api_key),
):
    """
    Quick scan — headers, SSL, and CORS only. Typical duration: 3-8 seconds.
    No injection testing, no threat intel. Safe for frequent CI/CD checks.
    """
    client_ip = get_client_ip(http_request)
    if not quick_limiter.allow(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit: 20 quick scans per minute.")

    target = normalize_target(request.target)
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        raise HTTPException(status_code=422, detail=f"Invalid target: {error_msg}")

    start_time = time.time()
    try:
        scanner = SentinelCore(
            timeout=request.timeout,
            modules=["headers", "ssl", "cors"],
            include_threat_intel=False,
        )
        report = scanner.scan(target)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)[:200]}")

    return report_to_dict(report, time.time() - start_time)
