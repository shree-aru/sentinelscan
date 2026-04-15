"""
Tests for scanner/core.py — URL normalization and validation.

These are pure unit tests (no network calls).
Testing the URL handling logic in isolation catches bugs early and
documents the expected behavior clearly.
"""

import pytest
from scanner.core import normalize_target, validate_target


# ─────────────────────────────────────────────────────────────────────────────
#  normalize_target
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizeTarget:

    def test_adds_https_when_no_scheme(self):
        result = normalize_target("example.com")
        assert result.startswith("https://")

    def test_preserves_http_scheme(self):
        result = normalize_target("http://example.com")
        assert result.startswith("http://")

    def test_preserves_https_scheme(self):
        result = normalize_target("https://example.com")
        assert result.startswith("https://")

    def test_strips_leading_whitespace(self):
        result = normalize_target("  https://example.com  ")
        assert result == "https://example.com"

    def test_lowercases_scheme(self):
        result = normalize_target("HTTPS://Example.COM/path")
        assert result.startswith("https://")

    def test_preserves_path(self):
        result = normalize_target("https://example.com/api/v1")
        assert "/api/v1" in result

    def test_preserves_query_string(self):
        result = normalize_target("https://example.com/search?q=test")
        assert "q=test" in result


# ─────────────────────────────────────────────────────────────────────────────
#  validate_target
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateTarget:

    def test_valid_https_url(self):
        ok, msg = validate_target("https://example.com")
        assert ok is True
        assert msg == ""

    def test_valid_http_url(self):
        ok, msg = validate_target("http://example.com")
        assert ok is True

    def test_valid_url_with_path(self):
        ok, msg = validate_target("https://example.com/path?q=1")
        assert ok is True

    def test_ip_address_is_valid(self):
        ok, msg = validate_target("http://127.0.0.1:5000")
        assert ok is True

    def test_localhost_127_is_valid(self):
        """127.0.0.1 is explicitly allowed in validate_target."""
        ok, msg = validate_target("http://127.0.0.1")
        assert ok is True

    def test_missing_scheme_is_invalid(self):
        ok, msg = validate_target("example.com")
        assert ok is False
        assert msg != ""

    def test_ftp_scheme_is_invalid(self):
        ok, msg = validate_target("ftp://example.com")
        assert ok is False
        assert "unsupported" in msg.lower() or "ftp" in msg.lower()

    def test_empty_string_is_invalid(self):
        ok, msg = validate_target("")
        assert ok is False

    def test_no_dot_in_hostname_is_invalid(self):
        """hostnames without a dot (and not localhost) should be rejected."""
        ok, msg = validate_target("https://notahostname")
        assert ok is False

    def test_valid_subdomain(self):
        ok, msg = validate_target("https://api.example.com")
        assert ok is True

    def test_valid_url_with_port(self):
        ok, msg = validate_target("https://example.com:8443")
        assert ok is True


# ─────────────────────────────────────────────────────────────────────────────
#  Rate limiter (from api.main)
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimiter:
    """Test the in-memory sliding window rate limiter."""

    def test_allows_requests_within_limit(self):
        from api.main import RateLimiter
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.allow("1.2.3.4") is True

    def test_blocks_over_limit(self):
        from api.main import RateLimiter
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.allow("1.2.3.4")
        # 4th request should be blocked
        assert limiter.allow("1.2.3.4") is False

    def test_different_ips_independent(self):
        """Rate limit per IP — one blocked IP should not affect another."""
        from api.main import RateLimiter
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.allow("1.1.1.1")
        limiter.allow("1.1.1.1")
        # 1.1.1.1 is now blocked
        assert limiter.allow("1.1.1.1") is False
        # But 2.2.2.2 is unaffected
        assert limiter.allow("2.2.2.2") is True

    def test_remaining_decreases(self):
        from api.main import RateLimiter
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        assert limiter.remaining("1.2.3.4") == 5
        limiter.allow("1.2.3.4")
        assert limiter.remaining("1.2.3.4") == 4
        limiter.allow("1.2.3.4")
        assert limiter.remaining("1.2.3.4") == 3
