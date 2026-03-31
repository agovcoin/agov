"""Tests for agov backend security, validation, and endpoints."""
import json
import time
import pytest
from unittest.mock import patch, MagicMock
from collections import OrderedDict

# Import app components
from app import (
    app, validate_address, cache_get, cache_set, _cache,
    CACHE_TTL, MAX_CACHE, INITIAL_SCORE, GRADUATION_THRESHOLD,
    fetch_token_details, fetch_tokens_parallel
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


# ============================================================
# ADDRESS VALIDATION
# ============================================================
class TestValidateAddress:
    def test_valid_solana_address(self):
        assert validate_address("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", "solana") is True

    def test_valid_solana_short(self):
        assert validate_address("11111111111111111111111111111111", "solana") is True

    def test_invalid_solana_too_short(self):
        assert validate_address("DezXAZ8z7Pnrn", "solana") is False

    def test_invalid_solana_bad_chars(self):
        assert validate_address("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB10OIl", "solana") is False

    def test_invalid_solana_empty(self):
        assert validate_address("", "solana") is False

    def test_valid_evm_address(self):
        assert validate_address("0x1234567890abcdef1234567890abcdef12345678", "ethereum") is True

    def test_valid_evm_mixed_case(self):
        assert validate_address("0xAbCdEf1234567890AbCdEf1234567890AbCdEf12", "base") is True

    def test_invalid_evm_no_prefix(self):
        assert validate_address("1234567890abcdef1234567890abcdef12345678", "ethereum") is False

    def test_invalid_evm_too_short(self):
        assert validate_address("0x1234", "ethereum") is False

    def test_invalid_evm_bad_chars(self):
        assert validate_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", "ethereum") is False

    def test_xss_payload_solana(self):
        assert validate_address("<script>alert(1)</script>", "solana") is False

    def test_xss_payload_evm(self):
        assert validate_address("0x<img onerror=alert(1) src=x>aaaaaaaaaaaaaaa", "ethereum") is False

    def test_sql_injection_payload(self):
        assert validate_address("'; DROP TABLE tokens; --", "solana") is False


# ============================================================
# CACHE
# ============================================================
class TestCache:
    def test_cache_set_and_get(self):
        cache_set("test:key", {"value": 42})
        assert cache_get("test:key") == {"value": 42}

    def test_cache_miss(self):
        assert cache_get("nonexistent") is None

    def test_cache_expiry(self):
        cache_set("test:expire", {"value": 1})
        # Manually expire
        _cache["test:expire"]["ts"] = time.time() - CACHE_TTL - 1
        assert cache_get("test:expire") is None

    def test_cache_eviction(self):
        for i in range(MAX_CACHE + 10):
            cache_set(f"key:{i}", {"i": i})
        assert len(_cache) == MAX_CACHE
        # First entries should be evicted
        assert cache_get("key:0") is None
        # Last entries should exist
        assert cache_get(f"key:{MAX_CACHE + 9}") is not None


# ============================================================
# SECURITY HEADERS
# ============================================================
class TestSecurityHeaders:
    def test_nosniff_header(self, client):
        r = client.get("/api/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_options_header(self, client):
        r = client.get("/api/health")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_xss_protection_header(self, client):
        r = client.get("/api/health")
        assert r.headers.get("X-XSS-Protection") == "1; mode=block"

    def test_hsts_header(self, client):
        r = client.get("/api/health")
        assert "max-age=31536000" in r.headers.get("Strict-Transport-Security", "")


# ============================================================
# HEALTH ENDPOINT
# ============================================================
class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200

    def test_health_status_operational(self, client):
        r = client.get("/api/health")
        data = json.loads(r.data)
        assert data["status"] == "operational"

    def test_health_no_api_details(self, client):
        r = client.get("/api/health")
        data = json.loads(r.data)
        # Should NOT expose individual API connection status
        assert isinstance(data["apis"], str)
        assert "helius" not in str(data["apis"]).lower()

    def test_health_lists_tools(self, client):
        r = client.get("/api/health")
        data = json.loads(r.data)
        assert "xray" in data["tools"]
        assert len(data["tools"]) == 10


# ============================================================
# XRAY SCAN ENDPOINT
# ============================================================
class TestXrayScan:
    def test_missing_address(self, client):
        r = client.post("/api/xray/scan", json={})
        assert r.status_code == 400
        assert "Address required" in json.loads(r.data)["error"]

    def test_invalid_chain(self, client):
        r = client.post("/api/xray/scan", json={"address": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", "chain": "invalid"})
        assert r.status_code == 400
        assert "Unsupported chain" in json.loads(r.data)["error"]

    def test_invalid_solana_address(self, client):
        r = client.post("/api/xray/scan", json={"address": "not-valid", "chain": "solana"})
        assert r.status_code == 400
        assert "Invalid address format" in json.loads(r.data)["error"]

    def test_invalid_evm_address(self, client):
        r = client.post("/api/xray/scan", json={"address": "not-valid", "chain": "ethereum"})
        assert r.status_code == 400

    def test_xss_in_address_rejected(self, client):
        r = client.post("/api/xray/scan", json={"address": "<script>alert(1)</script>", "chain": "solana"})
        assert r.status_code == 400

    @patch("app.requests.get")
    def test_valid_scan_returns_data(self, mock_get, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"baseToken": {"name": "Test", "symbol": "TST"}, "marketCap": 50000, "liquidity": {"usd": 10000}, "volume": {"h24": 5000}, "txns": {"h24": {"buys": 10, "sells": 5}}, "priceChange": {"h24": 5}}]
        mock_get.return_value = mock_resp

        r = client.post("/api/xray/scan", json={"address": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", "chain": "solana"})
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "score" in data
        assert "address" in data

    def test_cached_result(self, client):
        cache_set("xray:solana:DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", {"score": 75, "cached": True})
        r = client.post("/api/xray/scan", json={"address": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"})
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["cached"] is True


# ============================================================
# HOLOGRAM ENDPOINT
# ============================================================
class TestHologram:
    def test_missing_address(self, client):
        r = client.post("/api/hologram/analyze", json={})
        assert r.status_code == 400

    def test_empty_address(self, client):
        r = client.post("/api/hologram/analyze", json={"address": ""})
        assert r.status_code == 400


# ============================================================
# ABDUCTION ENDPOINT
# ============================================================
class TestAbduction:
    def test_missing_address(self, client):
        r = client.post("/api/abduction/check", json={})
        assert r.status_code == 400

    def test_empty_address(self, client):
        r = client.post("/api/abduction/check", json={"address": ""})
        assert r.status_code == 400


# ============================================================
# DEBRIEFING ENDPOINT
# ============================================================
class TestDebriefing:
    def test_missing_wallet(self, client):
        r = client.post("/api/debriefing/report", json={})
        assert r.status_code == 400

    def test_empty_wallet(self, client):
        r = client.post("/api/debriefing/report", json={"wallet": ""})
        assert r.status_code == 400


# ============================================================
# FEED ENDPOINTS (GET)
# ============================================================
class TestFeeds:
    @patch("app.requests.get")
    def test_probe_feed_returns_json(self, mock_get, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp

        r = client.get("/api/probe/feed")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "tokens" in data

    @patch("app.requests.get")
    def test_graduation_feed_returns_json(self, mock_get, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp

        r = client.get("/api/graduation/feed")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "tokens" in data

    @patch("app.requests.get")
    def test_autopsy_feed_returns_json(self, mock_get, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp

        r = client.get("/api/autopsy/feed")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "autopsies" in data

    @patch("app.requests.get")
    def test_signal_returns_json(self, mock_get, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp

        r = client.get("/api/signal/narratives")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "narratives" in data

    @patch("app.requests.get")
    def test_mothership_returns_json(self, mock_get, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp

        r = client.get("/api/mothership/feed")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "movements" in data


# ============================================================
# PARALLEL FETCH
# ============================================================
class TestParallelFetch:
    @patch("app.requests.get")
    def test_fetch_token_details_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"baseToken": {"name": "Test"}}]
        mock_get.return_value = mock_resp

        result = fetch_token_details("abc123")
        assert result is not None
        assert result["baseToken"]["name"] == "Test"

    @patch("app.requests.get")
    def test_fetch_token_details_404(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = fetch_token_details("abc123")
        assert result is None

    @patch("app.fetch_token_details")
    def test_fetch_tokens_parallel(self, mock_fetch):
        mock_fetch.side_effect = lambda addr, timeout=5: {"addr": addr}

        results = fetch_tokens_parallel(["a", "b", "c"])
        assert len(results) == 3
        assert results["a"] == {"addr": "a"}
        assert results["b"] == {"addr": "b"}

    @patch("app.fetch_token_details")
    def test_fetch_tokens_parallel_with_failure(self, mock_fetch):
        def side_effect(addr, timeout=5):
            if addr == "bad":
                raise Exception("timeout")
            return {"addr": addr}
        mock_fetch.side_effect = side_effect

        results = fetch_tokens_parallel(["good", "bad"])
        assert results["good"] == {"addr": "good"}
        assert results["bad"] is None


# ============================================================
# CONSTANTS
# ============================================================
class TestConstants:
    def test_initial_score(self):
        assert INITIAL_SCORE == 50

    def test_graduation_threshold(self):
        assert GRADUATION_THRESHOLD == 69000

    def test_cache_ttl(self):
        assert CACHE_TTL == 300

    def test_max_cache(self):
        assert MAX_CACHE == 500


# ============================================================
# CORS (basic check)
# ============================================================
class TestCORS:
    def test_cors_allowed_origin(self, client):
        r = client.get("/api/health", headers={"Origin": "https://agovcoin.xyz"})
        assert r.headers.get("Access-Control-Allow-Origin") == "https://agovcoin.xyz"

    def test_cors_disallowed_origin(self, client):
        r = client.get("/api/health", headers={"Origin": "https://evil.com"})
        assert r.headers.get("Access-Control-Allow-Origin") != "https://evil.com"


# ============================================================
# DEBUG MODE
# ============================================================
class TestDebugMode:
    def test_debug_off_by_default(self):
        import os
        assert os.getenv("FLASK_DEBUG", "false").lower() != "true"
