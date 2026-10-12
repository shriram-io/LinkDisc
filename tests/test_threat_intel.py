
import requests

from threat_intel import check_threat


def test_missing_api_key_returns_unavailable(monkeypatch):
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)

    result = check_threat("https://example.com")

    assert result["status"] == "unavailable"


def test_threat_match_detected(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "matches": [{"threatType": "SOCIAL_ENGINEERING"}]
            }

    def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("threat_intel.requests.post", mock_post)

    result = check_threat("https://example.com")

    assert result["status"] == "threat_detected"
    assert result["matches"][0]["threat_type"] == "SOCIAL_ENGINEERING"


def test_no_match_does_not_claim_url_is_safe(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {}

    monkeypatch.setattr(
        "threat_intel.requests.post",
        lambda *args, **kwargs: MockResponse(),
    )

    result = check_threat("https://example.com")

    assert result["status"] == "no_match"
    assert "does not prove" in result["message"]


def test_network_error_returns_unavailable(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")

    def mock_post(*args, **kwargs):
        raise requests.Timeout("Test timeout")

    monkeypatch.setattr("threat_intel.requests.post", mock_post)

    result = check_threat("https://example.com")

    assert result["status"] == "unavailable"


def test_invalid_json_returns_unavailable(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")

    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            raise ValueError("Invalid JSON")

    monkeypatch.setattr(
        "threat_intel.requests.post",
        lambda *args, **kwargs: MockResponse(),
    )

    result = check_threat("https://example.com")

    assert result["status"] == "unavailable"
