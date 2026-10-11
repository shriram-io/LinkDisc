import pytest

from scanner import analyze_url


def test_normal_https_url():
    result = analyze_url("https://example.com")
    assert result["risk_level"] == "Low"
    assert result["risk_score"] == 0


def test_http_url():
    result = analyze_url("http://example.com")
    assert result["risk_score"] == 10
    assert result["risk_level"] == "Low"


def test_ip_address():
    result = analyze_url("http://192.0.2.1")
    assert result["risk_score"] >= 35


def test_suspicious_keywords():
    result = analyze_url("http://example.com/login")
    assert result["risk_score"] >= 20
    assert result["findings"]


def test_url_shortener():
    result = analyze_url("https://bit.ly/example")
    assert result["risk_score"] >= 15


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "ftp://example.com",
        "https://user:password@example.com",
        "https://example.com\\@evil.com",
    ],
)
def test_invalid_urls(url):
    with pytest.raises(ValueError):
        analyze_url(url)