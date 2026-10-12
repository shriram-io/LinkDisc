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

@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:99999",
        "https://-invalid.com",
        "https://example..com",
        "https://example.com/" + "a" * 2050,
        "https://example.com/\x00",
    ],
)
def test_malformed_urls(url):
    with pytest.raises(ValueError):
        analyze_url(url)


def test_normalized_hostname():
    result = analyze_url("https://EXAMPLE.COM")
    assert result["hostname"] == "example.com"


def test_suspicious_tld():
    result = analyze_url("https://example.zip")
    assert result["risk_score"] >= 10
    assert result["findings"]


def test_low_score_is_not_a_safety_guarantee():
    result = analyze_url("https://example.com")
    assert "not proof of safety" in result["limitations"]
