import pytest

from message_scanner import analyze_message


def test_empty_message_rejected():
    with pytest.raises(ValueError):
        analyze_message(" ")


def test_oversized_message_rejected():
    with pytest.raises(ValueError):
        analyze_message("x" * 10001)


def test_otp_request_flagged():
    result = analyze_message("Share your OTP immediately")
    assert result["risk_score"] >= 30
    assert result["findings"]


def test_prize_claim_flagged():
    result = analyze_message("You have won a prize!")
    assert result["findings"]


def test_ordinary_message_has_no_findings():
    result = analyze_message("The meeting starts at 10 AM.")
    assert result["risk_score"] == 0
    assert result["findings"] == []