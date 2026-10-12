
import pytest

from message_scanner import analyze_message


@pytest.mark.parametrize(
    "message",
    [
        "I will kill you",
        "I'll hurt you if you come here",
        "I am going to attack you",
        "You are dead",
        "I know where you live",
        "Do this or else",
    ],
)
def test_direct_threats_are_high_risk(message):
    result = analyze_message(message)

    assert result["risk_level"] == "High"
    assert result["risk_score"] >= 50
    assert result["findings"]


@pytest.mark.parametrize(
    "message",
    [
        "Have a nice day",
        "I will call you tomorrow",
        "The meeting starts at 10 AM.",
        "Never share your OTP or password with anyone.",
    ],
)
def test_benign_messages_are_low_risk(message):
    result = analyze_message(message)

    assert result["risk_level"] == "Low"
    assert result["risk_score"] == 0
    assert result["findings"] == []


@pytest.mark.parametrize(
    "message, expected_level",
    [
        ("Send me your OTP immediately", "Medium"),
        ("Congratulations, you have won a free gift!", "Medium"),
        (
            "Urgent! Transfer money immediately to avoid account closure.",
            "Medium",
        ),
        (
            "Your account is blocked. Verify immediately.",
            "Medium",
        ),
        (
            "I am from your bank. Send me your password.",
            "High",
        ),
    ],
)
def test_scam_indicators_are_detected(message, expected_level):
    result = analyze_message(message)

    assert result["risk_level"] == expected_level
    assert result["risk_score"] >= 20
    assert result["findings"]


def test_reported_threat_is_flagged_for_context_review():
    result = analyze_message(
        "Someone texted me: I will kill you"
    )

    assert result["risk_level"] == "Medium"
    assert result["risk_score"] == 25
    assert "Quoted or reported threat (context review)" in result["findings"]


@pytest.mark.parametrize("message", ["", "   ", None, 123])
def test_invalid_messages_are_rejected(message):
    with pytest.raises(ValueError):
        analyze_message(message)


def test_result_contains_expected_fields():
    result = analyze_message("I will kill you")

    assert {
        "risk_score",
        "risk_level",
        "findings",
        "assessment_type",
        "context_notes",
        "limitations",
    }.issubset(result.keys())


def test_message_length_limit():
    with pytest.raises(ValueError):
        analyze_message("a" * 10_001)
