import re

RULES = [
    (
        "Urgent pressure",
        re.compile(
            r"\b(act now|urgent|immediately|within \d+ hours|"
            r"account (?:will be|is) (?:blocked|suspended))\b",
            re.I,
        ),
        15,
    ),
    (
        "Credential or OTP request",
        re.compile(
            r"\b(share|send|confirm|enter|verify)\b.{0,45}"
            r"\b(otp|one.time password|password|pin|cvv)\b",
            re.I,
        ),
        30,
    ),
    (
        "Prize or reward claim",
        re.compile(
            r"\b(you have won|claim your prize|"
            r"congratulations.{0,30}(?:winner|won)|"
            r"free gift)\b",
            re.I,
        ),
        20,
    ),
    (
        "Payment pressure",
        re.compile(
            r"\b(pay now|transfer money|send money|"
            r"pay a fee to receive|processing fee required)\b",
            re.I,
        ),
        20,
    ),
    (
        "Impersonation language",
        re.compile(
            r"\b(pretending to be|on behalf of|"
            r"your bank manager|police officer demanding)\b",
            re.I,
        ),
        15,
    ),
    (
        "Suspicious link",
        re.compile(
            r"(?:https?://|www\.)\S+|"
            r"\b(?:bit\.ly|tinyurl\.com|t\.co)/\S+",
            re.I,
        ),
        10,
    ),
]


def analyze_message(message: str) -> dict:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please enter a message.")

    if len(message) > 10000:
        raise ValueError("Message must be 10,000 characters or fewer.")

    findings = []
    score = 0

    for label, pattern, points in RULES:
        if pattern.search(message):
            findings.append({
                "finding": label,
                "points": points,
            })
            score += points

    score = min(score, 100)

    if score >= 50:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "assessment_type": "Heuristic message analysis",
        "limitations": (
            "This checks known suspicious patterns only. "
            "It cannot prove a message is genuine or fraudulent."
        ),
    }