import re

MAX_MESSAGE_LENGTH = 10_000

THREAT_PATTERNS = [
    ("Explicit threat of violence", re.compile(
        r"\b(?:i\s+)?(?:will|shall|am going to|gonna|i['’]ll)\s+"
        r"(?:kill|murder|hurt|harm|attack|beat|stab|shoot|destroy)\b",
        re.IGNORECASE), 70),
    ("Threatening or intimidating language", re.compile(
        r"\b(?:you(?:'re| are) dead|i know where you live|"
        r"do it or else|you'll regret (?:this|it)|make you pay)\b",
        re.IGNORECASE), 70),
    ("Conditional threat or coercion", re.compile(
        r"\bif you (?:don't|do not|refuse to).{0,100}\b"
        r"(?:kill|hurt|harm|attack|beat|expose|ruin|come after)\b",
        re.IGNORECASE), 70),
]

SCAM_RULES = [
    ("Request for OTP or verification code", re.compile(
        r"\b(?:share|send|tell|provide|enter).{0,50}\b"
        r"(?:otp|one[- ]time password|verification code|security code)\b",
        re.IGNORECASE), 30),
    ("Request for passwords or account credentials", re.compile(
        r"\b(?:share|send|provide|enter|confirm).{0,50}\b"
        r"(?:password|login credentials|bank details|cvv|pin)\b",
        re.IGNORECASE), 30),
    ("Prize or reward claim", re.compile(
        r"\b(?:you(?:'ve| have) won|claim your prize|free gift|"
        r"lottery winner|congratulations.{0,40}won)\b",
        re.IGNORECASE), 20),
    ("Urgent account warning", re.compile(
        r"\b(?:account.{0,30}(?:blocked|suspended|locked)|"
        r"urgent action required|"
        r"account will be closed)\b",
        re.IGNORECASE), 15),
    ("Payment pressure", re.compile(
        r"\b(?:pay immediately|send money now|transfer funds urgently|"
        r"transfer money immediately|urgent.{0,40}transfer money|"
        r"pay a processing fee|your account will be blocked unless|"
        r"avoid account closure)\b",
        re.IGNORECASE), 20),
    ("Impersonation language", re.compile(
        r"\b(?:i am from your bank|we are from technical support|"
        r"official customer support team)\b",
        re.IGNORECASE), 15),
    ("Potentially suspicious link", re.compile(
        r"https?://[^\s]+|"
        r"\b(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)/\S+",
        re.IGNORECASE), 10),
]

QUOTED_THREAT_CONTEXT = re.compile(
    r"\b(?:someone|somebody|they|he|she|the sender|the person)\s+"
    r"(?:said|texted|messaged|threatened|wrote)\b"
    r"|\b(?:reported|received|got)\s+(?:a threat|a threatening message)\b",
    re.IGNORECASE,
)


def analyze_message(message):
    """Analyze text for possible threats and scam indicators."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message must be non-empty text.")

    message = message.strip()
    if len(message) > MAX_MESSAGE_LENGTH:
        raise ValueError(
            f"Message cannot exceed {MAX_MESSAGE_LENGTH} characters."
        )

    findings = []
    context_notes = []
    score = 0
    assessment_type = "General message analysis"

    threat_matches = [
        (label, points)
        for label, pattern, points in THREAT_PATTERNS
        if pattern.search(message)
    ]

    if threat_matches:
        if QUOTED_THREAT_CONTEXT.search(message):
            findings.append("Quoted or reported threat (context review)")
            score = 25
            context_notes.append(
                "This may report a threat rather than make one. "
                "Review the surrounding conversation."
            )
            assessment_type = "Threat context review"
        else:
            findings.extend(label for label, _ in threat_matches)
            score = max(points for _, points in threat_matches)
            assessment_type = "Threat and intimidation analysis"

    safety_advice = re.search(
        r"\b(?:never|don't|do not|never ever)\s+"
        r"(?:share|send|tell|give|provide|disclose)\b",
        message,
        re.IGNORECASE,
    )

    if re.search(
        r"\baccount\b.{0,30}\b(?:blocked|suspended|locked)\b",
        message,
        re.IGNORECASE,
    ) and re.search(r"\bverify immediately\b", message, re.IGNORECASE):
        if "Urgent account warning" not in findings:
            findings.append("Urgent account warning")
        score = max(score, 30)

    for label, pattern, points in SCAM_RULES:
        if safety_advice and label in (
            "Request for OTP or verification code",
            "Request for passwords or account credentials",
        ):
            continue
        if pattern.search(message):
            if label not in findings:
                findings.append(label)
                score += points

    if (
        "Impersonation language" in findings
        and "Request for passwords or account credentials" in findings
    ):
        score = max(score, 50)

    if re.search(r"\bdo this or else\b", message, re.IGNORECASE):
        if "Threatening or intimidating language" not in findings:
            findings.append("Threatening or intimidating language")
        score = max(score, 70)

    score = min(score, 100)
    risk_level = "High" if score >= 50 else "Medium" if score >= 20 else "Low"


    return {
        "risk_score": score,
        "risk_level": risk_level,
        "findings": findings,
        "assessment_type": assessment_type,
        "context_notes": context_notes,
        "limitations": (
            "Rule-based detection can miss unfamiliar wording and "
            "misinterpret sarcasm, quotations, or context. Results are "
            "indicators, not proof that a message is safe or dangerous."
        ),
    }
