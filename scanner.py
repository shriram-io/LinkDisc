import ipaddress
import re
from urllib.parse import urlsplit


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "verification",
    "password",
    "wallet",
    "banking",
    "signin",
    "account",
    "secure",
    "update",
}

KNOWN_RISKY_TLDS = {
    "zip",
    "mov",
    "click",
    "work",
    "country",
}


def analyze_url(url: str) -> dict:
    """Analyze a URL for suspicious characteristics.

    This is a heuristic scanner, not a definitive security verdict.
    """

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a URL.")

    url = url.strip()

    if len(url) > 2048:
        raise ValueError("URL must be 2048 characters or fewer.")

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("URL contains invalid control characters.")

    if "\\" in url:
        raise ValueError("URL contains an invalid backslash.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Please enter a valid URL.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.netloc or not hostname:
        raise ValueError("Please enter a valid URL with a hostname.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted.")

    hostname = hostname.rstrip(".").lower()

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if not is_ip_address:
        try:
            hostname_ascii = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("The hostname is invalid.") from exc

        hostname = hostname_ascii.lower()

        if len(hostname) > 253:
            raise ValueError("The hostname is too long.")

        labels = hostname.split(".")

        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("The hostname is invalid.")

        if len(labels) < 2:
            raise ValueError("Please enter a hostname with a domain extension.")

    elif port is not None and not 1 <= port <= 65535:
        raise ValueError("The port number is invalid.")

    findings = []
    score = 0

    def add_finding(reason: str, points: int) -> None:
        nonlocal score
        findings.append(reason)
        score += points

    if parsed.scheme.lower() == "http":
        add_finding("Uses HTTP instead of HTTPS.", 10)

    if is_ip_address:
        add_finding("Uses an IP address instead of a domain name.", 25)

    if hostname in SHORTENER_DOMAINS:
        add_finding("Uses a known URL-shortening service.", 15)

    if "@" in parsed.netloc:
        add_finding("Contains an @ symbol in the network location.", 20)

    if hostname.count(".") >= 4:
        add_finding("Contains an unusually deep subdomain structure.", 10)

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add_finding("Contains an internationalized domain label.", 10)

    if hostname.split(".")[-1] in KNOWN_RISKY_TLDS:
        add_finding("Uses a top-level domain on this scanner's review list.", 10)

    if len(url) > 120:
        add_finding("URL is unusually long.", 10)

    if hostname.count("-") >= 3:
        add_finding("Domain contains multiple hyphens.", 10)

    searchable_text = (hostname + parsed.path + parsed.query).lower()
    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])",
                     searchable_text)
    )

    if matched_keywords:
        add_finding(
            "Contains potentially sensitive keywords: "
            + ", ".join(matched_keywords)
            + ".",
            10,
        )

    score = min(score, 100)

    if score >= 40:
        risk_level = "High"
    elif score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "url": url,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": risk_level,
        "findings": findings,
        "recommendation": (
            "Do not open this link unless you can independently verify it."
            if score >= 40
            else "Verify the domain and intended destination before entering "
                 "sensitive information."
        ),
        "limitations": (
            "This heuristic scan does not establish whether a URL is malicious "
            "or safe. A low score is not proof of safety."
        ),
    }