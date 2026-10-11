import os
import requests


API_URL = (
    "https://safebrowsing.googleapis.com/"
    "v4/threatMatches:find"
)


def check_threat(url: str) -> dict:
    api_key = os.getenv("SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "status": "unavailable",
            "message": "Threat intelligence is not configured.",
        }

    payload = {
        "client": {
            "clientId": "scamlens",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            API_URL,
            params={"key": api_key},
            json=payload,
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])

        if matches:
            return {
                "status": "threat_detected",
                "message": "Google Safe Browsing reported a threat match.",
                "matches": [
                    {
                        "threat_type": match.get(
                            "threatType", "UNKNOWN"
                        )
                    }
                    for match in matches
                ],
            }

        return {
            "status": "no_match",
            "message": (
                "No threat match was returned. "
                "This does not prove the URL is safe."
            ),
        }

    except requests.RequestException:
        return {
            "status": "unavailable",
            "message": (
                "Threat intelligence could not be reached. "
                "Try again later."
            ),
        }

    except ValueError:
        return {
            "status": "unavailable",
            "message": "The threat-intelligence response was invalid.",
        }