import json
import os
import urllib.error
import urllib.request

from dotenv import load_dotenv


load_dotenv()


# ============================================================
# CONFIGURATION
# ============================================================

SIEM_ENABLED = (
    os.getenv(
        "SIEM_ENABLED",
        "false"
    ).lower()
    == "true"
)

SIEM_WEBHOOK_URL = os.getenv(
    "SIEM_WEBHOOK_URL"
)

SIEM_API_KEY = os.getenv(
    "SIEM_API_KEY"
)


# ============================================================
# SEND SIEM EVENT
# ============================================================

def send_siem_event(
    payload: dict
) -> bool:

    if not SIEM_ENABLED:

        print(
            "SIEM integration skipped: "
            "SIEM_ENABLED is not true."
        )

        return False

    if not SIEM_WEBHOOK_URL:

        print(
            "SIEM integration skipped: "
            "SIEM_WEBHOOK_URL is not configured."
        )

        return False

    body = json.dumps(
        payload
    ).encode("utf-8")

    headers = {
        "Content-Type":
            "application/json",

        "User-Agent":
            "Active-Honeytoken-Detection-System/1.0"
    }

    if SIEM_API_KEY:

        headers[
            "Authorization"
        ] = f"Bearer {SIEM_API_KEY}"

    request = urllib.request.Request(

        SIEM_WEBHOOK_URL,

        data=body,

        headers=headers,

        method="POST"
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=15
        ) as response:

            response.read()

        print(
            "SIEM security event sent."
        )

        return True

    except urllib.error.HTTPError as error:

        try:

            error_body = (
                error.read()
                .decode("utf-8")
            )

        except Exception:

            error_body = str(error)

        print(
            "SIEM HTTP error:",
            error_body
        )

        return False

    except Exception as error:

        print(
            "SIEM integration error:",
            str(error)
        )

        return False


# ============================================================
# CREATE HONEYTOKEN SIEM EVENT
# ============================================================

def send_honeytoken_siem_event(
    token_id: str,
    document: str,
    event_type: str,
    source_ip: str | None,
    risk_score: int,
    severity: str,
    reasons: list[str] | None = None,
    ip_intelligence: dict | None = None,
    mitre_attack: dict | None = None
):

    payload = {

        "event": {
            "kind":
                "alert",

            "category": [
                "intrusion_detection",
                "file",
                "security"
            ],

            "type": [
                "access",
                "info"
            ],

            "action":
                "honeytoken_triggered"
        },

        "system":
            "Active Honeytoken Detection System",

        "event_type":
            event_type,

        "severity":
            severity,

        "risk_score":
            risk_score,

        "token_id":
            token_id,

        "document":
            document,

        "source": {

            "ip":
                source_ip
        },

        "detection": {

            "reasons":
                reasons or []
        },

        "threat_intelligence":
            ip_intelligence or {},

        "mitre_attack":
            mitre_attack or {}
    }

    return send_siem_event(
        payload
    )