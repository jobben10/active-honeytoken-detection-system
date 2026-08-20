import hashlib
import hmac
import json
import urllib.error
import urllib.request

from .config import (
    WEBHOOK_ENABLED,
    WEBHOOK_URL,
    WEBHOOK_SECRET
)


def send_webhook_message(
    payload: dict
):
    """
    Send a security event to a configured webhook.
    """

    if not WEBHOOK_ENABLED:

        print(
            "Webhook notification skipped: "
            "WEBHOOK_ENABLED is not true."
        )

        return False


    if not WEBHOOK_URL:

        print(
            "Webhook notification skipped: "
            "WEBHOOK_URL is not configured."
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


    if WEBHOOK_SECRET:

        signature = hmac.new(
            WEBHOOK_SECRET.encode("utf-8"),
            body,
            hashlib.sha256
        ).hexdigest()

        headers[
            "X-Honeytoken-Signature"
        ] = signature


    request = urllib.request.Request(
        WEBHOOK_URL,
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
                "Webhook security alert sent."
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
            "Webhook HTTP error:",
            error_body
        )

        return False


    except Exception as error:

        print(
            "Webhook notification error:",
            str(error)
        )

        return False


def send_honeytoken_webhook(
    token_id: str,
    document: str,
    event_type: str,
    source_ip: str | None,
    risk_score: int,
    severity: str,
    reasons: list[str] | None = None
):
    """
    Send a structured honeytoken security event.
    """

    payload = {

        "event": "HONEYTOKEN_TRIGGERED",

        "system":
            "Active Honeytoken Detection System",

        "severity":
            severity,

        "risk_score":
            risk_score,

        "token_id":
            token_id,

        "document":
            document,

        "event_type":
            event_type,

        "source_ip":
            source_ip,

        "detection_reasons":
            reasons or []

    }


    return send_webhook_message(
        payload
    )