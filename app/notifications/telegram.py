import os
import json
import urllib.parse
import urllib.request
from typing import Any


def _is_enabled() -> bool:
    return os.getenv("TELEGRAM_ENABLED", "false").strip().lower() == "true"


def _get_config():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    return token, chat_id


def send_honeytoken_alert(
    token_id: str,
    document: str,
    source_ip: str | None = None,
    risk_score: int = 0,
    severity: str = "LOW",
    event_type: str = "TOKEN_TRIGGERED",
    reasons: list[str] | None = None,
    ip_intelligence: dict[str, Any] | None = None,
    mitre_attack: dict[str, Any] | None = None,
) -> bool:
    """
    Send a honeytoken security alert to Telegram.

    Returns:
        True  -> Telegram accepted the message
        False -> Telegram notification was not sent
    """

    if not _is_enabled():
        print("Telegram notification skipped: TELEGRAM_ENABLED is not true.")
        return False

    token, chat_id = _get_config()

    if not token:
        print("Telegram notification skipped: TELEGRAM_BOT_TOKEN is missing.")
        return False

    if not chat_id:
        print("Telegram notification skipped: TELEGRAM_CHAT_ID is missing.")
        return False

    reason_text = ""
    if reasons:
        reason_text = "\n".join(f"• {reason}" for reason in reasons)

    country = ""
    city = ""
    isp = ""
    asn = ""

    if ip_intelligence:
        country = ip_intelligence.get("country") or ""
        city = ip_intelligence.get("city") or ""
        isp = ip_intelligence.get("isp") or ""
        asn = ip_intelligence.get("asn") or ""

    mitre_text = ""

    if mitre_attack:
        techniques = mitre_attack.get("techniques", [])

        if techniques:
            technique_lines = []

            for technique in techniques:
                if isinstance(technique, dict):
                    technique_id = technique.get("id", "")
                    technique_name = technique.get("technique", "")

                    if technique_id or technique_name:
                        technique_lines.append(
                            f"• {technique_id} — {technique_name}"
                        )

            if technique_lines:
                mitre_text = "\n".join(technique_lines)

    message_parts = [
        "🚨 HONEYTOKEN SECURITY ALERT",
        "",
        f"Severity: {severity}",
        f"Risk Score: {risk_score}/100",
        f"Event: {event_type}",
        "",
        f"Token: {token_id}",
        f"Document: {document}",
        f"Source IP: {source_ip or 'Unknown'}",
    ]

    if country:
        message_parts.append(f"Country: {country}")

    if city:
        message_parts.append(f"City: {city}")

    if isp:
        message_parts.append(f"ISP: {isp}")

    if asn:
        message_parts.append(f"ASN: {asn}")

    if reason_text:
        message_parts.extend(
            [
                "",
                "Detection Reasons:",
                reason_text,
            ]
        )

    if mitre_text:
        message_parts.extend(
            [
                "",
                "MITRE ATT&CK:",
                mitre_text,
            ]
        )

    message_parts.extend(
        [
            "",
            "Status: CRITICAL ACTIVITY DETECTED",
            "",
            "Active Honeytoken Detection System",
        ]
    )

    message = "\n".join(message_parts)

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = urllib.parse.urlencode(
        {
            "chat_id": chat_id,
            "text": message,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Active-Honeytoken/1.0",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response_data = response.read().decode("utf-8")

        result = json.loads(response_data)

        if result.get("ok") is True:
            print("Telegram notification sent successfully.")
            return True

        print(
            "Telegram notification failed: "
            + str(result.get("description", "Unknown Telegram error"))
        )
        return False

    except Exception as exc:
        print(f"Telegram notification error: {exc}")
        return False