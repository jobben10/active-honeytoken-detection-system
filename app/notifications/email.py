import smtplib
from email.message import EmailMessage

from .config import (
    EMAIL_ENABLED,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    EMAIL_FROM,
    EMAIL_TO
)


def send_email_message(
    subject: str,
    message: str
):
    """
    Send a plain-text security alert email.
    """

    if not EMAIL_ENABLED:

        print(
            "Email notification skipped: "
            "EMAIL_ENABLED is not true."
        )

        return False


    if not SMTP_USERNAME:

        print(
            "Email notification skipped: "
            "SMTP_USERNAME is not configured."
        )

        return False


    if not SMTP_PASSWORD:

        print(
            "Email notification skipped: "
            "SMTP_PASSWORD is not configured."
        )

        return False


    if not EMAIL_FROM:

        print(
            "Email notification skipped: "
            "EMAIL_FROM is not configured."
        )

        return False


    if not EMAIL_TO:

        print(
            "Email notification skipped: "
            "EMAIL_TO is not configured."
        )

        return False


    email = EmailMessage()

    email["Subject"] = subject

    email["From"] = EMAIL_FROM

    email["To"] = EMAIL_TO

    email.set_content(
        message
    )


    try:

        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=15
        ) as server:

            server.starttls()

            server.login(
                SMTP_USERNAME,
                SMTP_PASSWORD
            )

            server.send_message(
                email
            )


        print(
            "Email security alert sent."
        )

        return True


    except Exception as error:

        print(
            "Email notification error:",
            str(error)
        )

        return False


def send_honeytoken_email(
    token_id: str,
    document: str,
    event_type: str,
    source_ip: str | None,
    risk_score: int,
    severity: str,
    reasons: list[str] | None = None
):
    """
    Send a formatted honeytoken security alert.
    """

    subject = (
        f"[{severity}] "
        f"Honeytoken Alert - "
        f"{document}"
    )


    message = (
        "ACTIVE HONEYTOKEN DETECTION SYSTEM\n"
        "\n"
        "SECURITY ALERT\n"
        "==============================\n"
        "\n"
        f"Severity: {severity}\n"
        f"Risk Score: {risk_score}/100\n"
        f"Document: {document}\n"
        f"Token ID: {token_id}\n"
        f"Event Type: {event_type}\n"
        f"Source IP: {source_ip or 'Unknown'}\n"
    )


    if reasons:

        message += (
            "\n"
            "Detection Reasons\n"
            "------------------------------\n"
        )

        for reason in reasons:

            message += (
                f"- {reason}\n"
            )


    message += (
        "\n"
        "Possible unauthorized document "
        "access has been detected.\n"
        "\n"
        "Investigate this event in the "
        "Security Operations Dashboard."
    )


    return send_email_message(
        subject=subject,
        message=message
    )