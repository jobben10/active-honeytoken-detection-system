import os

from dotenv import load_dotenv


load_dotenv()


# ============================================================
# TELEGRAM
# ============================================================

TELEGRAM_BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN"
)

TELEGRAM_CHAT_ID = os.getenv(
    "TELEGRAM_CHAT_ID"
)


# ============================================================
# EMAIL
# ============================================================

EMAIL_ENABLED = (
    os.getenv(
        "EMAIL_ENABLED",
        "false"
    ).lower()
    == "true"
)

SMTP_HOST = os.getenv(
    "SMTP_HOST",
    "smtp.gmail.com"
)

SMTP_PORT = int(
    os.getenv(
        "SMTP_PORT",
        "587"
    )
)

SMTP_USERNAME = os.getenv(
    "SMTP_USERNAME"
)

SMTP_PASSWORD = os.getenv(
    "SMTP_PASSWORD"
)

EMAIL_FROM = os.getenv(
    "EMAIL_FROM"
)

EMAIL_TO = os.getenv(
    "EMAIL_TO"
)


# ============================================================
# WEBHOOK
# ============================================================

WEBHOOK_ENABLED = (
    os.getenv(
        "WEBHOOK_ENABLED",
        "false"
    ).lower()
    == "true"
)

WEBHOOK_URL = os.getenv(
    "WEBHOOK_URL"
)

WEBHOOK_SECRET = os.getenv(
    "WEBHOOK_SECRET"
)