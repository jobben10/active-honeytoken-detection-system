import json
import os
import urllib.request

from dotenv import load_dotenv


load_dotenv()


BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN"
)


if not BOT_TOKEN:
    print(
        "ERROR: TELEGRAM_BOT_TOKEN "
        "is missing from .env"
    )

    raise SystemExit(1)


url = (
    "https://api.telegram.org/bot"
    f"{BOT_TOKEN}/getUpdates"
)


try:

    with urllib.request.urlopen(
        url,
        timeout=10
    ) as response:

        data = json.loads(
            response.read().decode(
                "utf-8"
            )
        )

except Exception as error:

    print(
        "Failed to contact Telegram:"
    )

    print(error)

    raise SystemExit(1)


if not data.get("ok"):

    print(
        "Telegram returned an error:"
    )

    print(data)

    raise SystemExit(1)


updates = data.get(
    "result",
    []
)


if not updates:

    print(
        "No Telegram messages found."
    )

    print(
        "Open your bot in Telegram "
        "and send /start, then run "
        "this script again."
    )

    raise SystemExit(0)


print()
print(
    "Telegram chats found:"
)
print()


seen = set()


for update in updates:

    message = update.get(
        "message"
    )

    if not message:
        continue

    chat = message.get(
        "chat"
    )

    if not chat:
        continue

    chat_id = chat.get(
        "id"
    )

    if chat_id in seen:
        continue

    seen.add(chat_id)

    print(
        f"Chat ID: {chat_id}"
    )

    print(
        f"Chat Type: "
        f"{chat.get('type')}"
    )

    print(
        f"Name: "
        f"{chat.get('first_name', '')} "
        f"{chat.get('last_name', '')}"
    )

    print(
        f"Username: "
        f"@{chat.get('username')}"
    )

    print()


if not seen:

    print(
        "No usable Telegram chats "
        "were found."
    )