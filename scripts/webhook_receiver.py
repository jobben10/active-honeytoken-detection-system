from fastapi import FastAPI, Request
import uvicorn


app = FastAPI(
    title="Honeytoken Webhook Test Receiver"
)


@app.post("/webhook")
async def receive_webhook(
    request: Request
):
    payload = await request.json()

    print("\n" + "=" * 70)
    print("HONEYTOKEN WEBHOOK RECEIVED")
    print("=" * 70)

    print(
        f"Event: {payload.get('event')}"
    )

    print(
        f"Severity: {payload.get('severity')}"
    )

    print(
        f"Risk Score: "
        f"{payload.get('risk_score')}/100"
    )

    print(
        f"Token ID: "
        f"{payload.get('token_id')}"
    )

    print(
        f"Document: "
        f"{payload.get('document')}"
    )

    print(
        f"Event Type: "
        f"{payload.get('event_type')}"
    )

    print(
        f"Source IP: "
        f"{payload.get('source_ip')}"
    )

    print(
        "Detection Reasons:"
    )

    for reason in payload.get(
        "detection_reasons",
        []
    ):
        print(
            f"  - {reason}"
        )

    print("=" * 70 + "\n")

    return {
        "received": True,
        "message": "Webhook received successfully"
    }


if __name__ == "__main__":

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=9000
    )