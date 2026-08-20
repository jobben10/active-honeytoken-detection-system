from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def login(username, password):
    response = client.post(
        "/api/auth/login",
        data={
            "username": username,
            "password": password,
        },
    )

    assert response.status_code == 200

    return response.json()["access_token"]


def auth_headers(token):
    return {
        "Authorization": f"Bearer {token}"
    }


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"


def test_root():
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "online"


def test_security_headers():
    response = client.get("/health")

    assert response.status_code == 200

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"


def test_cors_allowed_origin():
    response = client.options(
        "/api/tokens/",
        headers={
            "Origin": "http://127.0.0.1:5500",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert (
        response.headers.get("access-control-allow-origin")
        == "http://127.0.0.1:5500"
    )


def test_unauthenticated_tokens_rejected():
    response = client.get("/api/tokens/")

    assert response.status_code == 401


def test_unauthenticated_events_rejected():
    response = client.get("/api/events/")

    assert response.status_code == 401


def test_unauthenticated_alerts_rejected():
    response = client.get("/api/alerts/")

    assert response.status_code == 401


def test_unauthenticated_analytics_rejected():
    response = client.get("/api/analytics/overview")

    assert response.status_code == 401


def test_unauthenticated_audit_rejected():
    response = client.get("/api/audit/")

    assert response.status_code == 401


def test_admin_login():
    token = login(
        "admin",
        "Admin@12345",
    )

    assert token


def test_admin_identity():
    token = login(
        "admin",
        "Admin@12345",
    )

    response = client.get(
        "/api/auth/me",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["authenticated"] is True
    assert data["username"] == "admin"
    assert data["role"] == "ADMIN"


def test_viewer_read_access():
    token = login(
        "viewer",
        "Viewer@12345",
    )

    headers = auth_headers(token)

    endpoints = [
        "/api/tokens/",
        "/api/events/",
        "/api/alerts/",
        "/api/analytics/overview",
        "/api/audit/",
    ]

    for endpoint in endpoints:
        response = client.get(
            endpoint,
            headers=headers,
        )

        assert response.status_code == 200, (
            f"{endpoint} returned {response.status_code}"
        )


def test_viewer_cannot_create_honeytoken():
    token = login(
        "viewer",
        "Viewer@12345",
    )

    payload = {
        "document_name": "Unauthorized Test.xlsx",
        "document_type": "xlsx",
        "classification": "CONFIDENTIAL",
        "severity": "HIGH",
    }

    response = client.post(
        "/api/tokens/",
        json=payload,
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_viewer_cannot_create_event():
    token = login(
        "viewer",
        "Viewer@12345",
    )

    payload = {
        "token_id": "HNY-53CA9F63",
        "event_type": "AUTOMATED_TEST",
        "source_ip": "127.0.0.1",
        "user_agent": "Security-Test",
    }

    response = client.post(
        "/api/events/",
        json=payload,
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_viewer_cannot_acknowledge_alert():
    token = login(
        "viewer",
        "Viewer@12345",
    )

    response = client.put(
        "/api/alerts/26/acknowledge",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_viewer_cannot_resolve_alert():
    token = login(
        "viewer",
        "Viewer@12345",
    )

    response = client.put(
        "/api/alerts/26/resolve",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_viewer_cannot_deactivate_honeytoken():
    token = login(
        "viewer",
        "Viewer@12345",
    )

    response = client.put(
        "/api/tokens/HNY-53CA9F63/deactivate",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_analyst_can_read_events():
    token = login(
        "analyst",
        "Analyst@12345",
    )

    response = client.get(
        "/api/events/",
        headers=auth_headers(token),
    )

    assert response.status_code == 200


def test_analyst_cannot_manage_honeytokens():
    token = login(
        "analyst",
        "Analyst@12345",
    )

    response = client.put(
        "/api/tokens/HNY-53CA9F63/deactivate",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_invalid_honeytoken_payload():
    token = login(
        "admin",
        "Admin@12345",
    )

    payload = {
        "document_name": "",
        "document_type": "xlsx",
    }

    response = client.post(
        "/api/tokens/",
        json=payload,
        headers=auth_headers(token),
    )

    assert response.status_code in [400, 422]


def test_admin_can_create_honeytoken():
    token = login(
        "admin",
        "Admin@12345",
    )

    payload = {
        "document_name": "Automated Security Test.xlsx",
        "document_type": "xlsx",
        "classification": "CONFIDENTIAL",
        "severity": "HIGH",
    }

    response = client.post(
        "/api/tokens/",
        json=payload,
        headers=auth_headers(token),
    )

    assert response.status_code in [200, 201]

    data = response.json()

    assert "token_id" in data
    assert data["document_name"] == payload["document_name"]


def test_public_honeytoken_trigger():
    response = client.get(
        "/api/events/trigger/HNY-53CA9F63"
    )

    assert response.status_code == 200

    data = response.json()

    assert "event_id" in data
    assert data["event_id"] is not None


def test_nonexistent_endpoint():
    response = client.get(
        "/api/does-not-exist"
    )

    assert response.status_code == 404


def test_invalid_login():
    response = client.post(
        "/api/auth/login",
        data={
            "username": "admin",
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401
