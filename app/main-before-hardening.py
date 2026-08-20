from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine

from .api.tokens import router as token_router
from .api.events import router as event_router
from .api.alerts import router as alert_router
from .api.analytics import router as analytics_router
from .api.audit import router as audit_router
from .api.auth import router as auth_router


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="Active Honeytoken Detection System",
    description=(
        "Document-based honeytoken detection, "
        "correlation, risk scoring, alerting, "
        "analytics, audit logging, "
        "IP intelligence and authentication"
    ),
    version="1.4.0"
)


allowed_origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500"
]


app.add_middleware(
    CORSMiddleware,

    allow_origins=allowed_origins,

    allow_credentials=False,

    allow_methods=["*"],

    allow_headers=["*"]
)


# ============================================================
# ROUTERS
# ============================================================

app.include_router(
    auth_router
)

app.include_router(
    token_router
)

app.include_router(
    event_router
)

app.include_router(
    alert_router
)

app.include_router(
    analytics_router
)

app.include_router(
    audit_router
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {

        "system":
            "Active Honeytoken Detection System",

        "status":
            "online",

        "version":
            "1.4.0",

        "features": [

            "Honeytoken Generation",

            "Document Honeytokens",

            "Security Event Detection",

            "Risk Scoring",

            "Event Correlation",

            "Security Alerts",

            "Telegram Notifications",

            "Email Notifications",

            "Webhook Notifications",

            "SOC Analytics",

            "Security Audit Logging",

            "IP Threat Intelligence",

            "JWT Authentication",

            "Role Based Access Control"
        ]
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {

        "status":
            "healthy",

        "system":
            "Active Honeytoken Detection System",

        "version":
            "1.4.0"
    }