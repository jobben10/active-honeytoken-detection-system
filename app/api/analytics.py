from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..security import require_roles
from ..security import require_roles
from ..models import Alert, Honeytoken, SecurityEvent


router = APIRouter(
    prefix="/api/analytics",
    tags=["Security Analytics"]
)


# ============================================================
# SECURITY OVERVIEW
# ============================================================

@router.get("/overview")
def get_security_overview(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN", "SOC_ANALYST", "VIEWER"))
):

    total_tokens = (
        db.query(Honeytoken)
        .count()
    )

    active_tokens = (
        db.query(Honeytoken)
        .filter(
            Honeytoken.status == "ACTIVE"
        )
        .count()
    )

    total_events = (
        db.query(SecurityEvent)
        .count()
    )

    total_alerts = (
        db.query(Alert)
        .count()
    )

    open_alerts = (
        db.query(Alert)
        .filter(
            Alert.status == "OPEN"
        )
        .count()
    )

    acknowledged_alerts = (
        db.query(Alert)
        .filter(
            Alert.status == "ACKNOWLEDGED"
        )
        .count()
    )

    resolved_alerts = (
        db.query(Alert)
        .filter(
            Alert.status == "RESOLVED"
        )
        .count()
    )

    critical_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "CRITICAL"
        )
        .count()
    )

    high_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "HIGH"
        )
        .count()
    )

    medium_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "MEDIUM"
        )
        .count()
    )

    low_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "LOW"
        )
        .count()
    )

    events = (
        db.query(SecurityEvent)
        .all()
    )

    if events:

        average_risk_score = round(
            sum(
                event.risk_score
                for event in events
            ) / len(events),
            2
        )

    else:

        average_risk_score = 0


    return {

        "tokens": {
            "total": total_tokens,
            "active": active_tokens
        },

        "events": {
            "total": total_events
        },

        "alerts": {
            "total": total_alerts,
            "open": open_alerts,
            "acknowledged": acknowledged_alerts,
            "resolved": resolved_alerts
        },

        "severity": {
            "critical": critical_alerts,
            "high": high_alerts,
            "medium": medium_alerts,
            "low": low_alerts
        },

        "average_risk_score":
            average_risk_score
    }


# ============================================================
# EVENTS BY SEVERITY
# ============================================================

@router.get("/severity")
def get_severity_distribution(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN", "SOC_ANALYST", "VIEWER"))
):

    results = []

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]:

        count = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.severity
                == severity
            )
            .count()
        )

        results.append({
            "severity": severity,
            "count": count
        })


    return {
        "data": results
    }


# ============================================================
# EVENTS OVER TIME
# ============================================================

@router.get("/timeline")
def get_event_timeline(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN", "SOC_ANALYST", "VIEWER"))
):

    now = datetime.now(
        timezone.utc
    )

    start_time = (
        now - timedelta(hours=24)
    )

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.timestamp
            >= start_time
        )
        .order_by(
            SecurityEvent.timestamp.asc()
        )
        .all()
    )


    hourly = Counter()


    for event in events:

        timestamp = event.timestamp

        if timestamp.tzinfo is None:

            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        hour = timestamp.strftime(
            "%Y-%m-%d %H:00"
        )

        hourly[hour] += 1


    timeline = []


    for i in range(24):

        hour_time = (
            now
            - timedelta(
                hours=23 - i
            )
        )

        hour_key = hour_time.strftime(
            "%Y-%m-%d %H:00"
        )

        timeline.append({

            "hour": hour_key,

            "events":
                hourly.get(
                    hour_key,
                    0
                )
        })


    return {
        "data": timeline
    }


# ============================================================
# TOP SOURCE IPS
# ============================================================

@router.get("/source-ips")
def get_top_source_ips(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN", "SOC_ANALYST", "VIEWER"))
):

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.source_ip
            != None
        )
        .all()
    )

    counter = Counter(
        event.source_ip
        for event in events
    )


    results = []


    for ip, count in counter.most_common(10):

        results.append({

            "source_ip": ip,

            "count": count
        })


    return {
        "data": results
    }


# ============================================================
# MOST TARGETED HONEYTOKENS
# ============================================================

@router.get("/tokens")
def get_top_tokens(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN", "SOC_ANALYST", "VIEWER"))
):

    events = (
        db.query(SecurityEvent)
        .all()
    )

    counter = Counter(
        event.token_id
        for event in events
    )


    results = []


    for token_id, count in counter.most_common(10):

        token = (
            db.query(Honeytoken)
            .filter(
                Honeytoken.token_id
                == token_id
            )
            .first()
        )


        results.append({

            "token_id":
                token_id,

            "document":
                (
                    token.document_name
                    if token
                    else "Unknown"
                ),

            "count":
                count
        })


    return {
        "data": results
    }


# ============================================================
# DETECTION REASONS
# ============================================================

@router.get("/detection-reasons")
def get_detection_reasons(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN", "SOC_ANALYST", "VIEWER"))
):

    alerts = (
        db.query(Alert)
        .all()
    )


    counter = Counter()


    import json


    for alert in alerts:

        if not alert.detection_reasons:

            continue


        try:

            reasons = json.loads(
                alert.detection_reasons
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            continue


        if isinstance(
            reasons,
            list
        ):

            counter.update(
                reasons
            )


    results = []


    for reason, count in counter.most_common(10):

        results.append({

            "reason":
                reason,

            "count":
                count
        })


    return {
        "data": results
    }


