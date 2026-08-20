import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..security import require_roles
from ..models import Alert, Honeytoken, SecurityEvent
from ..detection.audit import create_audit_log


router = APIRouter(
    prefix="/api/alerts",
    tags=["Security Alerts"]
)


# ============================================================
# GET ALERT STATISTICS
# ============================================================

@router.get("/stats/summary")
def get_alert_statistics(
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST", "VIEWER")
    )
):

    total = (
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

    acknowledged = (
        db.query(Alert)
        .filter(
            Alert.status == "ACKNOWLEDGED"
        )
        .count()
    )

    resolved = (
        db.query(Alert)
        .filter(
            Alert.status == "RESOLVED"
        )
        .count()
    )

    critical = (
        db.query(Alert)
        .filter(
            Alert.severity == "CRITICAL"
        )
        .count()
    )

    high = (
        db.query(Alert)
        .filter(
            Alert.severity == "HIGH"
        )
        .count()
    )

    medium = (
        db.query(Alert)
        .filter(
            Alert.severity == "MEDIUM"
        )
        .count()
    )

    low = (
        db.query(Alert)
        .filter(
            Alert.severity == "LOW"
        )
        .count()
    )

    return {

        "total":
            total,

        "open":
            open_alerts,

        "acknowledged":
            acknowledged,

        "resolved":
            resolved,

        "severity": {

            "critical":
                critical,

            "high":
                high,

            "medium":
                medium,

            "low":
                low
        }
    }


# ============================================================
# GET ALL ALERTS
# ============================================================

@router.get("/")
def get_alerts(
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST", "VIEWER")
    )
):

    alerts = (
        db.query(Alert)
        .order_by(
            Alert.created_at.desc()
        )
        .all()
    )

    results = []

    for alert in alerts:

        reasons = []

        if alert.detection_reasons:

            try:

                reasons = json.loads(
                    alert.detection_reasons
                )

            except (
                json.JSONDecodeError,
                TypeError
            ):

                reasons = []

        results.append({

            "id":
                alert.id,

            "token_id":
                alert.token_id,

            "event_id":
                alert.event_id,

            "title":
                alert.title,

            "message":
                alert.message,

            "severity":
                alert.severity,

            "risk_score":
                alert.risk_score,

            "detection_reasons":
                reasons,

            "source_ip":
                alert.source_ip,

            "status":
                alert.status,

            "created_at":
                (
                    alert.created_at.isoformat()
                    if alert.created_at
                    else None
                ),

            "acknowledged_at":
                (
                    alert.acknowledged_at.isoformat()
                    if alert.acknowledged_at
                    else None
                ),

            "resolved_at":
                (
                    alert.resolved_at.isoformat()
                    if alert.resolved_at
                    else None
                )
        })

    return {

        "total":
            len(results),

        "alerts":
            results
    }


# ============================================================
# GET SINGLE ALERT
# ============================================================

@router.get(
    "/{alert_id}"
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST", "VIEWER")
    )
):

    alert = (
        db.query(Alert)
        .filter(
            Alert.id == alert_id
        )
        .first()
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    reasons = []

    if alert.detection_reasons:

        try:

            reasons = json.loads(
                alert.detection_reasons
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            reasons = []

    return {

        "id":
            alert.id,

        "token_id":
            alert.token_id,

        "event_id":
            alert.event_id,

        "title":
            alert.title,

        "message":
            alert.message,

        "severity":
            alert.severity,

        "risk_score":
            alert.risk_score,

        "detection_reasons":
            reasons,

        "source_ip":
            alert.source_ip,

        "status":
            alert.status,

        "created_at":
            (
                alert.created_at.isoformat()
                if alert.created_at
                else None
            ),

        "acknowledged_at":
            (
                alert.acknowledged_at.isoformat()
                if alert.acknowledged_at
                else None
            ),

        "resolved_at":
            (
                alert.resolved_at.isoformat()
                if alert.resolved_at
                else None
            )
    }


# ============================================================
# ACKNOWLEDGE ALERT
# ============================================================

@router.put(
    "/{alert_id}/acknowledge"
)
def acknowledge_alert(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST")
    )
):

    alert = (
        db.query(Alert)
        .filter(
            Alert.id == alert_id
        )
        .first()
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    alert.status = "ACKNOWLEDGED"

    alert.acknowledged_at = (
        datetime.now(timezone.utc)
    )

    db.commit()
    db.refresh(alert)

    create_audit_log(

        db=db,

        action="ALERT_ACKNOWLEDGED",

        resource_type="ALERT",

        resource_id=str(
            alert.id
        ),

        source_ip=(
            request.client.host
            if request.client
            else None
        ),

        details={

            "alert_id":
                alert.id,

            "token_id":
                alert.token_id,

            "event_id":
                alert.event_id,

            "severity":
                alert.severity,

            "risk_score":
                alert.risk_score,

            "previous_status":
                "OPEN",

            "new_status":
                "ACKNOWLEDGED"
        }
    )

    return {

        "message":
            "Alert acknowledged",

        "alert_id":
            alert.id,

        "status":
            alert.status
    }


# ============================================================
# RESOLVE ALERT
# ============================================================

@router.put(
    "/{alert_id}/resolve"
)
def resolve_alert(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST")
    )
):

    alert = (
        db.query(Alert)
        .filter(
            Alert.id == alert_id
        )
        .first()
    )

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    previous_status = alert.status

    alert.status = "RESOLVED"

    alert.resolved_at = (
        datetime.now(timezone.utc)
    )

    db.commit()
    db.refresh(alert)

    create_audit_log(

        db=db,

        action="ALERT_RESOLVED",

        resource_type="ALERT",

        resource_id=str(
            alert.id
        ),

        source_ip=(
            request.client.host
            if request.client
            else None
        ),

        details={

            "alert_id":
                alert.id,

            "token_id":
                alert.token_id,

            "event_id":
                alert.event_id,

            "severity":
                alert.severity,

            "risk_score":
                alert.risk_score,

            "previous_status":
                previous_status,

            "new_status":
                "RESOLVED"
        }
    )

    return {

        "message":
            "Alert resolved",

        "alert_id":
            alert.id,

        "status":
            alert.status
    }

