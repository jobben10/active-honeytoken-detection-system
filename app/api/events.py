import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..security import require_roles
from ..models import Honeytoken, SecurityEvent, Alert
from ..schemas import SecurityEventCreate

from ..detection.correlation import (
    calculate_correlated_risk,
    determine_correlated_severity
)

from ..detection.audit import create_audit_log

from ..detection.threat_intel import (
    lookup_ip_intelligence
)

from ..detection.mitre import (
    map_event_to_mitre,
    summarize_mitre_mapping
)

from ..detection.siem import (
    send_honeytoken_siem_event
)

from ..notifications.telegram import (
    send_honeytoken_alert
)

from ..notifications.email import (
    send_honeytoken_email
)

from ..notifications.webhook import (
    send_honeytoken_webhook
)


router = APIRouter(
    prefix="/api/events",
    tags=["Security Events"]
)


# ============================================================
# CREATE ALERT
# ============================================================

def create_alert(
    db: Session,
    token: Honeytoken,
    event: SecurityEvent,
    risk_score: int,
    severity: str,
    reasons: list[str]
):

    alert = Alert(

        token_id=token.token_id,

        event_id=event.id,

        title=f"{severity} Honeytoken Alert",

        message=(
            "Possible unauthorized access "
            f"detected for {token.document_name}"
        ),

        severity=severity,

        risk_score=risk_score,

        detection_reasons=json.dumps(
            reasons
        ),

        source_ip=event.source_ip,

        status="OPEN"
    )

    db.add(alert)

    db.commit()

    db.refresh(alert)

    return alert


# ============================================================
# PROCESS SECURITY EVENT
# ============================================================

def process_security_event(
    db: Session,
    event: SecurityEvent
):

    token = (
        db.query(Honeytoken)
        .filter(
            Honeytoken.token_id
            == event.token_id
        )
        .first()
    )

    if not token:

        raise HTTPException(
            status_code=404,
            detail="Honeytoken not found"
        )

    if token.status != "ACTIVE":

        return {
            "alert": False,
            "message": "Honeytoken is inactive",
            "token_id": token.token_id
        }

    # ========================================================
    # IP INTELLIGENCE
    # ========================================================

    ip_intelligence = (
        lookup_ip_intelligence(
            event.source_ip
        )
    )

    event.ip_country = (
        ip_intelligence.get("country")
    )

    event.ip_country_code = (
        ip_intelligence.get(
            "country_code"
        )
    )

    event.ip_region = (
        ip_intelligence.get("region")
    )

    event.ip_city = (
        ip_intelligence.get("city")
    )

    event.ip_isp = (
        ip_intelligence.get("isp")
    )

    event.ip_organization = (
        ip_intelligence.get(
            "organization"
        )
    )

    event.ip_asn = (

        str(
            ip_intelligence.get(
                "asn"
            )
        )

        if ip_intelligence.get("asn")

        else None
    )

    event.ip_timezone = (
        ip_intelligence.get(
            "timezone"
        )
    )

    event.ip_latitude = (

        str(
            ip_intelligence.get(
                "latitude"
            )
        )

        if ip_intelligence.get(
            "latitude"
        ) is not None

        else None
    )

    event.ip_longitude = (

        str(
            ip_intelligence.get(
                "longitude"
            )
        )

        if ip_intelligence.get(
            "longitude"
        ) is not None

        else None
    )

    event.ip_is_private = (

        "true"

        if ip_intelligence.get(
            "is_private",
            True
        )

        else "false"
    )

    # ========================================================
    # MITRE ATT&CK
    # ========================================================

    mitre_mappings = map_event_to_mitre(

        event_type=event.event_type,

        user_agent=event.user_agent,

        source_ip=event.source_ip
    )

    mitre_summary = (
        summarize_mitre_mapping(
            mitre_mappings
        )
    )

    event.mitre_techniques = (
        json.dumps(
            mitre_mappings
        )
    )

    event.mitre_tactics = (
        json.dumps(
            mitre_summary["tactics"]
        )
    )

    # ========================================================
    # SAVE EVENT
    # ========================================================

    db.add(event)

    db.commit()

    db.refresh(event)

    # ========================================================
    # RISK CALCULATION
    # ========================================================

    risk_result = (
        calculate_correlated_risk(
            db=db,
            token=token,
            event=event
        )
    )

    risk_score = (
        risk_result["score"]
    )

    reasons = (
        risk_result["reasons"]
    )

    severity = (
        determine_correlated_severity(
            risk_score
        )
    )

    event.risk_score = risk_score

    event.severity = severity

    db.commit()

    db.refresh(event)

    # ========================================================
    # CREATE ALERT
    # ========================================================

    alert = create_alert(

        db=db,

        token=token,

        event=event,

        risk_score=risk_score,

        severity=severity,

        reasons=reasons
    )

    # ========================================================
    # AUDIT LOG
    # ========================================================

    create_audit_log(

        db=db,

        action="HONEYTOKEN_TRIGGERED",

        resource_type="HONEYTOKEN",

        resource_id=token.token_id,

        source_ip=event.source_ip,

        details={

            "document":
                token.document_name,

            "event_id":
                event.id,

            "event_type":
                event.event_type,

            "risk_score":
                risk_score,

            "severity":
                severity,

            "alert_id":
                alert.id,

            "detection_reasons":
                reasons,

            "user_agent":
                event.user_agent,

            "ip_intelligence":
                ip_intelligence,

            "mitre_attack": {

                "techniques":
                    mitre_mappings,

                "summary":
                    mitre_summary
            }
        }
    )

    # ========================================================
    # SIEM
    # ========================================================

    siem_result = False

    try:

        siem_result = (
            send_honeytoken_siem_event(

                token_id=
                    token.token_id,

                document=
                    token.document_name,

                event_type=
                    event.event_type,

                source_ip=
                    event.source_ip,

                risk_score=
                    risk_score,

                severity=
                    severity,

                reasons=
                    reasons,

                ip_intelligence=
                    ip_intelligence,

                mitre_attack={

                    "techniques":
                        mitre_mappings,

                    "summary":
                        mitre_summary
                }
            )
        )

    except Exception as error:

        print(
            "SIEM notification error:",
            str(error)
        )

    # ========================================================
    # TELEGRAM
    # ========================================================

    telegram_result = False

    try:

        telegram_result = (
            send_honeytoken_alert(

                token_id=
                    token.token_id,

                document=
                    token.document_name,

                event_type=
                    event.event_type,

                source_ip=
                    event.source_ip,

                risk_score=
                    risk_score,

                severity=
                    severity,

                reasons=
                    reasons
            )
        )

    except Exception as error:

        print(
            "Telegram notification error:",
            str(error)
        )

    # ========================================================
    # EMAIL
    # ========================================================

    email_result = False

    try:

        email_result = (
            send_honeytoken_email(

                token_id=
                    token.token_id,

                document=
                    token.document_name,

                event_type=
                    event.event_type,

                source_ip=
                    event.source_ip,

                risk_score=
                    risk_score,

                severity=
                    severity,

                reasons=
                    reasons
            )
        )

    except Exception as error:

        print(
            "Email notification error:",
            str(error)
        )

    # ========================================================
    # WEBHOOK
    # ========================================================

    webhook_result = False

    try:

        webhook_result = (
            send_honeytoken_webhook(

                token_id=
                    token.token_id,

                document=
                    token.document_name,

                event_type=
                    event.event_type,

                source_ip=
                    event.source_ip,

                risk_score=
                    risk_score,

                severity=
                    severity,

                reasons=
                    reasons
            )
        )

    except Exception as error:

        print(
            "Webhook notification error:",
            str(error)
        )

    # ========================================================
    # RESPONSE
    # ========================================================

    return {

        "alert":
            True,

        "message":
            "Honeytoken triggered",

        "token_id":
            token.token_id,

        "document":
            token.document_name,

        "event_id":
            event.id,

        "alert_id":
            alert.id,

        "risk_score":
            risk_score,

        "severity":
            severity,

        "source_ip":
            event.source_ip,

        "detection_reasons":
            reasons,

        "ip_intelligence":
            ip_intelligence,

        "mitre_attack": {

            "techniques":
                mitre_mappings,

            "summary":
                mitre_summary
        },

        "siem_notification":
            siem_result,

        "telegram_notification":
            telegram_result,

        "email_notification":
            email_result,

        "webhook_notification":
            webhook_result
    }


# ============================================================
# CREATE EVENT
# ============================================================

@router.post("/")
def create_security_event(

    data: SecurityEventCreate,

    request: Request,

    db: Session = Depends(get_db),

    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST")
    )
):

    source_ip = (

        data.source_ip

        or (

            request.client.host

            if request.client

            else None
        )
    )

    event = SecurityEvent(

        token_id=
            data.token_id,

        event_type=
            data.event_type,

        source_ip=
            source_ip,

        user_agent=
            data.user_agent
    )

    return process_security_event(

        db=db,

        event=event
    )


# ============================================================
# CALLBACK
# ============================================================

@router.get(
    "/trigger/{token_id}"
)
def honeytoken_callback(

    token_id: str,

    request: Request,

    db: Session = Depends(get_db)
):

    token = (
        db.query(Honeytoken)
        .filter(
            Honeytoken.token_id
            == token_id
        )
        .first()
    )

    if not token:

        raise HTTPException(
            status_code=404,
            detail="Honeytoken not found"
        )

    source_ip = (

        request.client.host

        if request.client

        else None
    )

    user_agent = (
        request.headers.get(
            "user-agent"
        )
    )

    event = SecurityEvent(

        token_id=
            token_id,

        event_type=
            "TOKEN_TRIGGERED",

        source_ip=
            source_ip,

        user_agent=
            user_agent
    )

    return process_security_event(

        db=db,

        event=event
    )


# ============================================================
# GET EVENTS
# ============================================================

@router.get("/")
def get_security_events(
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST", "VIEWER")
    )
):

    events = (
        db.query(SecurityEvent)
        .order_by(
            SecurityEvent.timestamp.desc()
        )
        .all()
    )

    results = []

    for event in events:

        token = (
            db.query(Honeytoken)
            .filter(
                Honeytoken.token_id
                == event.token_id
            )
            .first()
        )

        mitre_techniques = []

        if event.mitre_techniques:

            try:

                mitre_techniques = (
                    json.loads(
                        event.mitre_techniques
                    )
                )

            except (
                json.JSONDecodeError,
                TypeError
            ):

                mitre_techniques = []

        mitre_tactics = []

        if event.mitre_tactics:

            try:

                mitre_tactics = (
                    json.loads(
                        event.mitre_tactics
                    )
                )

            except (
                json.JSONDecodeError,
                TypeError
            ):

                mitre_tactics = []

        results.append({

            "id":
                event.id,

            "token_id":
                event.token_id,

            "document":
                (
                    token.document_name
                    if token
                    else "Unknown"
                ),

            "event_type":
                event.event_type,

            "source_ip":
                event.source_ip,

            "user_agent":
                event.user_agent,

            "risk_score":
                event.risk_score,

            "severity":
                event.severity,

            "ip_intelligence": {

                "country":
                    event.ip_country,

                "country_code":
                    event.ip_country_code,

                "region":
                    event.ip_region,

                "city":
                    event.ip_city,

                "isp":
                    event.ip_isp,

                "organization":
                    event.ip_organization,

                "asn":
                    event.ip_asn,

                "timezone":
                    event.ip_timezone,

                "latitude":
                    event.ip_latitude,

                "longitude":
                    event.ip_longitude,

                "is_private":
                    event.ip_is_private
            },

            "mitre_attack": {

                "techniques":
                    mitre_techniques,

                "tactics":
                    mitre_tactics
            },

            "timestamp":
                (
                    event.timestamp.isoformat()
                    if event.timestamp
                    else None
                )
        })

    return {

        "total":
            len(results),

        "events":
            results
    }


# ============================================================
# GET SINGLE EVENT
# ============================================================

@router.get(
    "/id/{event_id}"
)
def get_security_event(

    event_id: int,

    db: Session = Depends(get_db),

    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST", "VIEWER")
    )
):

    event = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.id
            == event_id
        )
        .first()
    )

    if not event:

        raise HTTPException(
            status_code=404,
            detail="Security event not found"
        )

    token = (
        db.query(Honeytoken)
        .filter(
            Honeytoken.token_id
            == event.token_id
        )
        .first()
    )

    mitre_techniques = []

    if event.mitre_techniques:

        try:

            mitre_techniques = (
                json.loads(
                    event.mitre_techniques
                )
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            mitre_techniques = []

    mitre_tactics = []

    if event.mitre_tactics:

        try:

            mitre_tactics = (
                json.loads(
                    event.mitre_tactics
                )
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            mitre_tactics = []

    return {

        "id":
            event.id,

        "token_id":
            event.token_id,

        "document":
            (
                token.document_name
                if token
                else "Unknown"
            ),

        "event_type":
            event.event_type,

        "source_ip":
            event.source_ip,

        "user_agent":
            event.user_agent,

        "risk_score":
            event.risk_score,

        "severity":
            event.severity,

        "ip_intelligence": {

            "country":
                event.ip_country,

            "country_code":
                event.ip_country_code,

            "region":
                event.ip_region,

            "city":
                event.ip_city,

            "isp":
                event.ip_isp,

            "organization":
                event.ip_organization,

            "asn":
                event.ip_asn,

            "timezone":
                event.ip_timezone,

            "latitude":
                event.ip_latitude,

            "longitude":
                event.ip_longitude,

            "is_private":
                event.ip_is_private
        },

        "mitre_attack": {

            "techniques":
                mitre_techniques,

            "tactics":
                mitre_tactics
        },

        "timestamp":
            (
                event.timestamp.isoformat()
                if event.timestamp
                else None
            )
    }



