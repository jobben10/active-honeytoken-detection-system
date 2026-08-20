import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..security import require_roles
from ..models import AuditLog


router = APIRouter(
    prefix="/api/audit",
    tags=["Audit Logs"]
)


@router.get("/")
def get_audit_logs(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN", "SOC_ANALYST", "VIEWER"))
):

    logs = (
        db.query(AuditLog)
        .order_by(
            AuditLog.timestamp.desc()
        )
        .all()
    )

    results = []

    for log in logs:

        details = {}

        if log.details:

            try:
                details = json.loads(
                    log.details
                )
            except (
                json.JSONDecodeError,
                TypeError
            ):
                details = {
                    "raw": log.details
                }

        results.append({

            "id":
                log.id,

            "action":
                log.action,

            "resource_type":
                log.resource_type,

            "resource_id":
                log.resource_id,

            "source_ip":
                log.source_ip,

            "details":
                details,

            "timestamp":
                (
                    log.timestamp.isoformat()
                    if log.timestamp
                    else None
                )
        })

    return {
        "total": len(results),
        "logs": results
    }


@router.get("/summary")
def get_audit_summary(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN", "SOC_ANALYST", "VIEWER"))
):

    logs = (
        db.query(AuditLog)
        .all()
    )

    actions = {}

    resources = {}

    for log in logs:

        actions[log.action] = (
            actions.get(
                log.action,
                0
            ) + 1
        )

        resources[
            log.resource_type
        ] = (
            resources.get(
                log.resource_type,
                0
            ) + 1
        )

    return {

        "total": len(logs),

        "actions":
            actions,

        "resource_types":
            resources
    }
