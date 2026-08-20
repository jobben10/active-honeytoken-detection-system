import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models import AuditLog


def create_audit_log(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    source_ip: str | None = None,
    details: dict | None = None
):
    """
    Create a persistent security audit record.
    """

    audit = AuditLog(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        source_ip=source_ip,
        details=(
            json.dumps(details)
            if details
            else None
        ),
        timestamp=datetime.now(
            timezone.utc
        )
    )

    db.add(audit)

    db.commit()

    db.refresh(audit)

    return audit