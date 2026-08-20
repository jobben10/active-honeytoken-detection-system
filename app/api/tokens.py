import secrets
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse

from ..database import get_db
from ..models import Honeytoken, SecurityEvent
from ..schemas import HoneytokenCreate, HoneytokenResponse
from ..honeytokens.documents import create_excel_honeytoken
from ..detection.audit import create_audit_log
from ..security import require_roles


router = APIRouter(
    prefix="/api/tokens",
    tags=["Honeytokens"]
)


DOCUMENTS_DIR = Path("documents")

DOCUMENTS_DIR.mkdir(
    exist_ok=True
)


def generate_token():
    random_part = secrets.token_hex(
        4
    ).upper()

    return f"HNY-{random_part}"


def generate_unique_token(
    db: Session
):
    while True:

        token_id = generate_token()

        existing = (
            db.query(Honeytoken)
            .filter(
                Honeytoken.token_id == token_id
            )
            .first()
        )

        if not existing:
            return token_id


def create_filename(
    document_name: str,
    token_id: str
):
    original_name = Path(
        document_name
    ).stem

    extension = Path(
        document_name
    ).suffix.lower()

    if not extension:
        extension = ".xlsx"

    safe_name = (
        original_name
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace("*", "_")
        .replace("?", "_")
        .replace('"', "_")
        .replace("<", "_")
        .replace(">", "_")
        .replace("|", "_")
    )

    return (
        f"{safe_name}_{token_id}"
        f"{extension}"
    )


@router.post(
    "/",
    response_model=HoneytokenResponse
)
def create_honeytoken(
    data: HoneytokenCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles("ADMIN"))
):
    document_type = (
        data.document_type
        .strip()
        .lower()
    )

    if document_type != "xlsx":

        raise HTTPException(
            status_code=400,
            detail=(
                "Currently only XLSX "
                "documents are supported"
            )
        )

    token_id = generate_unique_token(
        db
    )

    token = Honeytoken(
        token_id=token_id,
        document_name=data.document_name,
        document_type=document_type,
        classification=data.classification,
        severity=data.severity,
        status="ACTIVE"
    )

    db.add(token)
    db.commit()
    db.refresh(token)

    filename = create_filename(
        data.document_name,
        token_id
    )

    try:

        filepath = create_excel_honeytoken(
            token_id=token_id,
            filename=filename
        )

    except Exception as error:

        db.delete(token)
        db.commit()

        raise HTTPException(
            status_code=500,
            detail=(
                "Honeytoken was created "
                "but document generation failed: "
                f"{str(error)}"
            )
        )

    create_audit_log(
        db=db,
        action="HONEYTOKEN_CREATED",
        resource_type="HONEYTOKEN",
        resource_id=token_id,
        source_ip=(
            request.client.host
            if request.client
            else None
        ),
        details={
            "document_name":
                data.document_name,

            "document_type":
                document_type,

            "classification":
                data.classification,

            "severity":
                data.severity,

            "status":
                "ACTIVE",

            "generated_file":
                filepath
        }
    )

    return token


@router.get("/")
def get_honeytokens(
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST", "VIEWER")
    )
):
    tokens = (
        db.query(Honeytoken)
        .order_by(
            Honeytoken.created_at.desc()
        )
        .all()
    )

    results = []

    for token in tokens:

        trigger_count = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.token_id
                == token.token_id
            )
            .count()
        )

        last_event = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.token_id
                == token.token_id
            )
            .order_by(
                SecurityEvent.timestamp.desc()
            )
            .first()
        )

        callback_url = (
            "http://127.0.0.1:8000/"
            f"api/events/trigger/"
            f"{token.token_id}"
        )

        results.append({

            "id":
                token.id,

            "token_id":
                token.token_id,

            "document_name":
                token.document_name,

            "document_type":
                token.document_type,

            "classification":
                token.classification,

            "severity":
                token.severity,

            "status":
                token.status,

            "trigger_count":
                trigger_count,

            "last_triggered":
                (
                    last_event.timestamp.isoformat()
                    if last_event
                    else None
                ),

            "created_at":
                (
                    token.created_at.isoformat()
                    if token.created_at
                    else None
                ),

            "callback_url":
                callback_url
        })

    return {
        "total": len(results),
        "tokens": results
    }

# ============================================================
# HONEYTOKEN DOCUMENT
# ============================================================

@router.get("/{token_id}/document")
def open_honeytoken_document(
    token_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST", "VIEWER")
    )
):
    token = (
        db.query(Honeytoken)
        .filter(
            Honeytoken.token_id == token_id
        )
        .first()
    )

    if not token:
        raise HTTPException(
            status_code=404,
            detail="Honeytoken not found"
        )

    filename = create_filename(
        token.document_name,
        token.token_id
    )

    filepath = DOCUMENTS_DIR / filename

    if not filepath.exists():
        raise HTTPException(
            status_code=404,
            detail="Honeytoken document not found"
        )

    return FileResponse(
        path=str(filepath),
        filename=filename,
        media_type=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        )
    )


@router.get("/{token_id}")
def get_honeytoken(
    token_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN", "SOC_ANALYST", "VIEWER")
    )
):
    token = (
        db.query(Honeytoken)
        .filter(
            Honeytoken.token_id == token_id
        )
        .first()
    )

    if not token:

        raise HTTPException(
            status_code=404,
            detail="Honeytoken not found"
        )

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.token_id
            == token.token_id
        )
        .order_by(
            SecurityEvent.timestamp.desc()
        )
        .all()
    )

    callback_url = (
        "http://127.0.0.1:8000/"
        f"api/events/trigger/"
        f"{token.token_id}"
    )

    return {

        "id":
            token.id,

        "token_id":
            token.token_id,

        "document_name":
            token.document_name,

        "document_type":
            token.document_type,

        "classification":
            token.classification,

        "severity":
            token.severity,

        "status":
            token.status,

        "trigger_count":
            len(events),

        "last_triggered":
            (
                events[0].timestamp.isoformat()
                if events
                else None
            ),

        "created_at":
            (
                token.created_at.isoformat()
                if token.created_at
                else None
            ),

        "callback_url":
            callback_url,

        "events": [

            {
                "id":
                    event.id,

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

                "timestamp":
                    (
                        event.timestamp.isoformat()
                        if event.timestamp
                        else None
                    )
            }

            for event in events
        ]
    }


@router.put(
    "/{token_id}/deactivate"
)
def deactivate_honeytoken(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN")
    )
):
    token = (
        db.query(Honeytoken)
        .filter(
            Honeytoken.token_id == token_id
        )
        .first()
    )

    if not token:

        raise HTTPException(
            status_code=404,
            detail="Honeytoken not found"
        )

    token.status = "INACTIVE"

    db.commit()
    db.refresh(token)

    create_audit_log(
        db=db,
        action="HONEYTOKEN_DEACTIVATED",
        resource_type="HONEYTOKEN",
        resource_id=token.token_id,
        source_ip=(
            request.client.host
            if request.client
            else None
        ),
        details={
            "document_name":
                token.document_name,

            "previous_status":
                "ACTIVE",

            "new_status":
                "INACTIVE"
        }
    )

    return {

        "message":
            "Honeytoken deactivated",

        "token_id":
            token.token_id,

        "status":
            token.status
    }


@router.put(
    "/{token_id}/activate"
)
def activate_honeytoken(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: dict = Depends(
        require_roles("ADMIN")
    )
):
    token = (
        db.query(Honeytoken)
        .filter(
            Honeytoken.token_id == token_id
        )
        .first()
    )

    if not token:

        raise HTTPException(
            status_code=404,
            detail="Honeytoken not found"
        )

    token.status = "ACTIVE"

    db.commit()
    db.refresh(token)

    create_audit_log(
        db=db,
        action="HONEYTOKEN_ACTIVATED",
        resource_type="HONEYTOKEN",
        resource_id=token.token_id,
        source_ip=(
            request.client.host
            if request.client
            else None
        ),
        details={
            "document_name":
                token.document_name,

            "previous_status":
                "INACTIVE",

            "new_status":
                "ACTIVE"
        }
    )

    return {

        "message":
            "Honeytoken activated",

        "token_id":
            token.token_id,

        "status":
            token.status
    }

