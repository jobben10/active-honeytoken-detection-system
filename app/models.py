from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from .database import Base


class Honeytoken(Base):
    __tablename__ = "honeytokens"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    token_id = Column(
        String(100),
        unique=True,
        index=True,
        nullable=False
    )

    document_name = Column(
        String(255),
        nullable=False
    )

    document_type = Column(
        String(50),
        nullable=False
    )

    classification = Column(
        String(50),
        default="CONFIDENTIAL"
    )

    severity = Column(
        String(20),
        default="HIGH"
    )

    status = Column(
        String(20),
        default="ACTIVE"
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    token_id = Column(
        String(100),
        index=True,
        nullable=False
    )

    event_type = Column(
        String(100),
        nullable=False
    )

    source_ip = Column(
        String(100)
    )

    user_agent = Column(
        String(500)
    )

    risk_score = Column(
        Integer,
        default=0
    )

    severity = Column(
        String(20),
        default="LOW"
    )

    # --------------------------------------------------------
    # IP INTELLIGENCE
    # --------------------------------------------------------

    ip_country = Column(
        String(100)
    )

    ip_country_code = Column(
        String(20)
    )

    ip_region = Column(
        String(100)
    )

    ip_city = Column(
        String(100)
    )

    ip_isp = Column(
        String(255)
    )

    ip_organization = Column(
        String(255)
    )

    ip_asn = Column(
        String(100)
    )

    ip_timezone = Column(
        String(100)
    )

    ip_latitude = Column(
        String(50)
    )

    ip_longitude = Column(
        String(50)
    )

    ip_is_private = Column(
        String(10),
        default="true"
    )

    # --------------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------------

    mitre_techniques = Column(
        Text,
        nullable=True
    )

    mitre_tactics = Column(
        Text,
        nullable=True
    )

    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    token_id = Column(
        String(100),
        index=True,
        nullable=False
    )

    event_id = Column(
        Integer,
        index=True,
        nullable=False
    )

    title = Column(
        String(255),
        nullable=False
    )

    message = Column(
        Text,
        nullable=False
    )

    severity = Column(
        String(20),
        default="LOW"
    )

    risk_score = Column(
        Integer,
        default=0
    )

    detection_reasons = Column(
        Text,
        nullable=True
    )

    source_ip = Column(
        String(100)
    )

    status = Column(
        String(30),
        default="OPEN"
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    acknowledged_at = Column(
        DateTime,
        nullable=True
    )

    resolved_at = Column(
        DateTime,
        nullable=True
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    action = Column(
        String(100),
        nullable=False,
        index=True
    )

    resource_type = Column(
        String(100),
        nullable=False
    )

    resource_id = Column(
        String(100),
        nullable=True,
        index=True
    )

    source_ip = Column(
        String(100),
        nullable=True
    )

    details = Column(
        Text,
        nullable=True
    )

    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )