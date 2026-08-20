from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..models import Honeytoken, SecurityEvent


def calculate_correlated_risk(
    db: Session,
    token: Honeytoken,
    event: SecurityEvent
):
    """
    Calculate a risk score using the current event
    plus recent correlated activity.
    """

    score = 0

    reasons = []

    # -------------------------------------------------
    # BASE RISK
    # -------------------------------------------------

    if token.classification.upper() == "CONFIDENTIAL":
        score += 30
        reasons.append(
            "Confidential document"
        )

    if token.severity.upper() == "CRITICAL":
        score += 40
        reasons.append(
            "Critical honeytoken"
        )

    elif token.severity.upper() == "HIGH":
        score += 30
        reasons.append(
            "High severity honeytoken"
        )

    elif token.severity.upper() == "MEDIUM":
        score += 20
        reasons.append(
            "Medium severity honeytoken"
        )

    if event.source_ip:
        score += 20
        reasons.append(
            "Source IP identified"
        )

    # -------------------------------------------------
    # CORRELATION WINDOW
    # -------------------------------------------------

    now = datetime.now(timezone.utc)

    window_start = (
        now - timedelta(minutes=15)
    )

    recent_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.timestamp >= window_start
        )
        .all()
    )

    # -------------------------------------------------
    # REPEATED ACCESS
    # -------------------------------------------------

    same_token_events = [
        item
        for item in recent_events
        if item.token_id == token.token_id
        and item.id != event.id
    ]

    if len(same_token_events) >= 1:

        score += 15

        reasons.append(
            "Repeated access to the same honeytoken"
        )

    if len(same_token_events) >= 3:

        score += 15

        reasons.append(
            "Multiple repeated accesses"
        )

    # -------------------------------------------------
    # SAME SOURCE IP
    # -------------------------------------------------

    if event.source_ip:

        same_ip_events = [
            item
            for item in recent_events
            if item.source_ip == event.source_ip
            and item.id != event.id
        ]

        if len(same_ip_events) >= 1:

            score += 15

            reasons.append(
                "Repeated activity from the same IP"
            )

        if len(same_ip_events) >= 3:

            score += 15

            reasons.append(
                "High activity from the same IP"
            )

    # -------------------------------------------------
    # MULTIPLE HONEYTOKENS
    # -------------------------------------------------

    if event.source_ip:

        token_ids = {
            item.token_id
            for item in recent_events
            if item.source_ip == event.source_ip
        }

        token_ids.add(
            event.token_id
        )

        if len(token_ids) >= 2:

            score += 25

            reasons.append(
                "Multiple honeytokens triggered "
                "from the same IP"
            )

        if len(token_ids) >= 3:

            score += 25

            reasons.append(
                "Multiple sensitive resources "
                "targeted from the same IP"
            )

    # -------------------------------------------------
    # SUSPICIOUS USER AGENT
    # -------------------------------------------------

    if event.user_agent:

        user_agent = (
            event.user_agent.lower()
        )

        suspicious_agents = [
            "curl",
            "wget",
            "python-requests",
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "scanner",
            "bot"
        ]

        matched_agent = next(
            (
                agent
                for agent in suspicious_agents
                if agent in user_agent
            ),
            None
        )

        if matched_agent:

            score += 20

            reasons.append(
                f"Suspicious user agent: "
                f"{matched_agent}"
            )

    # -------------------------------------------------
    # CAP SCORE
    # -------------------------------------------------

    score = min(
        score,
        100
    )

    return {
        "score": score,
        "reasons": reasons
    }


def determine_correlated_severity(
    score: int
):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"