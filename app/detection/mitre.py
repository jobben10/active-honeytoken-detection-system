from typing import Any


# ============================================================
# MITRE ATT&CK TECHNIQUE DEFINITIONS
# ============================================================

MITRE_TECHNIQUES = {
    "T1083": {
        "technique": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may enumerate files and directories "
            "to locate information of interest."
        )
    },

    "T1005": {
        "technique": "Data from Local System",
        "tactic": "Collection",
        "description": (
            "Adversaries may search local system sources "
            "to find files and information of interest."
        )
    },

    "T1071.001": {
        "technique": "Web Protocols: Web Protocols",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using application "
            "layer protocols such as HTTP or HTTPS."
        )
    },

    "T1059": {
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and scripting "
            "interpreters to execute commands."
        )
    },

    "T1041": {
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data over an existing "
            "command and control channel."
        )
    }
}


# ============================================================
# MAP EVENT TO MITRE ATT&CK
# ============================================================

def map_event_to_mitre(
    event_type: str | None,
    user_agent: str | None = None,
    source_ip: str | None = None
) -> list[dict[str, Any]]:

    mappings = []

    event = (
        event_type or ""
    ).upper()

    agent = (
        user_agent or ""
    ).lower()

    # --------------------------------------------------------
    # DOCUMENT / FILE ACCESS
    # --------------------------------------------------------

    if (
        "TOKEN" in event
        or "DOCUMENT" in event
        or "FILE" in event
    ):

        mappings.append({
            "id": "T1083",
            **MITRE_TECHNIQUES["T1083"]
        })

        mappings.append({
            "id": "T1005",
            **MITRE_TECHNIQUES["T1005"]
        })

    # --------------------------------------------------------
    # SCRIPTED / AUTOMATED ACCESS
    # --------------------------------------------------------

    scripting_tools = [
        "powershell",
        "python",
        "python-requests",
        "curl",
        "wget",
        "bash",
        "cmd",
        "sqlmap"
    ]

    if any(
        tool in agent
        for tool in scripting_tools
    ):

        mappings.append({
            "id": "T1059",
            **MITRE_TECHNIQUES["T1059"]
        })

    # --------------------------------------------------------
    # HTTP CALLBACK / WEB ACCESS
    # --------------------------------------------------------

    if (
        "CALLBACK" in event
        or "HTTP" in event
        or "WEB" in event
        or "TOKEN" in event
    ):

        mappings.append({
            "id": "T1071.001",
            **MITRE_TECHNIQUES["T1071.001"]
        })

    # --------------------------------------------------------
    # POSSIBLE EXFILTRATION
    # --------------------------------------------------------

    if (
        "EXFIL" in event
        or "DOWNLOAD" in event
        or "EXPORT" in event
    ):

        mappings.append({
            "id": "T1041",
            **MITRE_TECHNIQUES["T1041"]
        })

    # --------------------------------------------------------
    # REMOVE DUPLICATES
    # --------------------------------------------------------

    unique = {}

    for mapping in mappings:
        unique[mapping["id"]] = mapping

    return list(unique.values())


# ============================================================
# SUMMARY
# ============================================================

def summarize_mitre_mapping(
    mappings: list[dict[str, Any]]
):

    tactics = sorted({
        mapping["tactic"]
        for mapping in mappings
    })

    techniques = sorted({
        mapping["id"]
        for mapping in mappings
    })

    return {
        "technique_count": len(
            techniques
        ),
        "tactic_count": len(
            tactics
        ),
        "techniques": techniques,
        "tactics": tactics
    }