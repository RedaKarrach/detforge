"""Human names for the ATT&CK ids used in this repository, so the CLI can print
"T1059.001 PowerShell" instead of a bare id. Offline on purpose: the table covers
the techniques the rules use; anything else falls back to the id."""

TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

TECHNIQUE_NAMES = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.003": "OS Credential Dumping: NTDS",
    "T1021": "Remote Services",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1047": "Windows Management Instrumentation",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1069": "Permission Groups Discovery",
    "T1069.002": "Permission Groups Discovery: Domain Groups",
    "T1070": "Indicator Removal",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1087": "Account Discovery",
    "T1087.002": "Account Discovery: Domain Account",
    "T1105": "Ingress Tool Transfer",
    "T1218": "System Binary Proxy Execution",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1490": "Inhibit System Recovery",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.002": "Abuse Elevation Control Mechanism: Bypass User Account Control",
    "T1569": "System Services",
    "T1569.002": "System Services: Service Execution",
}


def technique_name(technique_id: str) -> str:
    """ "T1059.001" -> "Command and Scripting Interpreter: PowerShell"; unknown ids return themselves."""
    return TECHNIQUE_NAMES.get(technique_id.upper(), technique_id.upper())


def tactic_name(tactic: str) -> str:
    return TACTIC_NAMES.get(tactic.lower(), tactic)
