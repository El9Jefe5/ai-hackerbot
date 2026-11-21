"""
Deterministic risk scoring. This, not the LLM, is the source of truth for severity.
Rules are conservative exposure heuristics; CVE correlation is a later milestone
and is deliberately NOT guessed here.
"""
SEV_ORDER = ["info", "low", "medium", "high", "critical"]

_DATASTORE = ("medium", "A datastore is reachable over the network.",
              "Bind to localhost or a private segment, require authentication and TLS.")

RULES: dict[str, tuple[str, str, str]] = {
    "telnet": ("high", "Telnet sends credentials and data in cleartext.",
               "Disable Telnet and use SSH with key-based authentication."),
    "ftp": ("medium", "FTP is unencrypted and often permits weak or anonymous access.",
            "Replace with SFTP/FTPS, disable anonymous access, restrict by firewall."),
    "microsoft-ds": ("medium", "SMB is exposed; it is a common lateral-movement vector.",
                     "Block SMB at the perimeter, disable SMBv1, require signing."),
    "netbios-ssn": ("medium", "NetBIOS session service is exposed.",
                    "Block NetBIOS at the perimeter and disable it where unused."),
    "ms-wbt-server": ("medium", "Remote Desktop is exposed to the network.",
                      "Put RDP behind a VPN or gateway; enforce NLA and MFA."),
    "vnc": ("medium", "VNC remote access is exposed.",
            "Tunnel VNC over SSH/VPN and require strong authentication."),
    "mysql": _DATASTORE, "postgresql": _DATASTORE, "redis": _DATASTORE,
    "mongod": _DATASTORE, "memcached": _DATASTORE, "ms-sql-s": _DATASTORE,
    "ssh": ("info", "Administrative access service is exposed.",
            "Use key authentication, disable root login, restrict by source IP."),
    "http": ("info", "Web service detected; needs application-level testing.",
             "Run a web scan (ZAP integration planned); enforce HTTPS and security headers."),
}
DEFAULT = ("info", "Open port detected.", "Confirm the service is required; close or firewall it if not.")


def score_findings(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        sev, why, fix = RULES.get(str(f.get("service", "")).lower(), DEFAULT)
        out.append({**f, "severity": sev, "why": why, "remediation": fix})
    return out


def overall(findings: list[dict]) -> str:
    if not findings:
        return "none"
    return max((f["severity"] for f in findings), key=SEV_ORDER.index)
