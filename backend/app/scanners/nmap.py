"""
nmap wrapper. The agent/worker picks a PROFILE NAME; it never supplies flags.
Execution uses an argv list (no shell) with a timeout.
"""
import subprocess
import xml.etree.ElementTree as ET

from app.core import scope

# -sT = TCP connect scan: needs no raw sockets, so the container runs with zero Linux capabilities.
PROFILES: dict[str, list[str]] = {
    "nmap_quick": ["-sT", "-Pn", "-T3", "--top-ports", "100", "--open"],
}


def build_argv(profile: str, target: str) -> list[str]:
    if profile not in PROFILES:
        raise ValueError(f"Unknown scan profile: {profile!r}")
    if not target or target.startswith("-") or any(c.isspace() for c in target):
        raise ValueError("Invalid scan target")
    scope.classify(target)  # must be a well-formed ip / cidr / domain
    return ["nmap", *PROFILES[profile], "-oX", "-", target]


def run(profile: str, target: str, timeout: int = 300) -> str:
    argv = build_argv(profile, target)
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def parse_xml(xml_text: str) -> list[dict]:
    """Extract open ports. Output is derived from a hostile network: treat as data only."""
    root = ET.fromstring(xml_text)
    out: list[dict] = []
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr", "") if addr is not None else ""
        for p in host.findall("./ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            out.append({
                "host": ip,
                "port": int(p.get("portid", "0")),
                "protocol": p.get("protocol", "tcp"),
                "service": svc.get("name", "unknown") if svc is not None else "unknown",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
    return out
