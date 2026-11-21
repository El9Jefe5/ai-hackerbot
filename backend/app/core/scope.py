"""
Scope guard: the single choke point every scanner/agent action must pass.
Deny by default. The AI agent never builds targets itself; it can only
reference Target rows that this module has approved.
"""
import ipaddress
import re
import socket
from typing import Callable

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Never scannable, even if "verified" (SSRF / cloud metadata / local).
_ALWAYS_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    "::1/128", "fe80::/10", "ff00::/8",
)]


class ScopeViolation(Exception):
    pass


def classify(value: str) -> str:
    v = value.strip().lower()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            pass
    if _DOMAIN.match(v):
        return "domain"
    raise ScopeViolation(f"Unrecognized target format: {value!r}")


def _net(v: str):
    return ipaddress.ip_network(v, strict=False)


def _in_lab(value: str, kind: str, lab: list[str]) -> bool:
    for entry in lab:
        if kind == "domain":
            if value.lower() == entry.lower():
                return True
        else:
            try:
                n, e = _net(value), _net(entry)
                if n.version == e.version and n.subnet_of(e):
                    return True
            except ValueError:
                continue
    return False


def authorize(value: str, kind: str, verified: bool, lab_allowlist: list[str]) -> None:
    """Static policy check. Raise ScopeViolation unless the target may be assessed."""
    if not verified:
        raise ScopeViolation("Target ownership not verified")
    if kind in ("ip", "cidr"):
        net = _net(value)
        if any(net.version == b.version and net.overlaps(b) for b in _ALWAYS_BLOCKED):
            raise ScopeViolation("Target is in a permanently blocked range")
        if (net.is_private or net.is_reserved) and not _in_lab(value, kind, lab_allowlist):
            raise ScopeViolation("Private/reserved range is outside the lab allowlist")


def default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({i[4][0].split("%")[0] for i in infos})


def authorize_resolved(
    value: str, kind: str, verified: bool, lab_allowlist: list[str],
    resolver: Callable[[str], list[str]] = default_resolver,
) -> list[str]:
    """
    Execution-time check (ADR-005). Domains are resolved NOW and every resulting
    IP must pass policy, which defeats DNS rebinding. Returns the vetted
    addresses; callers must scan THESE, never re-resolve the name.
    """
    authorize(value, kind, verified, lab_allowlist)
    if kind != "domain":
        return [value]
    try:
        ips = resolver(value)
    except OSError:
        raise ScopeViolation("Domain did not resolve")
    if not ips:
        raise ScopeViolation("Domain did not resolve")
    for ip in ips:
        authorize(ip, "ip", True, lab_allowlist)
    return ips
