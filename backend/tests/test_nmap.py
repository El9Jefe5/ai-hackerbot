import pytest

from app.core.scope import ScopeViolation
from app.scanners import nmap

SAMPLE = """<?xml version="1.0"?>
<nmaprun><host><address addr="172.28.0.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="3000"><state state="open"/><service name="http" product="Express" version="4"/></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
</ports></host></nmaprun>"""


def test_parse_only_open_ports():
    ports = nmap.parse_xml(SAMPLE)
    assert len(ports) == 1
    assert ports[0]["port"] == 3000 and ports[0]["service"] == "http" and ports[0]["product"] == "Express"


def test_argv_is_fixed_and_shell_free():
    argv = nmap.build_argv("nmap_quick", "172.28.0.10")
    assert argv[0] == "nmap" and argv[-1] == "172.28.0.10" and "-sT" in argv


@pytest.mark.parametrize("bad", ["-iL /etc/passwd", "1.2.3.4; id", "--script=x", "a b", ""])
def test_argument_injection_rejected(bad):
    with pytest.raises((ValueError, ScopeViolation)):
        nmap.build_argv("nmap_quick", bad)


def test_unknown_profile_rejected():
    with pytest.raises(ValueError):
        nmap.build_argv("nmap_all_the_things", "172.28.0.10")
