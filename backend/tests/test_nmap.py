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


# Shape taken from a real Juice Shop scan: nmap matched nothing and fell back to its port table.
UNMATCHED_HTTP = r"""<nmaprun><host><address addr="172.28.0.10"/><ports>
<port protocol="tcp" portid="3000"><state state="open"/>
<service name="ppp" servicefp="SF-Port3000-TCP:V=7.95%r(GetRequest,281E,&quot;HTTP/1\.1\x20200\x20OK\r\nX-Frame-Options:\x20SAMEORIGIN&quot;)%r(Help,2F,&quot;HTTP/1\.1\x20400\x20Bad\x20Request&quot;);" method="table" conf="3"/>
</port></ports></host></nmaprun>"""

GUESS_ONLY = """<nmaprun><host><address addr="172.28.0.10"/><ports>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" method="table" conf="3"/></port>
</ports></host></nmaprun>"""


def test_http_reply_overrides_port_table_guess():
    p = nmap.parse_xml(UNMATCHED_HTTP)[0]
    assert p["service"] == "http" and p["method"] == "inferred" and p["confirmed"]


def test_bare_table_guess_is_marked_unconfirmed():
    p = nmap.parse_xml(GUESS_ONLY)[0]
    assert p["service"] == "telnet" and not p["confirmed"]


def test_probed_service_is_confirmed():
    xml = SAMPLE.replace('<service name="http"', '<service method="probed" name="http"')
    assert nmap.parse_xml(xml)[0]["confirmed"]
