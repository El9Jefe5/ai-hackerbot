import pytest

from app.core.scope import ScopeViolation, authorize, classify

LAB = ["172.28.0.0/24", "juice-shop"]


def test_classify():
    assert classify("10.0.0.5") == "ip"
    assert classify("10.0.0.0/24") == "cidr"
    assert classify("Example.com") == "domain"
    with pytest.raises(ScopeViolation):
        classify("rm -rf /; whoami")


def test_unverified_denied():
    with pytest.raises(ScopeViolation):
        authorize("172.28.0.10", "ip", False, LAB)


@pytest.mark.parametrize("v", ["127.0.0.1", "169.254.169.254", "::1"])
def test_always_blocked_even_if_verified(v):
    with pytest.raises(ScopeViolation):
        authorize(v, "ip", True, LAB)


def test_private_outside_lab_denied():
    with pytest.raises(ScopeViolation):
        authorize("10.0.0.5", "ip", True, LAB)


def test_lab_allowed():
    authorize("172.28.0.10", "ip", True, LAB)
    authorize("juice-shop", "domain", True, LAB)


def test_cidr_cannot_exceed_lab():
    with pytest.raises(ScopeViolation):
        authorize("172.28.0.0/16", "cidr", True, LAB)
