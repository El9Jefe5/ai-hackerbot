import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import config
from app.core.db import Base, get_db
from app.main import app

PW = "correct-horse-battery"


@pytest.fixture()
def client(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    Session = sessionmaker(eng, expire_on_commit=False)

    def _db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _db
    monkeypatch.setattr(config.settings, "lab_targets", ["juice-shop", "172.28.0.0/24"])
    yield TestClient(app)
    app.dependency_overrides.clear()


def _login(c, email):
    c.post("/auth/register", json={"email": email, "password": PW})
    tok = c.post("/auth/login", json={"email": email, "password": PW}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def test_requires_auth(client):
    assert client.get("/targets").status_code == 401


def test_bad_login(client):
    client.post("/auth/register", json={"email": "a@x.io", "password": PW})
    assert client.post("/auth/login", json={"email": "a@x.io", "password": "wrong-password"}).status_code == 401


def test_lab_flow_end_to_end(client):
    h = _login(client, "a@x.io")
    t = client.post("/targets", json={"value": "juice-shop"}, headers=h).json()
    assert client.get(f"/targets/{t['id']}/scope-check", headers=h).json()["decision"] == "deny"
    assert client.post(f"/targets/{t['id']}/verify", headers=h).json()["verified"] is True
    assert client.get(f"/targets/{t['id']}/scope-check", headers=h).json()["decision"] == "allow"


def test_cannot_access_other_users_target(client):
    a = _login(client, "a@x.io")
    b = _login(client, "b@x.io")
    t = client.post("/targets", json={"value": "juice-shop"}, headers=a).json()
    assert client.get(f"/targets/{t['id']}/scope-check", headers=b).status_code == 404


def test_metadata_ip_never_allowed(client):
    h = _login(client, "a@x.io")
    t = client.post("/targets", json={"value": "169.254.169.254"}, headers=h).json()
    assert client.post(f"/targets/{t['id']}/verify", headers=h).status_code == 501  # not lab, can't verify
