import types

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import config
from app.core.db import Base, get_db
from app.core.queue import get_queue
from app.main import app

PW = "correct-horse-battery"


class FakeQueue:
    def __init__(self):
        self.items = []

    def enqueue(self, assessment_id):
        self.items.append(assessment_id)


@pytest.fixture()
def env(monkeypatch):
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    Session = sessionmaker(eng, expire_on_commit=False)
    monkeypatch.setattr(config.settings, "lab_targets", ["juice-shop", "172.28.0.0/24"])
    q = FakeQueue()

    def _db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_queue] = lambda: q
    yield types.SimpleNamespace(client=TestClient(app), Session=Session, queue=q)
    app.dependency_overrides.clear()


def login(client, email):
    client.post("/auth/register", json={"email": email, "password": PW})
    tok = client.post("/auth/login", json={"email": email, "password": PW}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}
