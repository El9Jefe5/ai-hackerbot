from tests.conftest import login


def _target(env, h, value="juice-shop"):
    return env.client.post("/targets", json={"value": value}, headers=h).json()["id"]


def test_unverified_target_cannot_be_assessed(env):
    h = login(env.client, "a@x.io")
    tid = _target(env, h)
    r = env.client.post("/assessments", json={"target_id": tid}, headers=h)
    assert r.status_code == 403 and env.queue.items == []


def test_verified_lab_target_is_queued(env):
    h = login(env.client, "a@x.io")
    tid = _target(env, h)
    env.client.post(f"/targets/{tid}/verify", headers=h)
    r = env.client.post("/assessments", json={"target_id": tid}, headers=h)
    assert r.status_code == 202 and r.json()["status"] == "queued"
    assert env.queue.items == [r.json()["id"]]
    got = env.client.get(f"/assessments/{r.json()['id']}", headers=h).json()
    assert got["findings"] == []


def test_unknown_profile_rejected(env):
    h = login(env.client, "a@x.io")
    tid = _target(env, h)
    env.client.post(f"/targets/{tid}/verify", headers=h)
    r = env.client.post("/assessments", json={"target_id": tid, "profile": "rm -rf"}, headers=h)
    assert r.status_code == 422


def test_cannot_use_or_read_other_users_resources(env):
    a, b = login(env.client, "a@x.io"), login(env.client, "b@x.io")
    tid = _target(env, a)
    env.client.post(f"/targets/{tid}/verify", headers=a)
    assert env.client.post("/assessments", json={"target_id": tid}, headers=b).status_code == 404
    aid = env.client.post("/assessments", json={"target_id": tid}, headers=a).json()["id"]
    assert env.client.get(f"/assessments/{aid}", headers=b).status_code == 404


def test_requires_auth(env):
    assert env.client.post("/assessments", json={"target_id": 1}).status_code == 401
