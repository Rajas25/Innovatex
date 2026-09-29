from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed_all

client = TestClient(app)


def setup_module() -> None:
    seed_all()


def test_login_success():
    r = client.post("/api/auth/login", json={"username": "tester", "password": "Tester!Pass2024"})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "tester"


def test_login_failure():
    r = client.post("/api/auth/login", json={"username": "tester", "password": "wrong"})
    assert r.status_code == 401


def test_me_requires_token():
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_me_with_token():
    login = client.post("/api/auth/login",
                        json={"username": "lead", "password": "Lead!Pass2024"}).json()
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {login['token']}"})
    assert r.status_code == 200
    assert r.json()["username"] == "lead"