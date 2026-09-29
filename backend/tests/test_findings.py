from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed_all

client = TestClient(app)


def setup_module() -> None:
    seed_all()


def _token(username: str, password: str) -> str:
    return client.post("/api/auth/login",
                       json={"username": username, "password": password}).json()["token"]


def test_list_findings():
    token = _token("tester", "Tester!Pass2024")
    r = client.get("/api/findings", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 12
    # CVSS scores must be computed server-side.
    assert all(f["cvss"]["score"] is not None for f in data)


def test_findings_require_auth():
    assert client.get("/api/findings").status_code == 401


def test_status_change_requires_lead():
    tester = _token("tester", "Tester!Pass2024")
    r = client.patch("/api/findings/WM-001/status",
                     json={"status": "confirmed"},
                     headers={"Authorization": f"Bearer {tester}"})
    assert r.status_code == 403

    lead = _token("lead", "Lead!Pass2024")
    r = client.patch("/api/findings/WM-001/status",
                     json={"status": "confirmed"},
                     headers={"Authorization": f"Bearer {lead}"})
    assert r.status_code == 200
    assert r.json()["status"] == "confirmed"