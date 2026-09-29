from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed_all

client = TestClient(app)


def setup_module() -> None:
    seed_all()


def _token() -> str:
    return client.post("/api/auth/login",
                       json={"username": "tester", "password": "Tester!Pass2024"}).json()["token"]


def _run(lab_id: str, payload: dict):
    r = client.post("/api/labs/run",
                    json={"lab_id": lab_id, "payload": payload},
                    headers={"Authorization": f"Bearer {_token()}"})
    assert r.status_code == 200, r.text
    return r.json()


def test_xss_lab_detects_exploitation():
    result = _run("xss", {"name": "<img src=x onerror=alert(1)>"})
    assert result["exploited"] is True


def test_sqli_lab_returns_more_rows_than_baseline():
    result = _run("sqli", {"term": "' OR '1'='1"})
    assert result["exploited"] is True
    assert result["response"]["row_count"] >= 5


def test_idor_lab_crosses_owner_boundary():
    result = _run("idor", {"id": "wm-1004", "as_user": "s.novak"})
    assert result["exploited"] is True


def test_bfla_lab_escalates_viewer():
    seed_all()  # reset the role we are about to flip
    result = _run("bfla", {"as_user": "s.novak", "target_id": 3, "role": "admin"})
    assert result["exploited"] is True


def test_jwt_lab_forges_none_alg():
    result = _run("jwt", {})
    assert result["exploited"] is True
    assert result["response"]["server_response"]["signature_verified"] is False


def test_headers_lab_scores_poorly():
    result = _run("headers", {})
    assert result["exploited"] is True
    assert result["response"]["score"] < 60


def test_all_twelve_labs_are_registered():
    token = _token()
    labs = client.get("/api/labs", headers={"Authorization": f"Bearer {token}"}).json()
    assert len(labs) == 12