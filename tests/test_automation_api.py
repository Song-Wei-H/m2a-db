from fastapi.testclient import TestClient

from app.main import app
from app.routers import automation


def test_target_automation_status_is_target_scoped(monkeypatch):
    monkeypatch.setattr(automation, "_target_tasks", {})
    response = TestClient(app).get("/automation/targets/31/status")
    assert response.status_code == 200
    assert response.json() == {"target_id": 31, "status": "stopped"}


def test_target_automation_fails_closed_for_unknown_target(monkeypatch):
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def get(self, model, target_id): return None

    monkeypatch.setattr(automation, "async_session", lambda: Session())
    response = TestClient(app).post("/automation/targets/999999/start")
    assert response.status_code == 404


def test_retest_requires_a_recorded_reason():
    response = TestClient(app).post(
        "/automation/targets/31/retest", json={"reason": ""}
    )
    assert response.status_code == 422
