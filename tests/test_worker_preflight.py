from fastapi.testclient import TestClient

from app.main import app
from app.routers import worker_preflight


def test_preflight_reports_capability_mismatch(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "ok", "allowed_tools": ["nmap_service", "httpx_basic"]}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url):
            return Response()

    monkeypatch.setattr(worker_preflight.httpx, "AsyncClient", lambda **kwargs: Client())
    monkeypatch.setattr(worker_preflight.settings, "allowed_tools", "nmap_service,httpx_basic,nuclei_safe")

    response = TestClient(app).get("/workers/preflight")

    assert response.status_code == 200
    assert response.json()["status"] == "CAPABILITY_MISMATCH"
    assert response.json()["missing_on_worker"] == ["nuclei_safe"]
    assert response.json()["version_verification"]["state"] == "REQUESTED_NOT_DEPLOYED"
