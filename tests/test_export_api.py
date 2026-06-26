import shutil
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app
from report_sample import sample_report


def test_report_export_api_returns_file_paths():
    shutil.rmtree("reports", ignore_errors=True)
    try:
        client = TestClient(app)
        with patch("app.api.targets.generate_target_report", new_callable=AsyncMock) as mock_report:
            mock_report.return_value = sample_report()
            response = client.get("/targets/18/report/export?format=json")

        assert response.status_code == 200
        body = response.json()
        assert body["target_id"] == 18
        assert body["format"] == "json"
        assert Path(body["files"]["json"]).exists()
    finally:
        shutil.rmtree("reports", ignore_errors=True)


def test_report_export_api_rejects_invalid_format():
    client = TestClient(app)
    response = client.get("/targets/18/report/export?format=xml")

    assert response.status_code == 400
