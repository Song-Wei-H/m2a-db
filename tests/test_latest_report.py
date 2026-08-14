import shutil
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from report_sample import sample_report
from worker.report_exporter import ReportExporter


def _api_exporter(tmp_path):
    return lambda: ReportExporter(output_dir=tmp_path)


def test_export_all_updates_latest_reports():
    root = Path("tests/.tmp_reports")
    shutil.rmtree(root, ignore_errors=True)
    try:
        ReportExporter(output_dir=root).export_all(sample_report())

        assert (root / "latest" / "latest.json").exists()
        assert (root / "latest" / "latest.html").exists()
        assert (root / "latest" / "latest.pdf").exists()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_latest_report_api_returns_html(tmp_path):
    with patch("app.api.targets.ReportExporter", side_effect=_api_exporter(tmp_path)):
        ReportExporter(output_dir=tmp_path).export_all(sample_report())
        response = TestClient(app).get("/targets/18/report/latest")

        assert response.status_code == 200
        assert "M2A Security Assessment Report" in response.text


def test_latest_report_does_not_leak_another_targets_global_latest(tmp_path):
    with patch("app.api.targets.ReportExporter", side_effect=_api_exporter(tmp_path)):
        ReportExporter(output_dir=tmp_path).export_all(sample_report())
        response = TestClient(app).get("/targets/999/report/latest")

        assert response.status_code == 404
