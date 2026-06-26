import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from report_sample import sample_report
from worker.report_exporter import ReportExporter


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


def test_latest_report_api_returns_html():
    shutil.rmtree("reports", ignore_errors=True)
    try:
        ReportExporter().export_all(sample_report())
        response = TestClient(app).get("/targets/18/report/latest")

        assert response.status_code == 200
        assert "M2A Security Assessment Report" in response.text
    finally:
        shutil.rmtree("reports", ignore_errors=True)
