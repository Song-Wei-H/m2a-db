import shutil
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from scripts import export_report
from report_sample import sample_report
from worker.report_exporter import ReportExporter


def test_export_all_creates_report_directories():
    root = Path("tests/.tmp_reports")
    shutil.rmtree(root, ignore_errors=True)
    try:
        result = ReportExporter(output_dir=root).export_all(sample_report())

        assert set(result) == {"json", "html", "pdf"}
        assert (root / "json").is_dir()
        assert (root / "html").is_dir()
        assert (root / "pdf").is_dir()
        assert result["json"].exists()
        assert result["html"].exists()
        assert result["pdf"].exists()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_export_rejects_unsupported_format():
    try:
        ReportExporter(output_dir="tests/.tmp_reports").export(sample_report(), format="xml")
    except ValueError as exc:
        assert "Unsupported report export format" in str(exc)
    else:
        raise AssertionError("Expected unsupported export format to raise")


@pytest.mark.asyncio
async def test_export_report_cli_calls_report_exporter(monkeypatch):
    root = Path("tests/.tmp_reports")
    shutil.rmtree(root, ignore_errors=True)
    try:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "export_report.py",
                "--target",
                "18",
                "--format",
                "html",
                "--output-dir",
                str(root),
            ],
        )
        with patch("scripts.export_report.generate_target_report", new_callable=AsyncMock) as mock_report:
            mock_report.return_value = sample_report()
            result = await export_report.main()

        assert Path(result["html"]).exists()
        mock_report.assert_awaited_once_with(18)
    finally:
        shutil.rmtree(root, ignore_errors=True)
