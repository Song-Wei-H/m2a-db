import json
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from report_sample import sample_report
from worker.report_lifecycle import ReportLifecycleManager


@pytest.mark.asyncio
async def test_report_lifecycle_exports_completed_target():
    root = Path("tests/.tmp_lifecycle_reports")
    shutil.rmtree(root, ignore_errors=True)
    try:
        with patch("worker.report_lifecycle.generate_target_report", new_callable=AsyncMock) as mock_report:
            mock_report.return_value = sample_report()
            result = await ReportLifecycleManager(output_dir=root).on_target_completed(18)

        assert result["exported"] is True
        assert (root / "json" / "target_18.json").exists()
        assert (root / "html" / "target_18.html").exists()
        assert (root / "pdf" / "target_18.pdf").exists()
        metadata = json.loads((root / "latest" / "export_metadata.json").read_text(encoding="utf-8"))
        assert metadata["18"]["export_status"] == "exported"
        assert metadata["18"]["report_generator_version"] == "target-report-v1"
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.asyncio
async def test_report_lifecycle_export_failure_is_non_blocking():
    class FailingExporter:
        def export_all(self, report):
            raise RuntimeError("disk full")

    with patch("worker.report_lifecycle.generate_target_report", new_callable=AsyncMock) as mock_report:
        mock_report.return_value = sample_report()
        result = await ReportLifecycleManager(exporter=FailingExporter()).on_target_completed(18)

    assert result["exported"] is False
    assert result["error"] == "disk full"
