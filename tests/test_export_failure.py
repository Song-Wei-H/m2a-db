from unittest.mock import AsyncMock, patch

import pytest

from report_sample import sample_report
from worker.report_lifecycle import ReportLifecycleManager


@pytest.mark.asyncio
async def test_report_export_failure_does_not_raise_to_execution():
    class FailingExporter:
        def export_all(self, report):
            raise RuntimeError("permission denied")

    with patch("worker.report_lifecycle.generate_target_report", new_callable=AsyncMock) as mock_report:
        mock_report.return_value = sample_report()
        result = await ReportLifecycleManager(exporter=FailingExporter()).on_target_completed(18)

    assert result == {
        "exported": False,
        "skipped": False,
        "error": "permission denied",
    }
