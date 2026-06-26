import shutil
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from report_sample import sample_report
from worker.report_lifecycle import ReportLifecycleManager


@pytest.mark.asyncio
async def test_duplicate_export_uses_report_hash_not_file_existence():
    root = Path("tests/.tmp_lifecycle_reports")
    shutil.rmtree(root, ignore_errors=True)
    try:
        manager = ReportLifecycleManager(output_dir=root)
        with patch("worker.report_lifecycle.generate_target_report", new_callable=AsyncMock) as mock_report:
            mock_report.return_value = sample_report()
            first = await manager.on_target_completed(18)
            (root / "json" / "target_18.json").unlink()
            second = await manager.on_target_completed(18)

        assert first["exported"] is True
        assert second["exported"] is False
        assert second["skipped"] is True
        assert second["reason"] == "duplicate_report"
        assert not (root / "json" / "target_18.json").exists()
    finally:
        shutil.rmtree(root, ignore_errors=True)
