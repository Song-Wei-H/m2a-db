import json
import shutil
from pathlib import Path

from report_sample import sample_report
from worker.report_exporter import REPORT_VERSION, ReportExporter


def test_json_export_preserves_report_and_adds_metadata():
    root = Path("tests/.tmp_reports")
    shutil.rmtree(root, ignore_errors=True)
    try:
        path = ReportExporter(output_dir=root).export_json(sample_report())
        payload = json.loads(path.read_text(encoding="utf-8"))

        assert path == root / "json" / "target_18.json"
        assert payload["target_summary"]["target_id"] == 18
        assert payload["tool_results"][0]["parsed_output"] == {"status_code": 200}
        assert payload["report_metadata"]["report_version"] == REPORT_VERSION
        assert payload["report_metadata"]["dataset_version"] == "round-dataset-v1"
        assert payload["report_metadata"]["feature_version"] == "round-feature-v1"
        assert payload["report_metadata"]["label_version"] == "round-label-v1"
    finally:
        shutil.rmtree(root, ignore_errors=True)
