import shutil
from pathlib import Path

from report_sample import sample_report
from worker.report_exporter import ReportExporter


def test_html_export_uses_template_sections():
    root = Path("tests/.tmp_reports")
    shutil.rmtree(root, ignore_errors=True)
    try:
        path = ReportExporter(output_dir=root).export_html(sample_report())
        html = path.read_text(encoding="utf-8")

        assert path == root / "html" / "target_18.html"
        assert "Executive Summary" in html
        assert "Target Summary" in html
        assert "Open Ports" in html
        assert "Tool Results" in html
        assert "Decision Timeline" in html
        assert "Risk Summary" in html
        assert "MITRE Mapping" in html
        assert "Learning Summary" in html
        assert "Round Summary" in html
        assert "Recommendation" in html
        assert "badge" in html
        assert "<table" in html
    finally:
        shutil.rmtree(root, ignore_errors=True)
