import shutil
from pathlib import Path

from report_sample import sample_report
from worker.report_exporter import ReportExporter


def test_pdf_export_creates_pdf_file():
    root = Path("tests/.tmp_reports")
    shutil.rmtree(root, ignore_errors=True)
    try:
        path = ReportExporter(output_dir=root).export_pdf(sample_report())
        data = path.read_bytes()

        assert path == root / "pdf" / "target_18.pdf"
        assert data.startswith(b"%PDF")
        assert b"M2A" in data
    finally:
        shutil.rmtree(root, ignore_errors=True)
