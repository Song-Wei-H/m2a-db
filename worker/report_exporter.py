"""Report export helpers.

The exporter accepts the dictionary returned by generate_target_report(). It
does not query the database and does not recalculate risk, decisions, learning,
or governance state.
"""

from __future__ import annotations

import html
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal


REPORT_VERSION = "report-export-v1"
ExportFormat = Literal["json", "html", "pdf", "all"]


class ReportExporter:
    def __init__(
        self,
        *,
        output_dir: str | Path = "reports",
        template_path: str | Path = "templates/report.html",
    ):
        self.output_dir = Path(output_dir)
        self.template_path = Path(template_path)

    def export_json(self, report: dict[str, Any]) -> Path:
        path = self._path_for(report, "json")
        payload = self._with_metadata(report)
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def export_html(self, report: dict[str, Any]) -> Path:
        path = self._path_for(report, "html")
        payload = self._with_metadata(report)
        path.write_text(self._render_html(payload), encoding="utf-8")
        return path

    def export_pdf(self, report: dict[str, Any]) -> Path:
        path = self._path_for(report, "pdf")
        payload = self._with_metadata(report)
        self._write_pdf(payload, path)
        return path

    def export_all(self, report: dict[str, Any]) -> dict[str, Path]:
        return {
            "json": self.export_json(report),
            "html": self.export_html(report),
            "pdf": self.export_pdf(report),
        }

    def export(self, report: dict[str, Any], *, format: ExportFormat) -> Path | dict[str, Path]:
        if format == "json":
            return self.export_json(report)
        if format == "html":
            return self.export_html(report)
        if format == "pdf":
            return self.export_pdf(report)
        if format == "all":
            return self.export_all(report)
        raise ValueError(f"Unsupported report export format: {format}")

    def _path_for(self, report: dict[str, Any], extension: str) -> Path:
        target_id = _target_id(report)
        directory = self.output_dir / extension
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"target_{target_id}.{extension}"

    def _with_metadata(self, report: dict[str, Any]) -> dict[str, Any]:
        payload = deepcopy(report)
        payload["report_metadata"] = {
            "report_version": REPORT_VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
            "target_id": _target_id(report),
            "scan_run_id": _scan_run_id(report),
            "model_version": _first_present(report, "model_version"),
            "dataset_version": _version_from_report(report, "dataset_version"),
            "feature_version": _version_from_report(report, "feature_version"),
            "label_version": _version_from_report(report, "label_version"),
        }
        return payload

    def _render_html(self, report: dict[str, Any]) -> str:
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape

            env = Environment(
                loader=FileSystemLoader(str(self.template_path.parent)),
                autoescape=select_autoescape(["html", "xml"]),
            )
            template = env.get_template(self.template_path.name)
            return template.render(report=report)
        except Exception:
            return _render_html_fallback(report)

    def _write_pdf(self, report: dict[str, Any], path: Path) -> None:
        try:
            from reportlab.lib.pagesizes import LETTER
            from reportlab.pdfgen import canvas

            canvas_obj = canvas.Canvas(str(path), pagesize=LETTER)
            text = canvas_obj.beginText(72, 720)
            text.setFont("Helvetica", 11)
            for line in _pdf_lines(report):
                text.textLine(line[:100])
            canvas_obj.drawText(text)
            canvas_obj.save()
            return
        except Exception:
            path.write_bytes(_minimal_pdf(_pdf_lines(report)))


def _target_id(report: dict[str, Any]) -> Any:
    summary = report.get("target_summary") or report.get("target") or {}
    return summary.get("target_id") or report.get("target_id") or "unknown"


def _scan_run_id(report: dict[str, Any]) -> Any:
    summary = report.get("target_summary") or {}
    return summary.get("scan_run_id") or report.get("scan_run_id")


def _version_from_report(report: dict[str, Any], key: str) -> Any:
    for decision in report.get("decision_scores", []):
        snapshot = decision.get("input_snapshot") or {}
        if snapshot.get(key):
            return snapshot[key]
    for row in report.get("round_value_summary", []):
        if row.get(key):
            return row[key]
    return None


def _first_present(report: dict[str, Any], key: str) -> Any:
    if report.get(key):
        return report[key]
    metadata = report.get("model_metadata") or {}
    return metadata.get(key)


def _render_html_fallback(report: dict[str, Any]) -> str:
    summary = report.get("target_summary") or {}
    decision_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(decision.get('severity')))}</td>"
        f"<td>{html.escape(str(decision.get('risk_score')))}</td>"
        f"<td>{html.escape(str(decision.get('next_action')))}</td>"
        f"<td>{html.escape(str(decision.get('reason')))}</td>"
        "</tr>"
        for decision in report.get("decision_scores", [])
    )
    port_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(port.get('ip')))}</td>"
        f"<td>{html.escape(str(port.get('port')))}</td>"
        f"<td>{html.escape(str(port.get('protocol')))}</td>"
        f"<td>{html.escape(str(port.get('service')))}</td>"
        "</tr>"
        for port in report.get("open_ports", [])
    )
    tool_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(result.get('tool_name')))}</td>"
        f"<td>{html.escape(str(result.get('success')))}</td>"
        f"<td>{html.escape(str(result.get('evidence_type')))}</td>"
        f"<td>{html.escape(str(result.get('risk_level')))}</td>"
        "</tr>"
        for result in report.get("tool_results", [])
    )
    mitre_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(mapping.get('mitre_phase')))}</td>"
        f"<td>{html.escape(str(mapping.get('mitre_technique')))}</td>"
        f"<td>{html.escape(str(mapping.get('count')))}</td>"
        "</tr>"
        for mapping in report.get("mitre_mapping", [])
    )
    learning_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('tool_name')))}</td>"
        f"<td>{html.escape(str(item.get('service')))}</td>"
        f"<td>{html.escape(str(item.get('success_rate')))}</td>"
        f"<td>{html.escape(str(item.get('avg_learning_score')))}</td>"
        "</tr>"
        for item in report.get("learning_summary", [])
    )
    round_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('round')))}</td>"
        f"<td>{html.escape(str(item.get('tool_name')))}</td>"
        f"<td>{html.escape(str(item.get('round_value')))}</td>"
        "</tr>"
        for item in report.get("round_value_summary", [])
    )
    recommendation_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('severity')))}</td>"
        f"<td>{html.escape(str(item.get('recommendation')))}</td>"
        "</tr>"
        for item in report.get("remediation", [])
    )
    return f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>M2A Report</title><style>.badge{{border-radius:999px;padding:3px 8px;background:#475569;color:white}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #ddd;padding:6px}}</style></head>
<body>
<h1>M2A Security Assessment Report</h1>
<h2>Executive Summary</h2>
<p>Target {html.escape(str(summary.get('target')))} status: {html.escape(str(summary.get('status')))}</p>
<h2>Target Summary</h2>
<table><tr><th>Target ID</th><td>{html.escape(str(summary.get('target_id')))}</td></tr><tr><th>Scope</th><td>{html.escape(str(summary.get('scope')))}</td></tr></table>
<h2>Open Ports</h2>
<table><thead><tr><th>IP</th><th>Port</th><th>Protocol</th><th>Service</th></tr></thead><tbody>{port_rows}</tbody></table>
<h2>Tool Results</h2>
<table><thead><tr><th>Tool</th><th>Success</th><th>Evidence</th><th>Risk</th></tr></thead><tbody>{tool_rows}</tbody></table>
<h2>Decision Timeline</h2>
<table><thead><tr><th>Severity</th><th>Risk</th><th>Action</th><th>Reason</th></tr></thead><tbody>{decision_rows}</tbody></table>
<h2>Risk Summary</h2>
<p><span class="badge">{html.escape(str((report.get('risk_ranking') or {}).get('highest_severity')))}</span> {(report.get('risk_ranking') or {}).get('highest_risk_score')}</p>
<h2>MITRE Mapping</h2>
<table><thead><tr><th>Phase</th><th>Technique</th><th>Count</th></tr></thead><tbody>{mitre_rows}</tbody></table>
<h2>Learning Summary</h2>
<table><thead><tr><th>Tool</th><th>Service</th><th>Success Rate</th><th>Average Score</th></tr></thead><tbody>{learning_rows}</tbody></table>
<h2>Round Summary</h2>
<table><thead><tr><th>Round</th><th>Tool</th><th>Value</th></tr></thead><tbody>{round_rows}</tbody></table>
<h2>Recommendation</h2>
<table><thead><tr><th>Severity</th><th>Recommendation</th></tr></thead><tbody>{recommendation_rows}</tbody></table>
</body>
</html>"""


def _pdf_lines(report: dict[str, Any]) -> list[str]:
    summary = report.get("target_summary") or {}
    risk = report.get("risk_ranking") or {}
    lines = [
        "M2A Security Assessment Report",
        "",
        "Cover",
        f"Target: {summary.get('target')}",
        f"Status: {summary.get('status')}",
        "",
        "Executive Summary",
        f"Highest Severity: {risk.get('highest_severity')}",
        f"Highest Risk Score: {risk.get('highest_risk_score')}",
        "",
        "Findings",
    ]
    for decision in report.get("decision_scores", [])[:20]:
        lines.append(
            f"- {decision.get('severity')} risk={decision.get('risk_score')} action={decision.get('next_action')}"
        )
    lines.extend(["", "MITRE", "Recommendation"])
    for item in report.get("remediation", [])[:20]:
        lines.append(f"- {item.get('severity')}: {item.get('recommendation')}")
    return [str(line) for line in lines]


def _minimal_pdf(lines: list[str]) -> bytes:
    text = "\\n".join(lines)
    stream = "BT /F1 12 Tf 72 720 Td " + _pdf_text(text[:3000]) + " Tj ET"
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        f"5 0 obj << /Length {len(stream.encode('latin-1', errors='ignore'))} >> stream\n{stream}\nendstream endobj",
    ]
    body = "%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(body.encode("latin-1")))
        body += obj + "\n"
    xref_pos = len(body.encode("latin-1"))
    body += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    body += "".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:])
    body += f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    return body.encode("latin-1", errors="ignore")


def _pdf_text(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("\n", "\\n")
    return f"({escaped})"
