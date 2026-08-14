"""Report export helpers.

The exporter accepts the dictionary returned by generate_target_report(). It
does not query the database and does not recalculate risk, decisions, learning,
or governance state.
"""

from __future__ import annotations

import html
import json
import shutil
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal


REPORT_VERSION = "report-export-v2-zh-tw"
REPORT_GENERATOR_VERSION = "target-report-v1"
ExportFormat = Literal["json", "html", "pdf", "all"]
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ReportExporter:
    def __init__(
        self,
        *,
        output_dir: str | Path | None = None,
        template_path: str | Path | None = None,
    ):
        self.output_dir = PROJECT_ROOT / "reports" if output_dir is None else Path(output_dir)
        self.template_path = PROJECT_ROOT / "templates" / "report.html" if template_path is None else Path(template_path)

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
        paths = {
            "json": self.export_json(report),
            "html": self.export_html(report),
            "pdf": self.export_pdf(report),
        }
        self.update_latest(paths)
        return paths

    def update_latest(self, paths: dict[str, Path]) -> dict[str, Path]:
        latest_dir = self.output_dir / "latest"
        latest_dir.mkdir(parents=True, exist_ok=True)
        latest_paths: dict[str, Path] = {}
        for extension, path in paths.items():
            latest_path = latest_dir / f"latest.{extension}"
            shutil.copyfile(path, latest_path)
            latest_paths[extension] = latest_path
        return latest_paths

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
            "exported_at": datetime.now(UTC).isoformat(),
            "export_status": "exported",
            "export_formats": ["json", "html", "pdf"],
            "report_generator_version": REPORT_GENERATOR_VERSION,
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
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.cidfonts import UnicodeCIDFont
            from reportlab.graphics.charts.barcharts import VerticalBarChart
            from reportlab.graphics.shapes import Drawing, String
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

            styles = getSampleStyleSheet()
            pdfmetrics.registerFont(UnicodeCIDFont("MSung-Light"))
            for style in styles.byName.values():
                style.fontName = "MSung-Light"
            styles["BodyText"].leading = 14
            document = SimpleDocTemplate(
                str(path),
                pagesize=A4,
                rightMargin=0.55 * inch,
                leftMargin=0.55 * inch,
                topMargin=0.55 * inch,
                bottomMargin=0.55 * inch,
            )
            story = [Paragraph("M2A 資安評估報告", styles["Title"]), Spacer(1, 12)]
            summary = report.get("target_summary") or {}
            risk = report.get("risk_ranking") or {}
            _append_pdf_section(
                story,
                "執行摘要",
                [
                    ["目標", summary.get("target")],
                    ["狀態", summary.get("status")],
                    ["範圍", summary.get("scope")],
                    ["最高嚴重度", risk.get("highest_severity")],
                    ["最高風險分數", risk.get("highest_risk_score")],
                ],
                styles,
            )
            quantitative_metrics = report.get("quantitative_metrics") or {}
            _append_pdf_metrics_chart(story, quantitative_metrics, styles, VerticalBarChart, Drawing, String)
            severity_distribution = quantitative_metrics.get("severity_distribution") or []
            tool_outcomes = quantitative_metrics.get("tool_outcomes") or {}
            llm_metrics = quantitative_metrics.get("llm_advisory") or {}
            _append_pdf_table(
                story,
                "量化指標總覽",
                ["指標", "數值"],
                [
                    ["決策總數", sum(item.get("count", 0) for item in severity_distribution)],
                    ["工具執行總數", tool_outcomes.get("total", 0)],
                    ["工具成功數", tool_outcomes.get("successful", 0)],
                    ["工具失敗數", tool_outcomes.get("failed", 0)],
                    ["工具成功率", f'{tool_outcomes.get("success_rate", 0)}%'],
                    ["LLM 建議總數", llm_metrics.get("total", 0)],
                    ["LLM 動作一致數", llm_metrics.get("action_matches", 0)],
                    ["LLM 動作一致率", f'{llm_metrics.get("action_match_rate", 0)}%'],
                    ["未核准 LLM 建議", llm_metrics.get("unapproved", 0)],
                ],
                styles,
            )
            _append_pdf_table(
                story,
                "Heretic 顧問建議比較",
                ["決策 ID", "建議動作", "建議工具", "信心", "驗證狀態", "動作一致", "已核准", "理由"],
                [
                    [
                        row.get("decision_score_id"),
                        row.get("recommended_action"),
                        row.get("recommended_tool"),
                        row.get("confidence"),
                        row.get("validator_status"),
                        row.get("matches_deterministic_action"),
                        row.get("approved"),
                        row.get("reasoning"),
                    ]
                    for row in report.get("llm_advisory_recommendations", [])
                ],
                styles,
            )
            _append_pdf_table(
                story,
                "開放連接埠",
                ["IP", "連接埠", "協定", "服務", "產品"],
                [[row.get("ip"), row.get("port"), row.get("protocol"), row.get("service"), row.get("product")] for row in report.get("open_ports", [])],
                styles,
            )
            _append_pdf_table(
                story,
                "工具執行結果",
                ["工具", "成功", "證據", "風險", "服務"],
                [[row.get("tool_name"), row.get("success"), row.get("evidence_type"), row.get("risk_level"), row.get("service")] for row in report.get("tool_results", [])],
                styles,
            )
            _append_pdf_table(
                story,
                "決策時間線",
                ["嚴重度", "風險", "動作", "下一工具", "理由"],
                [[row.get("severity"), row.get("risk_score"), row.get("next_action"), row.get("next_tool"), row.get("reason")] for row in report.get("decision_scores", [])],
                styles,
            )
            _append_pdf_table(
                story,
                "CVE 候選篩選摘要",
                ["完整候選", "強制保留", "報告顯示", "摘要收斂", "KEV", "精確版本"],
                [[
                    report.get("cve_candidate_summary", {}).get("total_candidates", 0),
                    report.get("cve_candidate_summary", {}).get("mandatory_candidates", 0),
                    report.get("cve_candidate_summary", {}).get("selected_candidates", 0),
                    report.get("cve_candidate_summary", {}).get("summarized_candidates", 0),
                    report.get("cve_candidate_summary", {}).get("kev_candidates", 0),
                    report.get("cve_candidate_summary", {}).get("exact_version_candidates", 0),
                ]],
                styles,
            )
            _append_pdf_table(
                story,
                "CVE 候選項目 - 需要版本驗證",
                ["CVE", "CVSS", "證據層級", "候選狀態", "信心", "官方引用"],
                [
                    [
                        row.get("cve_id") or row.get("cve"),
                        row.get("cvss_score") if row.get("cvss_score") is not None else row.get("cvss"),
                        row.get("evidence_level"),
                        row.get("finding_status"),
                        row.get("match_confidence"),
                        "\n".join(str(ref.get("url")) for ref in row.get("evidence_references", []) if ref.get("url")),
                    ]
                    for row in report.get("matched_cves", [])
                ],
                styles,
            )
            _append_pdf_table(
                story,
                "MITRE 映射",
                ["階段", "技術", "數量"],
                [[row.get("mitre_phase"), row.get("mitre_technique"), row.get("count")] for row in report.get("mitre_mapping", [])],
                styles,
            )
            _append_pdf_table(
                story,
                "建議措施",
                ["嚴重度", "建議"],
                [[row.get("severity"), row.get("recommendation")] for row in report.get("remediation", [])],
                styles,
            )
            document.build(story)
            return
        except Exception:
            path.write_bytes(_minimal_pdf(_pdf_lines(report)))


def _pdf_value(value: Any) -> str:
    return html.escape("-" if value is None or value == "" else str(value))


def _append_pdf_section(story: list[Any], title: str, rows: list[list[Any]], styles: Any) -> None:
    _append_pdf_table(story, title, ["欄位", "值"], rows, styles)


def _append_pdf_table(
    story: list[Any], title: str, headers: list[str], rows: list[list[Any]], styles: Any
) -> None:
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    story.extend([Paragraph(title, styles["Heading2"]), Spacer(1, 4)])
    safe_rows = rows or [["尚無資料"] + [""] * (len(headers) - 1)]
    data = [
        [Paragraph(_pdf_value(cell), styles["BodyText"]) for cell in headers],
        *[
            [Paragraph(_pdf_value(cell), styles["BodyText"]) for cell in row]
            for row in safe_rows
        ],
    ]
    table = Table(data, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.extend([table, Spacer(1, 12)])


def _append_pdf_metrics_chart(story: list[Any], metrics: dict[str, Any], styles: Any, chart_type: Any, drawing_type: Any, string_type: Any) -> None:
    from reportlab.lib import colors
    from reportlab.platypus import Spacer

    distribution = metrics.get("severity_distribution") or [
        {"label": label, "count": 0}
        for label in ("重大", "高", "中", "低", "資訊")
    ]
    drawing = drawing_type(470, 220)
    chart = chart_type()
    chart.x = 46
    chart.y = 38
    chart.width = 375
    chart.height = 140
    chart.data = [[item.get("count", 0) for item in distribution]]
    chart.categoryAxis.categoryNames = [item.get("label", "") for item in distribution]
    chart.categoryAxis.labels.fontName = "MSung-Light"
    chart.categoryAxis.labels.fontSize = 8
    chart.valueAxis.labels.fontName = "MSung-Light"
    chart.valueAxis.labels.fontSize = 8
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueStep = 1
    chart.bars[0].fillColor = colors.HexColor("#2563EB")
    drawing.add(string_type(46, 194, "風險嚴重度分布（決策筆數）", fontName="MSung-Light", fontSize=12))
    drawing.add(chart)
    story.extend([drawing, Spacer(1, 12)])


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
