"""Automatic report lifecycle hooks.

This module is a side-effect boundary for report generation/export. It never
performs decisions, risk scoring, learning, ranking, governance, or ToolTask
creation.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from worker.report_exporter import REPORT_GENERATOR_VERSION, REPORT_VERSION, ReportExporter
from worker.report_generator import generate_target_report


logger = logging.getLogger(__name__)


class ReportLifecycleManager:
    def __init__(
        self,
        *,
        exporter: ReportExporter | None = None,
        output_dir: str | Path = "reports",
    ):
        self.exporter = exporter or ReportExporter(output_dir=output_dir)
        self.output_dir = Path(output_dir)
        self.registry_path = self.output_dir / "latest" / "export_metadata.json"

    async def on_target_completed(self, target_id: int) -> dict[str, Any]:
        try:
            logger.info("Assessment completed. target_id=%s", target_id)
            logger.info("Generating report... target_id=%s", target_id)
            report = await generate_target_report(target_id)
            report_hash = _report_hash(report)

            registry = self._load_registry()
            previous = registry.get(str(target_id))
            if (
                previous
                and previous.get("report_hash") == report_hash
                and previous.get("report_version") == REPORT_VERSION
                and previous.get("export_status") == "exported"
            ):
                logger.info("Report export skipped; unchanged report already exported. target_id=%s", target_id)
                return {
                    "exported": False,
                    "skipped": True,
                    "reason": "duplicate_report",
                    "metadata": previous,
                }

            paths = self.exporter.export_all(report)
            metadata = {
                "target_id": target_id,
                "report_hash": report_hash,
                "report_version": REPORT_VERSION,
                "report_generator_version": REPORT_GENERATOR_VERSION,
                "exported_at": datetime.now(UTC).isoformat(),
                "export_status": "exported",
                "export_formats": sorted(paths),
                "files": {key: str(path) for key, path in paths.items()},
            }
            registry[str(target_id)] = metadata
            self._save_registry(registry)

            logger.info("Report exported. target_id=%s", target_id)
            logger.info("JSON: %s", paths.get("json"))
            logger.info("HTML: %s", paths.get("html"))
            logger.info("PDF: %s", paths.get("pdf"))
            return {
                "exported": True,
                "skipped": False,
                "metadata": metadata,
            }
        except Exception as exc:
            logger.warning(
                "Report export failed. Execution already completed. No retry required. target_id=%s error=%s",
                target_id,
                exc,
            )
            return {
                "exported": False,
                "skipped": False,
                "error": str(exc),
            }

    def _load_registry(self) -> dict[str, Any]:
        if not self.registry_path.exists():
            return {}
        try:
            return json.loads(self.registry_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _save_registry(self, registry: dict[str, Any]) -> None:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")


def _report_hash(report: dict[str, Any]) -> str:
    payload = json.dumps(report, default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
