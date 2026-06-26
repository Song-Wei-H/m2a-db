"""Export a generated target report to JSON, HTML, PDF, or all formats."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

from worker.report_exporter import ReportExporter
from worker.report_generator import generate_target_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export M2A target report")
    parser.add_argument("--target", type=int, required=True, help="Target ID")
    parser.add_argument(
        "--format",
        choices=["json", "html", "pdf", "all"],
        default="all",
        help="Export format",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Report output directory",
    )
    return parser.parse_args()


async def main() -> dict[str, Any]:
    args = parse_args()
    report = await generate_target_report(args.target)
    if report.get("error") == "Target not found":
        raise SystemExit(f"Target not found: {args.target}")

    exporter = ReportExporter(output_dir=args.output_dir)
    result = exporter.export(report, format=args.format)
    if isinstance(result, dict):
        output = {key: str(path) for key, path in result.items()}
    else:
        output = {args.format: str(Path(result))}
    print(output)
    return output


if __name__ == "__main__":
    asyncio.run(main())
