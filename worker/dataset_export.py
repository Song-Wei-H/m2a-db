"""Dataset export utilities.

Exports read an already-built dataset only. They never train models or mutate
runtime orchestration state.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Literal


ExportFormat = Literal["csv", "json", "parquet"]


def export_dataset(
    dataset: list[dict[str, Any]],
    destination: str | Path,
    *,
    format: ExportFormat,
) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)

    if format == "csv":
        _export_csv(dataset, path)
    elif format == "json":
        _export_json(dataset, path)
    elif format == "parquet":
        _export_parquet(dataset, path)
    else:
        raise ValueError(f"Unsupported dataset export format: {format}")
    return path


def _export_csv(dataset: list[dict[str, Any]], path: Path) -> None:
    columns = _columns(dataset)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in dataset:
            writer.writerow({column: _cell(row.get(column)) for column in columns})


def _export_json(dataset: list[dict[str, Any]], path: Path) -> None:
    path.write_text(json.dumps(dataset, indent=2, default=str), encoding="utf-8")


def _export_parquet(dataset: list[dict[str, Any]], path: Path) -> None:
    try:
        import pandas as pd  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on optional install
        raise RuntimeError("Parquet export requires pandas with a parquet engine") from exc

    pd.DataFrame(dataset).to_parquet(path, index=False)


def _columns(dataset: list[dict[str, Any]]) -> list[str]:
    columns: list[str] = []
    for row in dataset:
        for key in row:
            if key not in columns:
                columns.append(key)
    return columns


def _cell(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str, sort_keys=True)
    return value
