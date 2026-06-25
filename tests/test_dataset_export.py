import sys
from pathlib import Path
from types import SimpleNamespace

from worker.dataset_export import export_dataset


def test_export_dataset_csv():
    path = Path("tests/.tmp_dataset.csv")
    try:
        exported = export_dataset(
            [{"target_id": 1, "round_value": 2, "feature_vector": {"a": 1}}],
            path,
            format="csv",
        )

        text = exported.read_text(encoding="utf-8")
        assert "target_id" in text
        assert "round_value" in text
    finally:
        path.unlink(missing_ok=True)


def test_export_dataset_json():
    path = Path("tests/.tmp_dataset.json")
    try:
        exported = export_dataset(
            [{"target_id": 1, "round_value": 2}],
            path,
            format="json",
        )

        assert '"target_id": 1' in exported.read_text(encoding="utf-8")
    finally:
        path.unlink(missing_ok=True)


def test_export_dataset_parquet_uses_optional_pandas(monkeypatch):
    calls = {}
    path = Path("tests/.tmp_dataset.parquet")

    class FakeDataFrame:
        def __init__(self, rows):
            calls["rows"] = rows

        def to_parquet(self, path, index=False):
            calls["path"] = path
            calls["index"] = index
            path.write_bytes(b"PARQUET")

    monkeypatch.setitem(sys.modules, "pandas", SimpleNamespace(DataFrame=FakeDataFrame))

    try:
        exported = export_dataset(
            [{"target_id": 1, "round_value": 2}],
            path,
            format="parquet",
        )

        assert exported.read_bytes() == b"PARQUET"
        assert calls["index"] is False
    finally:
        path.unlink(missing_ok=True)
