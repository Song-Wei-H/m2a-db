import re
from pathlib import Path


ALLOWED_DIRECT_CREATION = {
    Path("app/models.py"),
    Path("app/tool_task_writer.py"),
}


def test_production_tooltask_creation_is_centralized():
    offenders: list[str] = []

    for root in (Path("app"), Path("worker")):
        for path in root.rglob("*.py"):
            if path in ALLOWED_DIRECT_CREATION:
                continue
            source = path.read_text(encoding="utf-8")
            if re.search(r"\bToolTask\s*\(", source):
                offenders.append(path.as_posix())

    assert offenders == []
