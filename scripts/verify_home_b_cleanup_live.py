"""Verify one sealed home B run before resetting only its synthetic loopback lab.

The report is derived evidence outside the immutable suite. No reset key is saved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen


TARGET = "http://127.0.0.1:18080"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def request(path: str, *, body: dict | None = None, headers: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = Request(TARGET + path, data=data, headers=headers or {},
                  method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urlopen(req, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError(f"unexpected target HTTP status: {response.status}")
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", type=Path)
    parser.add_argument("secret_config", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("cleanup report exists; refusing a second reset")
    suite = args.suite.resolve()
    manifest_path = suite / "sha256-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("formal_sample") is not False or manifest.get("run_id") != suite.name:
        raise ValueError("expected one sealed, non-formal suite")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("source manifest is incomplete")
    for relative, expected in files.items():
        path = (suite / relative).resolve()
        if suite not in path.parents or not path.is_file() or sha(path) != expected:
            raise ValueError(f"source evidence mismatch: {relative}")
    arms = list(suite.glob("B-*/arm-result.json"))
    if len(arms) != 1:
        raise ValueError("expected exactly one B arm")
    arm = json.loads(arms[0].read_text(encoding="utf-8"))
    run_id = arm.get("run_id")
    if (arm.get("suite_run_id") != suite.name or arm.get("formal_sample") is not False
            or arm.get("max_executed_depth") != 1 or not isinstance(run_id, str)):
        raise ValueError("B arm identity/depth mismatch")
    before = request("/lab/healthz")
    if before != {"status": "ok", "scenario": "gade-l2-t1078"}:
        raise ValueError("unexpected target identity; no reset attempted")
    values = [line.split("=", 1)[1].strip().strip("\"'")
              for line in args.secret_config.read_text(encoding="utf-8").splitlines()
              if line.startswith("GADE_L2_RESET_KEY=")]
    if len(values) != 1 or len(values[0]) < 24:
        raise ValueError("one valid local reset key is required")
    case_id = f"GADE-B-{run_id}-POSTRUN-CLEANUP"
    reset = request("/lab/admin/reset",
                    headers={"X-Request-ID": f"{run_id}-postrun-cleanup",
                             "X-Test-Case-ID": case_id},
                    body={"reset_key": values[0], "test_case_id": case_id})
    after = request("/lab/healthz")
    ok = (reset.get("status") == "reset" and reset.get("active_sessions") == 0
          and reset.get("l3_marker_cleared") is True
          and reset.get("l3_temp_files_cleared") is True
          and reset.get("test_case_id") == case_id and after == before)
    report = {"status": "VERIFIED" if ok else "PARTIAL", "suite_id": suite.name,
              "run_id": run_id, "target": TARGET,
              "source_manifest_sha256": sha(manifest_path), "before_health": before,
              "reset_response": reset, "after_health": after,
              "note": "Reset reports zero sessions; no independent session-token test was performed."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(f"POST_RUN_CLEANUP={report['status']} sha256={sha(args.output)}")
    if not ok:
        raise RuntimeError("cleanup response/target health was partial")


if __name__ == "__main__":
    main()
