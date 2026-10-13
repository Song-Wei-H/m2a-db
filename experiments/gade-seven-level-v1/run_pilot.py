"""Deterministic governance pilot. No database, network, or Worker execution."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.action_contracts import ACTION_REQUIRED_ATTACK_DEPTH
from app.attack_authorization import POLICY_VERSION, depth_decision
from app.vulnerability_queue import TEST_FIXTURE_DEPTHS, evaluate_candidate


OUT = Path(__file__).resolve().parent
DATASET = [
    {"level": level, "action": f"fixture.depth.{level}",
     "evidence_ref": f"fixture:evidence:depth:{level}"}
    for level in range(1, 8)
]


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def candidate(item: dict) -> SimpleNamespace:
    return SimpleNamespace(required_action=item["action"], required_attack_depth=item["level"],
                           evidence_refs=[item["evidence_ref"]])


def decision(item: dict, engagement_depth: int, evidence: list[str] | None = None) -> dict:
    refs = [item["evidence_ref"]] if evidence is None else evidence
    return evaluate_candidate(candidate(item), engagement_depth=engagement_depth, evidence_refs=refs)


def main() -> None:
    assert set(ACTION_REQUIRED_ATTACK_DEPTH.values()) == {1}, "Production depth inventory changed"
    assert TEST_FIXTURE_DEPTHS == {f"fixture.depth.{i}": i for i in range(1, 8)}
    matrix = []
    for engagement in range(1, 8):
        for item in DATASET:
            required = item["level"]
            expected = "AUTHORIZED" if required <= engagement else "DENIED_BY_DEPTH"
            actual = decision(item, engagement)
            ceiling = depth_decision(engagement, required)
            passed = (actual["status"] == expected and ceiling["passed"] == (required <= engagement)
                      and actual["reason_code"] == ("ELIGIBLE" if required <= engagement else "ATTACK_DEPTH_EXCEEDED"))
            matrix.append({"scenario_id": f"M-{engagement}-{required}", "engagement_depth": engagement,
                           "required_depth": required, "action": item["action"],
                           "expected_decision": expected, "actual_decision": actual["status"],
                           "decision_reason": actual["reason_code"], "pass": passed,
                           "evidence_reference": item["evidence_ref"],
                           "trace_id": None, "trace_scope": "in-memory fixture; no durable Execution Trace"})
    pilot = []
    for group, engagement in (("A", 7), ("B", 1)):
        for item in DATASET:
            actual = decision(item, engagement)
            expected = "AUTHORIZED" if group == "A" or item["level"] == 1 else "DENIED_BY_DEPTH"
            pilot.append({"scenario_id": f"{group}-{item['level']}", "group": group,
                          "engagement_depth": engagement, "required_depth": item["level"],
                          "action": item["action"], "evidence_reference": item["evidence_ref"],
                          "expected_decision": expected, "actual_decision": actual["status"],
                          "decision_reason": actual["reason_code"], "pass": actual["status"] == expected,
                          "execution_authorization_created": False, "worker_request_sent": False,
                          "trace_id": None, "worker_receipt": None,
                          "result_scope": "queue eligibility fixture only"})
    negative = []
    cases = [
        ("missing-evidence", decision(DATASET[0], 7, []), "EVIDENCE_INSUFFICIENT"),
        ("unrelated-evidence", decision(DATASET[0], 7, ["fixture:unrelated"]), "EVIDENCE_INSUFFICIENT"),
        ("unregistered-action", evaluate_candidate(SimpleNamespace(required_action="fixture.unregistered",
          required_attack_depth=1, evidence_refs=["e"]), engagement_depth=7, evidence_refs=["e"]), "UNSUPPORTED_ACTION"),
        ("required-depth-mismatch", evaluate_candidate(SimpleNamespace(required_action="fixture.depth.2",
          required_attack_depth=1, evidence_refs=["e"]), engagement_depth=7, evidence_refs=["e"]), "DENIED_BY_POLICY"),
    ]
    for name, actual, expected in cases:
        negative.append({"scenario_id": name, "expected_decision": expected,
                         "actual_decision": actual["status"], "decision_reason": actual["reason_code"],
                         "pass": actual["status"] == expected, "trace_id": None})
    from subprocess import check_output
    tag_sha = check_output(["git", "rev-list", "-n", "1", "gade-preexp-v1"], cwd=ROOT, text=True).strip()
    head_sha = check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    raw_results = {"dataset.json": DATASET, "matrix-49.json": matrix,
                   "pilot-ab.json": pilot, "negative-fixtures.json": negative}
    manifest = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "baseline_tag": "gade-preexp-v1", "baseline_commit_sha": tag_sha,
                "source_head_sha": head_sha, "experiment_commit_sha": None,
                "source_state": "uncommitted experiment runner; runner_sha256 is the exact code identity",
                "policy_version": POLICY_VERSION,
                "action_contract_sha256": hashlib.sha256((ROOT / "app/action_contracts.py").read_bytes()).hexdigest(),
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "dataset_sha256": digest(DATASET),
                "raw_result_sha256": {name: digest(data) for name, data in raw_results.items()},
                "oracle": "queue AUTHORIZED iff registered fixture action, matching required depth, own evidence and required_depth <= engagement_depth",
                "evidence_scope": "Deterministic queue eligibility only; no PostgreSQL, durable grant, ToolTask, Kali Worker, or receipt",
                "matrix_pass": sum(x["pass"] for x in matrix), "matrix_total": len(matrix),
                "pilot_pass": sum(x["pass"] for x in pilot), "pilot_total": len(pilot),
                "negative_pass": sum(x["pass"] for x in negative), "negative_total": len(negative),
                "unauthorized_execution_count": "NOT_MEASURED_NO_EXECUTION",
                "authorization_escape": "NOT_MEASURED_NO_RUNTIME_EXECUTION",
                "runtime_enforcement_result": "NOT_RUN",
                "trace_completeness": "NOT_MEASURED_NO_DURABLE_TRACE"}
    for name, data in (*raw_results.items(), ("manifest.json", manifest)):
        (OUT / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not all(x["pass"] for x in matrix + pilot + negative):
        raise SystemExit("Pilot fixture oracle failed; inspect raw JSON")
    print(f"MATRIX={len(matrix)}/{len(matrix)} PILOT={len(pilot)}/{len(pilot)} NEGATIVE={len(negative)}/{len(negative)}")


if __name__ == "__main__":
    main()
