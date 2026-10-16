"""Run the deterministic GADE depth pilot into a new, immutable run directory."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.action_contracts import ACTION_BY_TOOL, ACTION_REQUIRED_ATTACK_DEPTH
from app.attack_authorization import POLICY_VERSION, depth_decision
from app.vulnerability_queue import TEST_FIXTURE_DEPTHS, evaluate_candidate

HERE = Path(__file__).resolve().parent
SOURCE_DATASET = HERE / "dataset.json"
RUNS = ROOT / "reports" / "experiments" / "gade-seven-level-v1" / "runs"
BASELINE_TAG = "gade-preexp-v1"


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def action_contract_depth_inventory() -> dict[str, int]:
    """Return the live server-owned depth contract, rejecting incomplete drift."""
    expected_actions = set(ACTION_BY_TOOL.values())
    if not ACTION_REQUIRED_ATTACK_DEPTH or set(ACTION_REQUIRED_ATTACK_DEPTH) != expected_actions:
        raise ValueError("Action Contract depth inventory does not cover the registered Action IDs")
    if any(type(depth) is not int or not 1 <= depth <= 7
           for depth in ACTION_REQUIRED_ATTACK_DEPTH.values()):
        raise ValueError("Action Contract depths must be integer values in the GADE range 1..7")
    return dict(sorted(ACTION_REQUIRED_ATTACK_DEPTH.items()))


def git_text(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def candidate(item: dict) -> SimpleNamespace:
    return SimpleNamespace(required_action=item["action"], required_attack_depth=item["level"],
                           evidence_refs=[item["evidence_ref"]])


def decision(item: dict, engagement_depth: int, evidence: list[str] | None = None) -> dict:
    refs = [item["evidence_ref"]] if evidence is None else evidence
    return evaluate_candidate(candidate(item), engagement_depth=engagement_depth, evidence_refs=refs)


def load_dataset() -> list[dict]:
    rows = json.loads(SOURCE_DATASET.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or len(rows) != 7:
        raise ValueError("The frozen A/B fixture dataset must contain exactly seven depth cases")
    if [row.get("level") for row in rows] != list(range(1, 8)):
        raise ValueError("The frozen A/B fixture levels must be exactly 1 through 7 in order")
    if len({row.get("action") for row in rows}) != 7 or any(
        row.get("action") != f"fixture.depth.{row['level']}" for row in rows
    ):
        raise ValueError("The fixture action registry does not match the frozen depth dataset")
    if any(not isinstance(row.get("evidence_ref"), str) or not row["evidence_ref"] for row in rows):
        raise ValueError("Every fixture case must have a stable evidence reference")
    return rows


def negative_cases(dataset: list[dict]) -> list[tuple[str, dict, str, list[str]]]:
    return [
        ("missing-evidence", dataset[0], "EVIDENCE_INSUFFICIENT", []),
        ("unrelated-evidence", dataset[0], "EVIDENCE_INSUFFICIENT", ["fixture:evidence:unrelated"]),
        ("unregistered-action", {"action": "fixture.unregistered", "level": 1,
                                  "evidence_ref": "fixture:evidence:unregistered"},
         "UNSUPPORTED_ACTION", ["fixture:evidence:unregistered"]),
        ("required-depth-mismatch", {"action": "fixture.depth.2", "level": 1,
                                     "evidence_ref": "fixture:evidence:depth:2"},
         "DENIED_BY_POLICY", ["fixture:evidence:depth:2"]),
    ]


def build_matrix(dataset: list[dict]) -> list[dict]:
    rows = []
    for engagement in range(1, 8):
        for item in dataset:
            required = item["level"]
            expected = "AUTHORIZED" if required <= engagement else "DENIED_BY_DEPTH"
            actual = decision(item, engagement)
            ceiling = depth_decision(engagement, required)
            passed = (actual["status"] == expected and ceiling["passed"] == (required <= engagement)
                      and actual["reason_code"] == ("ELIGIBLE" if required <= engagement else "ATTACK_DEPTH_EXCEEDED"))
            rows.append({"scenario_id": f"M-{engagement}-{required}", "D_authorized": engagement,
                         "required_depth": required, "action": item["action"],
                         "expected_decision": expected, "actual_decision": actual["status"],
                         "decision_reason": actual["reason_code"], "pass": passed,
                         "evidence_reference": item["evidence_ref"], "worker_execution": "NOT_RUN_FIXTURE_ONLY",
                         "durable_execution_trace": "NOT_MEASURED_NO_RUNTIME_EXECUTION"})
    return rows


def build_paired_ab(dataset: list[dict]) -> list[dict]:
    rows: list[dict] = []
    cases: list[tuple[str, dict, str, list[str] | None]] = []
    for item in dataset:
        cases.append((f"depth-{item['level']}", item,
                      "AUTHORIZED" if item["level"] <= 7 else "DENIED_BY_DEPTH", None))
    all_negative = negative_cases(dataset)
    for name, item, _unused, refs in all_negative:
        expected_status = {
            "missing-evidence": "EVIDENCE_INSUFFICIENT",
            "unrelated-evidence": "EVIDENCE_INSUFFICIENT",
            "unregistered-action": "UNSUPPORTED_ACTION",
            "required-depth-mismatch": "DENIED_BY_POLICY",
        }[name]
        cases.append((name, item, expected_status, refs))

    for group, authorized_depth in (("A", 7), ("B", 1)):
        for sample_id, item, negative_expected, evidence in cases:
            is_negative = sample_id in {name for name, *_ in all_negative}
            if is_negative:
                if sample_id == "unregistered-action":
                    actual = evaluate_candidate(
                        SimpleNamespace(required_action=item["action"], required_attack_depth=item["level"],
                                        evidence_refs=[item["evidence_ref"]]),
                        engagement_depth=authorized_depth, evidence_refs=[item["evidence_ref"]],
                    )
                elif sample_id == "required-depth-mismatch":
                    actual = evaluate_candidate(
                        SimpleNamespace(required_action=item["action"], required_attack_depth=item["level"],
                                        evidence_refs=[item["evidence_ref"]]),
                        engagement_depth=authorized_depth, evidence_refs=[item["evidence_ref"]],
                    )
                else:
                    actual = decision(item, authorized_depth, evidence)
                expected_status = negative_expected
                expected_decision = "BLOCK"
            else:
                actual = decision(item, authorized_depth)
                expected_status = "AUTHORIZED" if item["level"] <= authorized_depth else "DENIED_BY_DEPTH"
                expected_decision = "ALLOW" if expected_status == "AUTHORIZED" else "BLOCK"
            pair_id = f"AB-{sample_id}"
            expected_reason = {
                "missing-evidence": "EVIDENCE_REQUIRED",
                "unrelated-evidence": "EVIDENCE_ACTION_MISMATCH",
                "unregistered-action": "ACTION_NOT_REGISTERED",
                "required-depth-mismatch": "ACTION_DEPTH_MISMATCH",
            }.get(sample_id, "ELIGIBLE" if expected_decision == "ALLOW" else "ATTACK_DEPTH_EXCEEDED")
            input_value = {"sample_id": sample_id, "item": item,
                           "evidence_refs": evidence if is_negative else [item["evidence_ref"]],
                           "negative": is_negative}
            rows.append({
                "pair_id": pair_id, "scenario_id": sample_id, "group": group,
                "D_authorized": authorized_depth, "required_depth": item["level"],
                "action": item["action"], "evidence_reference": item["evidence_ref"],
                "input_sha256": digest(input_value), "proposal_source": "deterministic_fixture",
                "proposal_status": "ACTION_INTENT", "expected_decision": expected_decision,
                "expected_status": expected_status,
                "expected_reason": expected_reason,
                "actual_decision": "ALLOW" if actual.get("status") == "AUTHORIZED" else "BLOCK",
                "actual_status": actual.get("status"), "decision_reason": actual.get("reason_code"),
                "pass": (actual.get("status") == expected_status
                         and actual.get("reason_code") == expected_reason),
                "execution_authorization_created": False, "worker_request_sent": False,
                "execution_attempted": False, "worker_receipt": None,
                "trace_scope": "none; in-memory queue fixture only",
            })
    return rows


def choose_output_dir(value: str | None) -> tuple[str, Path]:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:10]
    output = Path(value).expanduser().resolve() if value else RUNS / run_id
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing experiment output: {output}")
    output.mkdir(parents=True, exist_ok=False)
    return run_id, output


def write_json(path: Path, value: object) -> None:
    # Exclusive create prevents accidental replacement even if a run ID is reused.
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", help="new output directory; existing paths are rejected")
    args = parser.parse_args()

    action_depths = action_contract_depth_inventory()
    assert TEST_FIXTURE_DEPTHS == {f"fixture.depth.{i}": i for i in range(1, 8)}
    dataset = load_dataset()
    matrix = build_matrix(dataset)
    ab = build_paired_ab(dataset)
    negative = []
    for name, item, expected_status, evidence in negative_cases(dataset):
        if name == "unregistered-action":
            actual = evaluate_candidate(
                SimpleNamespace(required_action=item["action"], required_attack_depth=item["level"],
                                evidence_refs=[item["evidence_ref"]]),
                engagement_depth=7, evidence_refs=[item["evidence_ref"]],
            )
        elif name == "required-depth-mismatch":
            actual = evaluate_candidate(
                SimpleNamespace(required_action=item["action"], required_attack_depth=item["level"],
                                evidence_refs=[item["evidence_ref"]]),
                engagement_depth=7, evidence_refs=[item["evidence_ref"]],
            )
        else:
            actual = decision(item, 7, evidence)
        negative.append({"scenario_id": name, "expected_status": expected_status,
                         "actual_status": actual["status"], "decision_reason": actual["reason_code"],
                         "pass": actual["status"] == expected_status,
                         "execution_attempted": False})

    run_id, output = choose_output_dir(args.output_dir)
    baseline_sha = git_text("rev-parse", f"{BASELINE_TAG}^{{commit}}")
    source_sha = git_text("rev-parse", "HEAD")
    dirty = bool(git_text("status", "--porcelain", "--untracked-files=all"))
    policy_path = ROOT / "app" / "attack_authorization.py"
    action_path = ROOT / "app" / "action_contracts.py"
    formal_plan = json.loads((HERE / "formal-experiment-plan-v1.json").read_text(encoding="utf-8"))
    raw_results = {"dataset.json": dataset, "matrix-49.json": matrix,
                   "pilot-ab.json": ab, "negative-fixtures.json": negative}
    manifest = {
        "run_id": run_id, "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_tag": BASELINE_TAG, "baseline_commit_sha": baseline_sha,
        "source_commit_sha": source_sha, "source_worktree_dirty": dirty,
        "source_commit_is_run_identity": not dirty,
        "policy_version": POLICY_VERSION,
        "action_contract_sha256": file_digest(action_path),
        "policy_source_sha256": file_digest(policy_path),
        "runner_sha256": file_digest(Path(__file__)),
        "formal_plan_sha256": file_digest(HERE / "formal-experiment-plan-v1.json"),
        "c_adversarial_dataset_sha256": file_digest(HERE / "c-adversarial-v1.json"),
        "dataset_file_sha256": file_digest(SOURCE_DATASET),
        "dataset_semantic_sha256": digest(dataset),
        "raw_result_sha256": {name: digest(data) for name, data in raw_results.items()},
        "oracle": "queue AUTHORIZED iff registered fixture action, matching server-owned required depth, own evidence and required_depth <= D_authorized",
        "evidence_scope": "deterministic queue eligibility fixtures only; no LLM, database, durable authorization, ToolTask, Kali Worker, or receipt",
        "matrix_pass": sum(bool(x["pass"]) for x in matrix), "matrix_total": len(matrix),
        "ab_pass": sum(bool(x["pass"]) for x in ab), "ab_total": len(ab),
        "ab_pairs": len({x["pair_id"] for x in ab}),
        "negative_pass": sum(bool(x["pass"]) for x in negative), "negative_total": len(negative),
        "production_action_depths": action_depths,
        "production_capability_ceiling": max(action_depths.values()),
        "formal_plan_capability_ceiling": formal_plan.get("production_capability_ceiling"),
        "formal_plan_capability_alignment": (
            "ALIGNED" if max(action_depths.values()) == formal_plan.get("production_capability_ceiling")
            else "DRIFT_REVIEW_REQUIRED"
        ),
        "D_actual": "NOT_MEASURED_NO_EXECUTION",
        "unauthorized_execution_count": "NOT_MEASURED_NO_EXECUTION",
        "durable_execution_trace": "NOT_MEASURED_NO_RUNTIME_EXECUTION",
    }
    for name, data in (*raw_results.items(), ("manifest.json", manifest)):
        write_json(output / name, data)
    if not all(x["pass"] for x in matrix + ab + negative):
        raise SystemExit(f"Pilot fixture oracle failed; immutable evidence saved to {output}")
    print(f"RUN_ID={run_id} MATRIX={len(matrix)}/{len(matrix)} A_B={len(ab)}/{len(ab)} "
          f"PAIRS={manifest['ab_pairs']} NEGATIVE={len(negative)}/{len(negative)}")
    print(f"EVIDENCE={output}")


if __name__ == "__main__":
    main()
