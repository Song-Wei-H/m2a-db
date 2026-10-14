"""Preflight or run the fixed C prompt pilot; provider calls require a clean experiment branch and confirmation."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import subprocess
import sys
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.config import settings
from app.models import Target
from app.attack_authorization import POLICY_VERSION
from experiments.boundary_experiment import expand_c_stimuli, run_governed_fixture_trial
from experiments.mode_b_provider import (
    LiteLlmModeBAdapter, ProviderIdentityError, ProviderResponseError, materialize_action_intent,
)

PLAN_PATH = HERE / "formal-experiment-plan-v1.json"
C_DESIGN_PATH = HERE / "c-adversarial-v1.json"
SOURCE_DATASET_PATH = ROOT / "experiments" / "data" / "boundary_scenarios_v1.json"
OUTPUT_ROOT = ROOT / "reports" / "experiments" / "gade-seven-level-v1" / "C" / "runs"
EXPECTED_BRANCH = "experiment/gade-seven-level-v1"
EXPECTED_CONFIRMATION = "RUN-GADE-C-PILOT-240"


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def atomic_json(path: Path, value: Any) -> None:
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temp.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
    temp.replace(path)


def load_design() -> tuple[dict[str, Any], dict[str, Any]]:
    plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    expanded = expand_c_stimuli(SOURCE_DATASET_PATH, C_DESIGN_PATH)
    if plan.get("groups", {}).get("C", {}).get("D_authorized") != 1:
        raise ValueError("C authorization depth differs from the frozen plan")
    if expanded["sample_count"] != 24 or plan["groups"]["C"].get("pilot_repetitions_per_cell") != 10:
        raise ValueError("C pilot sample count differs from the frozen 24 x 10 design")
    if plan.get("formal_execution_started") is not False:
        raise ValueError("The plan is already marked as executed; use a new versioned plan")
    return plan, expanded


def preflight() -> dict[str, Any]:
    plan, expanded = load_design()
    branch = git("branch", "--show-current")
    head = git("rev-parse", "HEAD")
    baseline = git("rev-parse", "gade-preexp-v1^{commit}")
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    expected_model = plan["fixed_variables"]["requested_model"].split(" (", 1)[0]
    if plan["fixed_variables"]["expected_returned_model"] != expected_model:
        raise ValueError("Requested and expected returned model identities are not the reviewed exact alias")
    status = {
        "branch": branch,
        "expected_branch": EXPECTED_BRANCH,
        "head": head,
        "baseline_tag_commit": baseline,
        "worktree_dirty": dirty,
        "configured_provider": "company-litellm",
        "configured_model": settings.llm_model,
        "expected_model": expected_model,
        "configured_model_matches": settings.llm_model == expected_model,
        "provider_endpoint_sha256": hashlib.sha256(settings.llm_base_url.rstrip('/').encode()).hexdigest(),
        "cells": expanded["sample_count"],
        "repetitions_per_cell": plan["groups"]["C"]["pilot_repetitions_per_cell"],
        "planned_provider_calls": expanded["sample_count"] * plan["groups"]["C"]["pilot_repetitions_per_cell"],
        "provider_live_status": "NOT_CHECKED_NO_REQUEST_SENT",
        "worker_execution": "DISABLED_NETWORKLESS_FIXTURE_ONLY",
        "source_dataset_sha256": expanded["source_dataset_sha256"],
        "c_design_file_sha256": expanded["c_design_file_sha256"],
        "expanded_dataset_sha256": expanded["expanded_dataset_sha256"],
    }
    status["execution_gate_pass"] = (
        branch == EXPECTED_BRANCH and not dirty and settings.llm_model == expected_model
        and baseline == plan["baseline_commit_sha"]
    )
    return status


class ScalarResult:
    def __init__(self, value: Any):
        self.value = value

    def scalar_one_or_none(self) -> Any:
        return self.value


class InMemoryGovernanceSession:
    """Only stores ephemeral objects for one fixture trial; never opens a database."""
    def __init__(self, action: Any):
        self.action = action
        self.added: list[Any] = []

    async def execute(self, _statement: Any) -> ScalarResult:
        return ScalarResult(self.action)

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        for index, row in enumerate(self.added, 1):
            if getattr(row, "id", None) is None:
                row.id = index


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def error_record(sample: dict[str, Any], repetition: int, status: str, error: Exception) -> dict[str, Any]:
    return {
        "sample_id": sample["sample_id"], "attack_class": sample["attack_class"],
        "source_scenario_id": sample["source_scenario_id"], "input_sha256": sample["input_sha256"],
        "repetition": repetition, "D_authorized": 1, "expected_action": sample["expected_action"],
        "expected_valid": sample["expected_valid"], "proposal_outcome": status,
        "governance_result": "NOT_RUN", "authorization_issued": False,
        "execution_attempted": False, "execution_kind": "FIXTURE",
        "error_class": type(error).__name__, "error_summary": str(error)[:1000],
        "durable_authorization_issued": False, "durable_trace_complete": False,
    }


async def collect(plan: dict[str, Any], expanded: dict[str, Any], run_id: str, output: Path,
                  expected_model: str) -> tuple[list[dict[str, Any]], bool]:
    observations_path = output / "observations.jsonl"
    adapter = LiteLlmModeBAdapter()
    seen_call_ids: set[str] = set()
    aborted = False
    repetitions = plan["groups"]["C"]["pilot_repetitions_per_cell"]
    for sample in expanded["samples"]:
        scenario = sample["scenario"]
        expected_action = sample["expected_action"]
        for repetition in range(1, repetitions + 1):
            call_started = datetime.now(timezone.utc).isoformat()
            try:
                call = adapter.call(scenario, expected_model=expected_model)
            except ProviderIdentityError as exc:
                row = error_record(sample, repetition, "PROVIDER_ERROR", exc)
                row["provider_evidence"] = exc.evidence
                append_jsonl(observations_path, row)
                aborted = True
                break
            except ProviderResponseError as exc:
                row = error_record(sample, repetition, "INVALID_RESPONSE", exc)
                row["provider_evidence"] = exc.evidence
                call_id = exc.evidence.get("provider_call_id")
                row["provider_call_id"] = call_id
                if call_id in seen_call_ids:
                    row["proposal_outcome"] = "PROVIDER_ERROR"
                    row["error_summary"] = "Duplicate provider_call_id on invalid response; collection stopped"
                    aborted = True
                else:
                    seen_call_ids.add(call_id)
                append_jsonl(observations_path, row)
                if aborted:
                    break
                continue
            except httpx.HTTPError as exc:
                row = error_record(sample, repetition, "PROVIDER_ERROR", exc)
                append_jsonl(observations_path, row)
                aborted = True
                break
            except ValueError as exc:
                row = error_record(sample, repetition, "INVALID_RESPONSE", exc)
                append_jsonl(observations_path, row)
                aborted = True
                break
            except Exception as exc:
                row = error_record(sample, repetition, "RUNTIME_ERROR", exc)
                append_jsonl(observations_path, row)
                aborted = True
                break

            if call.provider != "company-litellm" or call.requested_model != expected_model or call.returned_model != expected_model:
                mismatch = RuntimeError(
                    f"Provider/model identity mismatch: provider={call.provider}, "
                    f"requested={call.requested_model}, returned={call.returned_model}"
                )
                row = error_record(sample, repetition, "PROVIDER_ERROR", mismatch)
                row.update({"provider_call_id": call.provider_call_id, "requested_model": call.requested_model,
                            "returned_model": call.returned_model, "response_sha256": call.response_hash})
                append_jsonl(observations_path, row)
                aborted = True
                break
            if call.provider_call_id in seen_call_ids:
                duplicate = RuntimeError("Duplicate provider_call_id; collection stopped")
                row = error_record(sample, repetition, "PROVIDER_ERROR", duplicate)
                row.update({"provider_call_id": call.provider_call_id, "response_sha256": call.response_hash})
                append_jsonl(observations_path, row)
                aborted = True
                break
            seen_call_ids.add(call.provider_call_id)

            # The in-memory registry result is selected from the model's proposal below.
            proposed_action = call.proposal.get("selected_action")
            if proposed_action in ACTION_IDENTITIES:
                action = SimpleNamespace(
                    action_id=proposed_action, validation_tier=1,
                    execution_identity=ACTION_IDENTITIES[proposed_action],
                    template_version=ACTION_TEMPLATES[proposed_action],
                )
            else:
                action = None
            try:
                proposal = materialize_action_intent(
                    scenario, call.proposal,
                    raw_response={"provider_call_id": call.provider_call_id,
                                  "returned_model": call.returned_model,
                                  "response_sha256": call.response_hash},
                )
            except (KeyError, TypeError, ValueError):
                # Preserve the actionable proposal; let the governance fixture classify it as a block.
                proposal = {
                    "selected_action": proposed_action, "proposed_parameters": {},
                    "ignored_authority_fields": call.proposal.get("ignored_authority_fields") or [],
                    "reason": call.proposal.get("reason") or "action materialization rejected",
                    "raw_response": {"provider_call_id": call.provider_call_id,
                                     "response_sha256": call.response_hash},
                }
            target_name = str(scenario["evidence"]["target"])
            target = Target(id=1, target=target_name, target_type="fixture",
                            scope=target_name, authorization_depth=1,
                            authorization_policy_version=POLICY_VERSION)
            call_completed = datetime.now(timezone.utc).isoformat()
            try:
                result = await run_governed_fixture_trial(
                    InMemoryGovernanceSession(action), target=target, scenario=scenario,
                    proposal=proposal, experiment_id=run_id,
                    trial_id=f"{sample['sample_id']}:{repetition}", mode="C",
                    provider=call.provider, model=call.returned_model,
                    temperature=0, seed=None,
                )
                row = asdict(result)
            except Exception as exc:
                row = error_record(sample, repetition, "RUNTIME_ERROR", exc)
                aborted = True
            row.update({
                "sample_id": sample["sample_id"], "attack_class": sample["attack_class"],
                "source_scenario_id": sample["source_scenario_id"],
                "input_sha256": sample["input_sha256"], "repetition": repetition,
                "D_authorized": 1, "expected_action": expected_action,
                "expected_valid": sample["expected_valid"],
                "proposed_action": proposed_action,
                "provider": call.provider, "provider_call_id": call.provider_call_id,
                "requested_model": call.requested_model, "returned_model": call.returned_model,
                "prompt_sha256": call.prompt_hash, "request_sha256": call.request_hash,
                "response_sha256": call.response_hash, "call_started_at_utc": call_started,
                "call_completed_at_utc": call_completed,
                "execution_kind": "FIXTURE", "real_worker_execution": False,
                "durable_authorization_issued": False, "durable_trace_complete": False,
                "provider_evidence": asdict(call),
            })
            append_jsonl(observations_path, row)
            if (row.get("governance_result") == "RUNTIME_ERROR"
                    or row.get("execution_outcome") == "RUNTIME_ERROR"
                    or row.get("authorization_contract_consistent") is False
                    or (row.get("authorization_violation") and row.get("authorization_issued"))):
                aborted = True
            if aborted:
                break
        if aborted:
            break
    return read_jsonl(observations_path), aborted


def run_provider_smoke(checks: dict[str, Any]) -> None:
    """One provider identity request, with no governance or Worker execution and no retry."""
    print("PROVIDER_SMOKE_PLAN=1 request; unmodified B1-HEADER; diagnostic only, excluded from C samples")
    if input("Type exactly RUN-GADE-PROVIDER-SMOKE-1: ").strip() != "RUN-GADE-PROVIDER-SMOKE-1":
        raise SystemExit("PROVIDER_SMOKE=CANCELLED; LLM_CALLS=0")
    source = json.loads(SOURCE_DATASET_PATH.read_text(encoding="utf-8"))
    scenario = next(row for row in source["scenarios"] if row["scenario_id"] == "B1-HEADER")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:10]
    output = OUTPUT_ROOT.parent.parent / "provider-smoke" / run_id
    output.mkdir(parents=True, exist_ok=False)
    result = {"method_commit": checks["head"], "started_at_utc": datetime.now(timezone.utc).isoformat(),
              "provider_endpoint_sha256": checks["provider_endpoint_sha256"],
              "expected_model": checks["expected_model"], "maximum_requests": 1,
              "requests_attempted": 1, "diagnostic_only": True, "included_in_C_samples": False,
              "real_worker_execution": False, "retry_count": 0}
    try:
        call = LiteLlmModeBAdapter().call(scenario, expected_model=checks["expected_model"])
    except ProviderIdentityError as exc:
        result.update({"identity_status": "FAIL", "response_status": "NOT_VALIDATED",
                       "provider_evidence": exc.evidence, "error": str(exc)})
    except ProviderResponseError as exc:
        result.update({"identity_status": "PASS", "response_status": "INVALID_RESPONSE",
                       "provider_evidence": exc.evidence, "error": str(exc)})
    except Exception as exc:
        result.update({"identity_status": "UNVERIFIED", "response_status": "ERROR",
                       "error": f"{type(exc).__name__}: {exc}"})
    else:
        result.update({"identity_status": "PASS", "response_status": "VALID_ACTION_INTENT",
                       "provider_evidence": asdict(call)})
    result["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    atomic_json(output / "provider-smoke.json", result)
    print(f"PROVIDER_IDENTITY={result['identity_status']} REQUESTS_ATTEMPTED=1 EVIDENCE={output}")
    if result["identity_status"] != "PASS" or result["response_status"] != "VALID_ACTION_INTENT":
        raise SystemExit("PROVIDER_SMOKE=NOT_READY; evidence preserved; no retry")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true", help="validate inputs/config without contacting the provider")
    parser.add_argument("--execute", action="store_true", help="issue the fixed 240-call provider pilot after explicit confirmation")
    parser.add_argument("--provider-smoke", action="store_true", help="one provider identity request after separate explicit confirmation; no C pilot")
    args = parser.parse_args()
    if sum((args.preflight_only, args.execute, args.provider_smoke)) > 1:
        raise SystemExit("Choose exactly one of --preflight-only, --execute, --provider-smoke")
    try:
        plan, expanded = load_design()
        checks = preflight()
    except Exception as exc:
        raise SystemExit(f"C_PREFLIGHT=FAIL error={type(exc).__name__}: {exc}")
    print("C_PREFLIGHT=" + ("PASS" if checks["execution_gate_pass"] else "LIMITED"))
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    if args.preflight_only or not (args.execute or args.provider_smoke):
        print("LLM_CALLS=0")
        return
    if not checks["execution_gate_pass"]:
        raise SystemExit("C execution gate failed (branch, clean tree, model identity, or baseline SHA)")
    if args.provider_smoke:
        run_provider_smoke(checks)
        return
    print(f"Planned provider calls: {checks['planned_provider_calls']}; no database, Docker, Worker, or target execution.")
    if input(f"Type exactly {EXPECTED_CONFIRMATION}: ").strip() != EXPECTED_CONFIRMATION:
        raise SystemExit("C_PILOT=CANCELLED; no provider call was made")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:10]
    output = OUTPUT_ROOT / run_id
    output.mkdir(parents=True, exist_ok=False)
    atomic_json(output / "samples.json", expanded)
    start_manifest = {
        "run_id": run_id, "status": "RUNNING", "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "branch": checks["branch"], "source_commit_sha": checks["head"],
        "baseline_commit_sha": checks["baseline_tag_commit"],
        "plan_sha256": file_sha(PLAN_PATH), "c_design_sha256": checks["c_design_file_sha256"],
        "expanded_dataset_sha256": checks["expanded_dataset_sha256"],
        "policy_version": POLICY_VERSION, "policy_sha256": file_sha(ROOT / "app" / "attack_authorization.py"),
        "action_contract_sha256": file_sha(ROOT / "app" / "action_contracts.py"),
        "runner_sha256": file_sha(Path(__file__)), "provider": "company-litellm",
        "requested_model": settings.llm_model, "temperature": 0, "seed": None,
        "expected_calls": checks["planned_provider_calls"], "real_worker_execution": False,
    }
    atomic_json(output / "manifest.running.json", start_manifest)
    observations, aborted = asyncio.run(collect(
        plan, expanded, run_id, output, checks["expected_model"],
    ))
    with (output / "trials.json").open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(observations, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    analyzer_path = HERE / "analyze_results.py"
    spec = importlib.util.spec_from_file_location("gade_result_analyzer", analyzer_path)
    if spec is None or spec.loader is None:
        raise SystemExit("Unable to load result analyzer; raw observations are preserved")
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    summary = analyzer.analyze_c(observations) if observations else {"status": "NO_OBSERVATIONS"}
    atomic_json(output / "summary.json", summary)
    final_manifest = {
        **start_manifest, "status": "PARTIAL_STOPPED_NOT_ACCEPTED" if aborted else "PILOT_COMPLETE",
        "fixture_acceptance_status": summary.get("fixture_acceptance_status", "NO_OBSERVATIONS"),
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "attempted_observations": len(observations),
        "distinct_provider_call_ids": len({row.get("provider_call_id") for row in observations if row.get("provider_call_id")}),
        "observations_sha256": file_sha(output / "trials.json"),
        "summary_sha256": file_sha(output / "summary.json"),
        "real_unauthorized_execution_count": "NOT_MEASURED_NO_REAL_WORKER",
        "durable_execution_trace": "NOT_MEASURED_IN_MEMORY_FIXTURE",
    }
    with (output / "manifest.json").open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(final_manifest, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(f"C_PILOT={final_manifest['status']} run_id={run_id} evidence={output}")


if __name__ == "__main__":
    main()
