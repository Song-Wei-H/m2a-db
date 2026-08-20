"""Smoke-check the fixture dataset, MLflow recorder and trial exports only."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from experiments.boundary_experiment import (
    MlflowExperimentRecorder,
    TrialObservation,
    export_observations,
    load_scenario_dataset,
    safe_log_trial,
    summarize_primary_metrics,
)


def main() -> int:
    dataset = load_scenario_dataset("experiments/data/boundary_scenarios_v1.json")
    row = TrialObservation(
        experiment_id="readiness-smoke", scenario_id="B1-DNS",
        trial_id="readiness-smoke-1", mode="A", boundary_class="B1_VALID",
        provider="rule-based", model=None, temperature=None, seed=None,
        proposed_action="dns.metadata_collect.v1",
        proposed_parameters={"target": "asset.example"},
        model_supplied_tier=None, model_supplied_risk=None,
        authoritative_action="dns.metadata_collect.v1", authoritative_tier=0,
        governance_result="ALLOW", governance_reason="ALLOW_VALID",
        authorization_issued=True, execution_attempted=True, violation=False,
        blocked=False, unsafe_execution=False, false_block=False,
        autonomous_completion=True, trace_complete=True, latency_ms=1.0,
        raw_response={"selected_action": "dns.metadata_collect.v1"},
    )
    with tempfile.TemporaryDirectory(prefix="m2a-boundary-readiness-") as temporary:
        root = Path(temporary)
        os.environ["MLFLOW_ALLOW_FILE_STORE"] = "true"
        recorder = MlflowExperimentRecorder(
            experiment_name="M2A GADE Boundary Readiness",
            tracking_uri=root.joinpath("mlruns").resolve().as_uri(),
        )
        if not safe_log_trial(
            recorder, row, dataset_sha256=dataset["dataset_sha256"],
            prompt_hash="mode-a-no-prompt",
        ):
            raise RuntimeError("MLflow readiness smoke logging failed")
        json_path, csv_path = root / "trials.json", root / "trials.csv"
        export_observations([row], json_path=json_path, csv_path=csv_path)
        if len(json.loads(json_path.read_text(encoding="utf-8"))) != 1:
            raise RuntimeError("JSON export validation failed")
        if "scenario_id" not in csv_path.read_text(encoding="utf-8"):
            raise RuntimeError("CSV export validation failed")
        metrics = summarize_primary_metrics([row])
        if metrics["unsafe_execution_rate"]["numerator"] != 0:
            raise RuntimeError("Unsafe execution metric validation failed")
    print(
        "PASS experiment readiness smoke: "
        f"scenarios={len(dataset['scenarios'])} "
        f"dataset_sha256={dataset['dataset_sha256']} "
        "mlflow=temporary-file-store export=json,csv"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
