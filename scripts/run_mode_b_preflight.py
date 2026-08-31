from __future__ import annotations

import json
import argparse
from datetime import UTC, datetime
from pathlib import Path

from experiments.boundary_experiment import load_scenario_dataset
from experiments.mode_b_provider import LiteLlmModeBAdapter, require_independent_calls


REPRESENTATIVE_SCENARIOS = (
    "B1-HEADER",
    "B2-UNKNOWN",
    "B4-TARGET",
    "B8-MYSQL-AUTH",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all-scenarios", action="store_true")
    parser.add_argument("--repetitions", type=int)
    args = parser.parse_args()
    dataset = load_scenario_dataset("experiments/data/boundary_scenarios_v1.json")
    by_id = {row["scenario_id"]: row for row in dataset["scenarios"]}
    scenario_ids = tuple(by_id) if args.all_scenarios else REPRESENTATIVE_SCENARIOS
    repetitions = args.repetitions if args.repetitions is not None else (1 if args.all_scenarios else 2)
    if repetitions < 1 or repetitions > 10:
        raise ValueError("repetitions must be between 1 and 10")
    records = []
    calls = []
    adapter = LiteLlmModeBAdapter()
    for scenario_id in scenario_ids:
        for repetition in range(1, repetitions + 1):
            call = adapter.call(by_id[scenario_id])
            calls.append(call)
            records.append({
                "scenario_id": scenario_id,
                "repetition": repetition,
                "call": call.__dict__,
            })
    require_independent_calls(calls)
    run_id = datetime.now(UTC).strftime("mode-b-preflight-%Y%m%dT%H%M%S%fZ")
    output = Path("reports/experiments/mode-b-preflight") / run_id / "provider_calls.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        f"PASS mode-b boundary sweep: scenarios={len(scenario_ids)} "
        f"calls={len(calls)} unique_ids={len(calls)} "
        f"requested_model={calls[0].requested_model} returned_model={calls[0].returned_model} "
        f"prompt_hash={calls[0].prompt_hash} run_id={run_id} evidence={output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
