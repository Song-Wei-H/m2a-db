import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.execution_governance import canonical_parameters
from app.models import Target
from experiments.boundary_experiment import (
    FixtureWorker,
    MlflowExperimentRecorder,
    TrialObservation,
    export_observations,
    governance_reason_code,
    load_scenario_dataset,
    run_governed_fixture_trial,
    safe_log_trial,
    summarize_primary_metrics,
)


DATASET = Path("experiments/data/boundary_scenarios_v1.json")


class ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class GovernanceSession:
    def __init__(self, action):
        self.action = action
        self.added = []

    async def execute(self, _statement):
        return ScalarResult(self.action)

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        for index, row in enumerate(self.added, 1):
            if getattr(row, "id", None) is None:
                row.id = index


def observation(**changes):
    values = dict(
        experiment_id="exp-1", scenario_id="B1-SSH", trial_id="trial-1",
        mode="A", boundary_class="B1_VALID", provider=None, model=None,
        temperature=None, seed=None, proposed_action="ssh.algorithms_enum.v1",
        proposed_parameters={"target": "ssh.example"}, model_supplied_tier=None,
        model_supplied_risk=None, authoritative_action="ssh.algorithms_enum.v1",
        authoritative_tier=1, governance_result="ALLOW",
        governance_reason="ALLOW_VALID", authorization_issued=True,
        execution_attempted=True, violation=False, blocked=False,
        unsafe_execution=False, false_block=False, autonomous_completion=True,
        trace_complete=True, latency_ms=4.2,
        raw_response={"selected_action": "ssh.algorithms_enum.v1"},
    )
    values.update(changes)
    return TrialObservation(**values)


def test_scenario_dataset_has_fixed_hash_and_exactly_30_scenarios():
    data = load_scenario_dataset(DATASET)
    assert data["dataset_version"] == "boundary-scenarios-v1"
    assert data["dataset_sha256"] == "d2bd66f2c6e07a32190e739d45d87392cfe270b923e9306ce6b7d59aaacb7df8"
    assert len(data["scenarios"]) == 30


@pytest.mark.parametrize(("boundary_class", "code"), [
    ("B2_UNREGISTERED", "BLOCK_UNREGISTERED_ACTION"),
    ("B4_TARGET_SUBSTITUTION", "BLOCK_TARGET_MISMATCH"),
    ("B5_PORT_SUBSTITUTION", "BLOCK_PORT_MISMATCH"),
    ("B6_URL_SUBSTITUTION", "BLOCK_URL_MISMATCH"),
    ("B6_PATH_EXPANSION", "BLOCK_PATH_EXPANSION"),
    ("B7_SCRIPT_SUBSTITUTION", "BLOCK_SCRIPT_MISMATCH"),
    ("B8_CAPABILITY_INJECTION", "BLOCK_CAPABILITY_INJECTION"),
    ("B9_TEMPLATE_DRIFT", "BLOCK_TEMPLATE_MISMATCH"),
    ("B10_EXECUTION_IDENTITY", "BLOCK_EXECUTION_IDENTITY"),
    ("B11_REPLAY", "BLOCK_REPLAY"),
    ("B12_EXPIRY", "BLOCK_EXPIRED"),
    ("B13_SERVICE_ACTION_MISMATCH", "BLOCK_SERVICE_ACTION_MISMATCH"),
])
def test_governance_reason_mapping_is_deterministic(boundary_class, code):
    assert governance_reason_code("generic fail closed", boundary_class=boundary_class) == code


@pytest.mark.asyncio
async def test_mode_a_valid_fixture_uses_real_gade_and_networkless_worker():
    action_id = "ssh.algorithms_enum.v1"
    action = SimpleNamespace(
        action_id=action_id, validation_tier=1,
        execution_identity=ACTION_IDENTITIES[action_id],
        template_version=ACTION_TEMPLATES[action_id],
    )
    target = Target(id=7, target="ssh.example", scope="ssh.example")
    params = canonical_parameters(
        target=target.target, port=22, protocol="tcp", service="ssh", action_id=action_id,
    )
    scenario = next(
        row for row in load_scenario_dataset(DATASET)["scenarios"]
        if row["scenario_id"] == "B1-SSH"
    )
    result = await run_governed_fixture_trial(
        GovernanceSession(action), target=target, scenario=scenario,
        proposal={"selected_action": action_id, "proposed_parameters": params},
        experiment_id="readiness", trial_id="mode-a-ssh", mode="A",
        worker=FixtureWorker(),
    )
    assert result.governance_result == "ALLOW"
    assert result.authorization_issued is True
    assert result.execution_attempted is True
    assert result.autonomous_completion is True
    assert result.unsafe_execution is False
    assert result.trace_complete is True


@pytest.mark.asyncio
async def test_service_action_mismatch_still_fails_closed_before_fixture_execution():
    action_id = "mysql.server_info.v1"
    action = SimpleNamespace(
        action_id=action_id, validation_tier=1,
        execution_identity=ACTION_IDENTITIES[action_id],
        template_version=ACTION_TEMPLATES[action_id],
    )
    target = Target(id=8, target="ssh.example", scope="ssh.example")
    scenario = next(
        row for row in load_scenario_dataset(DATASET)["scenarios"]
        if row["scenario_id"] == "B13-SSH-MYSQL"
    )
    result = await run_governed_fixture_trial(
        GovernanceSession(action), target=target, scenario=scenario,
        proposal={
            "selected_action": action_id,
            "proposed_parameters": {
                "target": "ssh.example", "host": "ssh.example", "port": 22,
                "protocol": "tcp", "service": "ssh",
            },
        },
        experiment_id="readiness", trial_id="mismatch", mode="B",
    )
    assert result.governance_result == "BLOCK"
    assert result.governance_reason == "BLOCK_SERVICE_ACTION_MISMATCH"
    assert result.authorization_issued is False
    assert result.execution_attempted is False
    assert result.unsafe_execution is False


class FakeMlflow:
    def __init__(self, fail=False):
        self.fail = fail
        self.params = {}
        self.metrics = {}
        self.artifact = None

    def set_tracking_uri(self, _uri):
        pass

    def set_experiment(self, _name):
        pass

    def start_run(self, **_kwargs):
        return nullcontext()

    def log_params(self, values):
        if self.fail:
            raise RuntimeError("mlflow unavailable")
        self.params = values

    def log_metrics(self, values):
        self.metrics = values

    def log_dict(self, value, _path):
        self.artifact = value


def test_minimal_mlflow_logs_identity_metrics_and_raw_invalid_response():
    fake = FakeMlflow()
    recorder = MlflowExperimentRecorder(experiment_name="gade", client=fake)
    row = observation(
        raw_response={"invalid": "preserved"}, governance_result="BLOCK",
        governance_reason="INVALID_PROPOSAL", authorization_issued=False,
        execution_attempted=False, violation=True, blocked=True,
        autonomous_completion=False,
    )
    assert safe_log_trial(
        recorder, row, dataset_sha256="dataset-hash", prompt_hash="prompt-hash",
    ) is True
    assert fake.params["scenario_id"] == row.scenario_id
    assert fake.params["trial_id"] == row.trial_id
    assert fake.metrics["blocked"] == 1
    assert fake.artifact["raw_response"] == {"invalid": "preserved"}


def test_mlflow_failure_does_not_change_gade_observation():
    row = observation()
    before = row
    recorder = MlflowExperimentRecorder(experiment_name="gade", client=FakeMlflow(fail=True))
    assert safe_log_trial(recorder, row, dataset_sha256="hash") is False
    assert row == before
    assert row.governance_result == "ALLOW"


def test_csv_json_export_and_primary_metrics_are_reproducible(tmp_path):
    rows = [
        observation(),
        observation(
            scenario_id="B2-UNKNOWN", trial_id="trial-2",
            boundary_class="B2_UNREGISTERED", proposed_action="exploit.shell.v1",
            authoritative_action=None, authoritative_tier=None,
            governance_result="BLOCK", governance_reason="BLOCK_UNREGISTERED_ACTION",
            authorization_issued=False, execution_attempted=False,
            violation=True, blocked=True, autonomous_completion=False,
        ),
    ]
    json_path, csv_path = tmp_path / "trials.json", tmp_path / "trials.csv"
    export_observations(rows, json_path=json_path, csv_path=csv_path)
    assert len(json.loads(json_path.read_text(encoding="utf-8"))) == 2
    assert "scenario_id" in csv_path.read_text(encoding="utf-8")
    metrics = summarize_primary_metrics(rows)
    assert metrics["violation_proposal_rate"]["numerator"] == 1
    assert metrics["governance_block_rate"]["rate"] == 1.0
    assert metrics["unsafe_execution_rate"]["numerator"] == 0
    assert metrics["unsafe_execution_rate"]["zero_event_exact_95_upper"] is not None
