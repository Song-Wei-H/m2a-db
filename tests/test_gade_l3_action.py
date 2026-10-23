import json
import hashlib
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.action_contracts import (
    ACTION_BY_TOOL, ACTION_IDENTITIES, ACTION_PARAMETER_SCHEMAS,
    ACTION_REQUIRED_ATTACK_DEPTH, ACTION_TEMPLATES, canonical_action_parameters,
)
from app.attack_authorization import depth_decision
from app.execution_governance import parameter_hash
from kali_worker import app as worker


ACTION = "lab.fixed_python_execution.v1"
TOOL = "lab_fixed_python_execution"
TARGET = "10.56.66.119"
PORT = 18080
SCRIPT_ID = "gade-controlled-python-execution-v1"
SCRIPT_SHA = "b6d8391432ad8f0f993a51c2c35e13d86354f3d0220c3e1c71d69e82a5f164bb"


@pytest.fixture(autouse=True)
def worker_replay_ledger(monkeypatch, tmp_path):
    monkeypatch.setenv("KALI_WORKER_REPLAY_DB_PATH", str(tmp_path / "worker-replay.sqlite3"))


def make_request(**overrides):
    correlation_id = overrides.pop("correlation_id", f"GADE-L3-D7-{uuid4().hex[:12]}")
    parameters = canonical_action_parameters(action_id=ACTION, target=TARGET, port=PORT,
                                             protocol="tcp", service="http")
    request = {
        "tool": TOOL, "target": TARGET, "port": PORT, "protocol": "tcp", "service": "http",
        "action_id": ACTION, "execution_identity": ACTION_IDENTITIES[ACTION],
        "authorization_parameters": parameters,
        "authorization_parameters_hash": parameter_hash(parameters), "task_id": 43,
        "authorization_id": 8, "request_id": str(uuid4()), "correlation_id": correlation_id,
        "template_id": ACTION_TEMPLATES[ACTION],
        "expected_worker_build_sha256": worker.WORKER_BUILD_SHA256,
    }
    request.update(overrides)
    return request


def test_l3_contract_is_fixed_to_target_and_depth_three():
    assert ACTION_BY_TOOL[TOOL] == ACTION
    assert ACTION_REQUIRED_ATTACK_DEPTH[ACTION] == 3
    assert ACTION_TEMPLATES[ACTION] == "lab_fixed_python_execution_v1"
    params = canonical_action_parameters(action_id=ACTION, target=TARGET, port=PORT,
                                         protocol="tcp", service="http")
    assert params["execute_path"] == "/lab/execute"
    assert params["script_id"] == SCRIPT_ID and params["script_sha256"] == SCRIPT_SHA
    assert params["expected_result"] == 39
    target_script = Path(__file__).resolve().parents[1] / "lab" / "mode-b-target" / "l3_execution_task.py"
    assert hashlib.sha256(target_script.read_bytes()).hexdigest() == SCRIPT_SHA
    assert "password" not in json.dumps(ACTION_PARAMETER_SCHEMAS[ACTION])
    assert depth_decision(7, 3)["passed"] is True
    assert depth_decision(1, 3)["reason_code"] == "ATTACK_DEPTH_EXCEEDED"


def test_codex_strict_output_schema_omits_unsupported_unique_items_but_rejects_duplicates_locally():
    import importlib.util
    import pytest

    bridge_path = (Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                   / "l3-action" / "codex_agent_bridge.py")
    spec = importlib.util.spec_from_file_location("gade_l3_codex_bridge_schema_test", bridge_path)
    assert spec is not None and spec.loader is not None
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)

    schema = bridge.output_schema()
    evidence_schema = schema["properties"]["evidence_ids"]
    assert "uniqueItems" not in evidence_schema
    assert evidence_schema["maxItems"] == 16

    duplicate_proposal = {
        "decision": "STOP",
        "action_id": None,
        "rationale": "The current evidence is sufficient to stop.",
        "evidence_ids": ["evidence-1", "evidence-1"],
    }
    with pytest.raises(ValueError, match="contains duplicates"):
        bridge.validate_decision_output(
            duplicate_proposal,
            available_action_ids={"http_security_headers.collect.v1"},
            evidence_ids={"evidence-1"},
        )


def test_l3_driver_depth_precondition_matches_contract(monkeypatch):
    import importlib.util
    import pytest

    driver_path = (Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                   / "l3-action" / "run_l3_d7_d1.py")
    spec = importlib.util.spec_from_file_location("gade_l3_driver_depth_test", driver_path)
    assert spec is not None and spec.loader is not None
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)

    assert driver.EXPECTED_ACTION_DEPTH == ACTION_REQUIRED_ATTACK_DEPTH[ACTION] == 3
    driver.validate_canonical_l3_action_depth()
    driver.validate_observed_content({
        "target": "10.56.66.119:18080", "scope": "10.56.66.119/32",
        "target_health_http_status": 200, "reset_verified": True,
        "reset_status": "reset", "active_sessions": 0,
        "l3_marker_cleared": True, "l3_temp_files_cleared": True,
    })
    with pytest.raises(RuntimeError, match="healthy response"):
        driver.validate_observed_content({
            "target": "10.56.66.119:18080", "scope": "10.56.66.119/32",
            "health_status": 200, "reset_verified": True,
        })
    monkeypatch.setitem(driver.ACTION_REQUIRED_ATTACK_DEPTH, ACTION, 2)
    with pytest.raises(RuntimeError, match=r"expected 3, got 2"):
        driver.validate_canonical_l3_action_depth()


def test_limited_c_evidence_is_fixed_untrusted_and_cannot_change_the_base_observation():
    import importlib.util
    import json
    import pytest

    driver_path = (Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                   / "l3-action" / "run_l3_d7_d1.py")
    spec = importlib.util.spec_from_file_location("gade_l3_c_evidence_contract_test", driver_path)
    assert spec is not None and spec.loader is not None
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    content = {
        "target": "10.56.66.119:18080", "scope": "10.56.66.119/32",
        "target_health_http_status": 200, "reset_verified": True, "reset_status": "reset",
        "active_sessions": 0, "l3_marker_cleared": True, "l3_temp_files_cleared": True,
    }
    content_bytes = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    content_sha = hashlib.sha256(content_bytes).hexdigest()
    observation = {"evidence_id": f"lab-observation:sha256:{content_sha}", "content_sha256": content_sha}
    stimulus = driver.L3_C_STIMULUS
    stimulus_hash = hashlib.sha256(stimulus["text"].encode("utf-8")).hexdigest()
    base = {"evidence_id": observation["evidence_id"], "sha256": content_sha, "content": content}
    injected = {"evidence_id": f"untrusted-evidence:sha256:{stimulus_hash}",
                "kind": "untrusted_prompt_injection", "sha256": stimulus_hash,
                "content": {"stimulus_id": stimulus["stimulus_id"], "trust": "UNTRUSTED",
                            "text": stimulus["text"]}}
    assert driver.validate_case_evidence("C", 1, [base, injected], observation, content,
                                         [base["evidence_id"], injected["evidence_id"]]) == {
                                             base["evidence_id"], injected["evidence_id"]}
    with pytest.raises(RuntimeError, match="fixed, hashed stimulus"):
        driver.validate_case_evidence("C", 1, [base, {**injected, "content": {"trust": "TRUSTED"}}],
                                      observation, content, [base["evidence_id"], injected["evidence_id"]])
    with pytest.raises(RuntimeError, match="only the canonical post-reset observation"):
        driver.validate_case_evidence("D1", 1, [base, injected], observation, content,
                                      [base["evidence_id"], injected["evidence_id"]])
    with pytest.raises(RuntimeError, match="exactly one untrusted evidence item"):
        driver.validate_case_evidence("C", 1, [base], observation, content, [base["evidence_id"]])


def test_l3_registry_uses_the_agent_catalog_schema_for_legacy_l1():
    import importlib.util
    import pytest

    from app.action_contracts import ACTION_PARAMETER_SCHEMAS

    driver_path = (Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                   / "l3-action" / "run_l3_d7_d1.py")
    spec = importlib.util.spec_from_file_location("gade_l3_driver_registry_schema_test", driver_path)
    assert spec is not None and spec.loader is not None
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)

    worker_tools = {item["tool"] for item in driver.ACTION_CONFIG.values()}
    catalog = driver.build_action_catalog(worker_tools)
    schemas = driver._registration_parameter_schemas(catalog)
    l1_action = "http_security_headers.collect.v1"
    l1_catalog_item = next(item for item in catalog if item["action_id"] == l1_action)

    # Legacy L1 intentionally gets its fixed schema from the reviewed Agent
    # catalog builder; it is not a key in ACTION_PARAMETER_SCHEMAS.
    assert l1_action not in ACTION_PARAMETER_SCHEMAS
    assert schemas[l1_action] == l1_catalog_item["parameter_schema"]
    assert set(schemas) == set(driver.ACTION_CONFIG)
    assert sorted(schemas[l1_action]["properties"]) == [
        "canonical_url", "collector", "host", "path", "port", "protocol",
        "scheme", "service", "target",
    ]

    incomplete_catalog = [dict(item) for item in catalog]
    incomplete_catalog[0].pop("parameter_schema")
    with pytest.raises(RuntimeError, match="no reviewed parameter schema"):
        driver._registration_parameter_schemas(incomplete_catalog)


def test_l3_registry_reconciles_only_the_known_026_to_028_l1_seed():
    import importlib.util
    from types import SimpleNamespace
    import pytest

    driver_path = (Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                   / "l3-action" / "run_l3_d7_d1.py")
    spec = importlib.util.spec_from_file_location("gade_l3_driver_registry_seed_test", driver_path)
    assert spec is not None and spec.loader is not None
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)

    action_id = "http_security_headers.collect.v1"
    tool_name = "http_security_headers"
    current_template = "http_security_headers_v2"
    old_template = "http_security_headers_v1"
    registry = SimpleNamespace(tool_name=tool_name, enabled=True, profile_id="remote-worker",
                               template_id=old_template)
    legacy = SimpleNamespace(template_id=old_template, tool_name=tool_name, enabled=False)

    state = driver._verify_or_reconcile_tool_registry(
        registry, action_id=action_id, tool_name=tool_name,
        template_id=current_template, legacy_template=legacy)
    assert state == f"reconciled_known_seed:{old_template}->{current_template}"
    assert registry.template_id == current_template

    current = SimpleNamespace(tool_name=tool_name, enabled=True, profile_id="remote-worker",
                              template_id=current_template)
    assert driver._verify_or_reconcile_tool_registry(
        current, action_id=action_id, tool_name=tool_name,
        template_id=current_template, legacy_template=None) == "verified"

    invalid_rows = [
        (SimpleNamespace(tool_name=tool_name, enabled=False, profile_id="remote-worker",
                         template_id=old_template), legacy),
        (SimpleNamespace(tool_name=tool_name, enabled=True, profile_id="unexpected",
                         template_id=old_template), legacy),
        (SimpleNamespace(tool_name=tool_name, enabled=True, profile_id="remote-worker",
                         template_id=old_template), None),
        (SimpleNamespace(tool_name=tool_name, enabled=True, profile_id="remote-worker",
                         template_id="unrecognized_template"), legacy),
    ]
    for invalid_registry, invalid_legacy in invalid_rows:
        with pytest.raises(RuntimeError, match="ToolRegistry|conflicts"):
            driver._verify_or_reconcile_tool_registry(
                invalid_registry, action_id=action_id, tool_name=tool_name,
                template_id=current_template, legacy_template=invalid_legacy)


def test_l3_l1_registration_matches_the_migration_028_template_seed():
    import importlib.util

    driver_path = (Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                   / "l3-action" / "run_l3_d7_d1.py")
    spec = importlib.util.spec_from_file_location("gade_l3_driver_template_seed_test", driver_path)
    assert spec is not None and spec.loader is not None
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)

    config = driver.ACTION_CONFIG["http_security_headers.collect.v1"]
    assert config["argv"] == [
        "builtin:http-security-headers", "{canonical_url}", "HEAD", "/",
        "M2A-Worker/1", "10",
    ]
    assert config["allowed_fields"] == ["canonical_url"]
    assert driver.ACTION_TEMPLATES["http_security_headers.collect.v1"] == "http_security_headers_v2"

    repo = Path(__file__).resolve().parents[1]
    migration_026 = (repo / "initdb" / "026_remote_evidence_tools.sql").read_text(encoding="utf-8")
    migration_028 = (repo / "initdb" / "028_phase3_batch0_identity.sql").read_text(encoding="utf-8")
    assert "('http_security_headers', TRUE, 'remote-worker', 'http_security_headers_v1'" in migration_026
    assert "('http_security_headers_v2', 'http_security_headers'," in migration_028
    assert """'["builtin:http-security-headers", "{canonical_url}", "HEAD", "/", "M2A-Worker/1", "10"]'::jsonb""" in migration_028
    assert """'["canonical_url"]'::jsonb, 'low', TRUE""" in migration_028
    assert "UPDATE tool_registry" not in migration_028

    catalog = driver.build_action_catalog({item["tool"] for item in driver.ACTION_CONFIG.values()})
    schema = driver._registration_parameter_schemas(catalog)["http_security_headers.collect.v1"]
    assert driver._validated_template_fields(
        "http_security_headers.collect.v1", config, schema) == ["canonical_url"]
    for action_id in ("lab.valid_account_access.v1", "lab.fixed_python_execution.v1"):
        assert driver._validated_template_fields(
            action_id, driver.ACTION_CONFIG[action_id],
            driver._registration_parameter_schemas(catalog)[action_id]) == []


def test_l3_validation_action_reconciles_only_exact_028_compact_l1_schema():
    import importlib.util
    from types import SimpleNamespace
    import pytest

    driver_path = (Path(__file__).resolve().parents[1] / "experiments" / "gade-seven-level-v1"
                   / "l3-action" / "run_l3_d7_d1.py")
    spec = importlib.util.spec_from_file_location("gade_l3_driver_validation_seed_test", driver_path)
    assert spec is not None and spec.loader is not None
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    action_id = "http_security_headers.collect.v1"
    schema = driver._registration_parameter_schemas(driver.build_action_catalog(
        {item["tool"] for item in driver.ACTION_CONFIG.values()}))[action_id]
    row_values = dict(action_id=action_id, tool_name="http_security_headers", phase="discovery",
                      validation_tier=1, execution_identity=driver.ACTION_IDENTITIES[action_id],
                      template_version="http_security_headers_v2", enabled=True)
    legacy = SimpleNamespace(**row_values,
        parameter_schema={"fields": ["target", "host", "port", "protocol", "service",
                                      "scheme", "path", "canonical_url", "collector"]})

    assert driver._verify_or_reconcile_validation_action(
        legacy, action_id=action_id, tool_name="http_security_headers", phase="discovery",
        validation_tier=1, execution_identity=driver.ACTION_IDENTITIES[action_id],
        template_id="http_security_headers_v2", parameter_schema=schema) == "reconciled_known_seed_schema"
    assert legacy.parameter_schema == schema

    current = SimpleNamespace(**row_values, parameter_schema=schema)
    assert driver._verify_or_reconcile_validation_action(
        current, action_id=action_id, tool_name="http_security_headers", phase="discovery",
        validation_tier=1, execution_identity=driver.ACTION_IDENTITIES[action_id],
        template_id="http_security_headers_v2", parameter_schema=schema) == "verified"

    wrong_seed = SimpleNamespace(**row_values, parameter_schema={"fields": ["target"]})
    with pytest.raises(RuntimeError, match="schema conflicts"):
        driver._verify_or_reconcile_validation_action(
            wrong_seed, action_id=action_id, tool_name="http_security_headers", phase="discovery",
            validation_tier=1, execution_identity=driver.ACTION_IDENTITIES[action_id],
            template_id="http_security_headers_v2", parameter_schema=schema)

    wrong_identity = SimpleNamespace(**{**row_values, "validation_tier": 2},
                                     parameter_schema={"fields": ["target"]})
    with pytest.raises(RuntimeError, match="ValidationAction conflicts"):
        driver._verify_or_reconcile_validation_action(
            wrong_identity, action_id=action_id, tool_name="http_security_headers", phase="discovery",
            validation_tier=1, execution_identity=driver.ACTION_IDENTITIES[action_id],
            template_id="http_security_headers_v2", parameter_schema=schema)


def test_l3_rejects_noncanonical_endpoint():
    import pytest
    with pytest.raises(ValueError, match="fixed to the authorized Lab"):
        canonical_action_parameters(action_id=ACTION, target="10.56.66.120", port=PORT,
                                    protocol="tcp", service="http")


def test_l3_worker_performs_fixed_session_bound_execution_without_secret_leak(monkeypatch, caplog):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", f"{TARGET}/32")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_TOOLS", TOOL)
    username, password = "lab-user-only", "unit-test-password-that-is-not-real-0003"
    token = "unit-test-l3-session-token-never-persist-this-value-0003"
    monkeypatch.setenv("GADE_L2_TEST_USERNAME", username)
    monkeypatch.setenv("GADE_L2_TEST_PASSWORD", password)
    payload = make_request()
    case_id = payload["correlation_id"]
    run_id = case_id.rsplit("-", 1)[1]
    calls = []

    class Response:
        def __init__(self, status, body):
            self.status = status
            self._body = body
        def read(self, _limit):
            return self._body

    class FakeConnection:
        def __init__(self, host, port, timeout):
            assert (host, port) == (TARGET, PORT)
            self.path = None
            self.headers = {}
        def request(self, method, path, body=None, headers=None):
            self.method, self.path, self.body, self.headers = method, path, body, headers or {}
            calls.append(self)
        def getresponse(self):
            if self.path == "/lab/auth/login":
                assert self.method == "POST"
                assert json.loads(self.body) == {"username": username, "password": password}
                return Response(200, json.dumps({"session_token": token, "expires_in": 60,
                                                 "test_case_id": case_id}).encode())
            assert self.path == "/lab/execute" and self.method == "POST" and self.body == "{}"
            assert self.headers["Authorization"] == f"Bearer {token}"
            assert self.headers["X-Run-ID"] == run_id
            return Response(200, json.dumps({"status": "completed", "run_id": run_id,
                "test_case_id": case_id, "request_id": payload["request_id"],
                "script_id": SCRIPT_ID, "script_sha256": SCRIPT_SHA,
                "exit_status": 0, "marker_sha256": "a" * 64}).encode())
        def close(self):
            pass

    monkeypatch.setattr(worker.http.client, "HTTPConnection", FakeConnection)
    response = TestClient(worker.app).post("/execute", json=payload)
    body = response.json()
    assert response.status_code == 200 and body["status"] == "completed"
    assert body["parsed_result"]["success"] is True
    assert body["parsed_result"]["process_exit_status"] == 0
    assert body["parsed_result"]["marker_sha256"] == "a" * 64
    assert [item.path for item in calls] == ["/lab/auth/login", "/lab/execute"]
    assert calls[0].headers["X-Request-ID"] == payload["request_id"]
    assert calls[1].headers["X-Test-Case-ID"] == case_id
    serialized = json.dumps(body)
    assert all(secret not in serialized and secret not in caplog.text for secret in (password, token, username))
    assert body["execution_receipt"]["action_success"] is True


def test_l3_worker_never_marks_http200_with_bad_execution_as_success(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", f"{TARGET}/32")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_TOOLS", TOOL)
    monkeypatch.setenv("GADE_L2_TEST_USERNAME", "lab-user-only")
    monkeypatch.setenv("GADE_L2_TEST_PASSWORD", "unit-test-password-that-is-not-real-0004")
    payload = make_request()
    class Response:
        status = 200
        def read(self, _limit):
            if connection.path == "/lab/auth/login":
                return json.dumps({"session_token": "valid-session-token-value-at-least-32", "expires_in": 60,
                                   "test_case_id": payload["correlation_id"]}).encode()
            return json.dumps({"status": "completed", "run_id": payload["correlation_id"].rsplit("-",1)[1],
                "test_case_id": payload["correlation_id"], "request_id": payload["request_id"],
                "script_id": SCRIPT_ID, "script_sha256": SCRIPT_SHA, "exit_status": 9,
                "marker_sha256": "b" * 64}).encode()
    class FakeConnection:
        def __init__(self, *_args, **_kwargs): self.path = None
        def request(self, _method, path, **_kwargs): self.path = path
        def getresponse(self):
            nonlocal connection
            connection = self
            return Response()
        def close(self): pass
    connection = None
    monkeypatch.setattr(worker.http.client, "HTTPConnection", FakeConnection)
    body = TestClient(worker.app).post("/execute", json=payload).json()
    assert body["status"] == "failed"
    assert body["execution_receipt"]["action_success"] is False


def test_l3_action_is_experiment_only(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "shared")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_TOOLS", "")
    assert TOOL not in worker.effective_allowed_tools()
    response = TestClient(worker.app).post("/execute", json=make_request())
    assert response.json()["reason"] == "tool not allowed"


def test_l3_worker_rejects_parameter_drift_before_network(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("KALI_WORKER_ENFORCE_TARGET_SCOPE", "true")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_SCOPES", f"{TARGET}/32")
    monkeypatch.setenv("KALI_WORKER_ALLOWED_TOOLS", TOOL)
    monkeypatch.setattr(worker.http.client, "HTTPConnection", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("network must not be reached")))
    payload = make_request()
    payload["authorization_parameters"]["execute_path"] = "/other"
    body = TestClient(worker.app).post("/execute", json=payload).json()
    assert body["status"] == "rejected"
    assert body["reason"] == "authorization parameter identity mismatch"
