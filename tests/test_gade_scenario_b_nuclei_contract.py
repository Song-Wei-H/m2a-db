from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import action_contracts
from kali_worker import app as worker
from worker import evidence_normalizer
from worker.evidence_normalizer import normalize_tool_result
from worker.parsers.nuclei_parser import parse_nuclei_output


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = ROOT / "kali_worker" / "nuclei_templates" / "scenario-b-v1"
TARGET_TRUTH_TEMPLATE = ROOT / "lab" / "mode-b-target" / "nuclei-target-truth-v1.template.json"
TEST_TARGET = "192.0.2.119"


def test_fixed_bundle_and_target_truth_hashes_are_content_verified():
    manifest_bytes = (TEMPLATE_ROOT / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    assert hashlib.sha256(manifest_bytes).hexdigest() == action_contracts.SCENARIO_B_NUCLEI_MANIFEST_SHA256
    truth_template = TARGET_TRUTH_TEMPLATE.read_text(encoding="utf-8")
    assert "__GADE_SCENARIO_B_TARGET_HOST__" in truth_template
    assert "__GADE_SCENARIO_B_SCOPE__" in truth_template
    rendered_truth = truth_template.replace("__GADE_SCENARIO_B_TARGET_HOST__", TEST_TARGET).replace(
        "__GADE_SCENARIO_B_SCOPE__", f"{TEST_TARGET}/32"
    )
    truth_bytes = rendered_truth.encode("utf-8")
    truth_sha256 = hashlib.sha256(truth_bytes).hexdigest()
    other_truth = rendered_truth.replace(TEST_TARGET, "192.0.2.120")
    assert len(truth_sha256) == 64
    assert hashlib.sha256(other_truth.encode("utf-8")).hexdigest() != truth_sha256
    assert manifest["profile_id"] == action_contracts.SCENARIO_B_NUCLEI_PROFILE
    assert manifest["selection_mode"] == "exact-fixed-bundle"
    assert manifest["runtime_loaded_count"] == 2
    assert {row["path"] for row in manifest["templates"]} == set(action_contracts.SCENARIO_B_NUCLEI_TEMPLATE_FILES)
    bundle = "".join(
        f"{name}:{action_contracts.SCENARIO_B_NUCLEI_TEMPLATE_SHA256[name]}\n"
        for name in sorted(action_contracts.SCENARIO_B_NUCLEI_TEMPLATE_FILES)
    )
    assert hashlib.sha256(bundle.encode("utf-8")).hexdigest() == action_contracts.SCENARIO_B_NUCLEI_BUNDLE_SHA256
    for name, expected in action_contracts.SCENARIO_B_NUCLEI_TEMPLATE_SHA256.items():
        assert hashlib.sha256((TEMPLATE_ROOT / name).read_bytes()).hexdigest() == expected
    truth = json.loads(rendered_truth)
    assert truth["target"] == f"{TEST_TARGET}:18080" and truth["scope"] == f"{TEST_TARGET}/32"
    assert truth["positive_control"]["cve_asserted"] is False
    assert truth["negative_control"]["cve_asserted"] is False


def test_scenario_b_contract_and_codex_catalog_are_profile_gated():
    env = os.environ.copy()
    for name in ("GADE_HOME_LAB_EXPLORATORY", "GADE_OFFICE_DOCKER_LAB", "GADE_OFFICE_DOCKER_LAB_TARGET",
                 "GADE_OFFICE_DOCKER_LAB_PORT"):
        env.pop(name, None)
    env["GADE_NUCLEI_PROFILE"] = "scenario-b-fixed-v1"
    env["GADE_L3_PROTOCOL"] = "GADE_BC_D1_D3_EXPLORATORY_V1"
    env["GADE_SCENARIO_B_TARGET_HOST"] = TEST_TARGET
    env["GADE_SCENARIO_B_TARGET_TRUTH_SHA256"] = "a" * 64
    bridge = ROOT / "experiments" / "gade-seven-level-v1" / "l3-action" / "codex_agent_bridge.py"
    code = (
        "import json,sys; from app.action_contracts import *; "
        "from codex_agent_bridge import build_action_catalog; "
        f"p=canonical_action_parameters(action_id='nuclei.safe_scan.v1',target='{TEST_TARGET}',port=18080,protocol='tcp',service='http'); "
        "print(json.dumps({'argv':nuclei_fixed_argv(p['canonical_url']),'parameters':p,'schema':ACTION_PARAMETER_SCHEMAS['nuclei.safe_scan.v1'],"
        "'template':ACTION_TEMPLATES['nuclei.safe_scan.v1'],'catalog':[x['action_id'] for x in build_action_catalog(['nuclei_safe'])]}))"
    )
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(bridge.parent), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, text=True, capture_output=True, check=True)
    payload = json.loads(result.stdout)
    assert payload["template"] == "nuclei_safe_scenario_b_v1"
    assert payload["parameters"]["template_ids"] == list(action_contracts.SCENARIO_B_NUCLEI_TEMPLATE_IDS)
    assert payload["parameters"]["severity_selector"] == "info"
    assert payload["argv"] == [
        "nuclei", "-u", f"http://{TEST_TARGET}:18080/", "-t", action_contracts.SCENARIO_B_NUCLEI_TEMPLATE_DIR,
        "-severity", "info", "-rl", "2", "-c", "1", "-bs", "1", "-timeout", "5",
        "-retries", "0", "-duc", "-ni", "-jsonl", "-silent", "-no-color",
    ]
    assert payload["catalog"] == ["nuclei.safe_scan.v1"]
    assert all("const" in schema for schema in payload["schema"]["properties"].values())

    env.pop("GADE_NUCLEI_PROFILE", None)
    unprofiled = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    assert unprofiled.returncode != 0  # D1 ScenarioBC intentionally requires the fixed B profile.


def _scenario_b_raw(findings: list[dict] | None = None) -> str:
    if findings is None:
        findings = [
            {"template-id": "gade-b-positive-backup-index-v1", "info": {"name": "positive", "severity": "info"},
             "type": "http", "matched-at": "http://192.0.2.119:18080/backup/", "matcher-name": "status-and-index-marker"},
            {"template-id": "gade-b-negative-control-v1", "info": {"name": "negative", "severity": "info"},
             "type": "http", "matched-at": "http://192.0.2.119:18080/lab/nuclei-negative-control", "matcher-name": "status-and-negative-marker"},
        ]
    return "\n".join(json.dumps(row, separators=(",", ":")) for row in findings) + "\n"


def test_parser_requires_exact_positive_negative_pair(monkeypatch):
    monkeypatch.setenv("GADE_NUCLEI_PROFILE", "scenario-b-fixed-v1")
    monkeypatch.setenv("GADE_SCENARIO_B_TARGET_HOST", TEST_TARGET)
    monkeypatch.setattr(action_contracts, "SCENARIO_B_NUCLEI_PROFILE_ENABLED", True)
    monkeypatch.setattr(action_contracts, "SCENARIO_B_NUCLEI_TARGET", TEST_TARGET)
    monkeypatch.setattr(evidence_normalizer, "SCENARIO_B_NUCLEI_PROFILE_ENABLED", True)
    raw = _scenario_b_raw()
    parsed = parse_nuclei_output(raw, host="192.0.2.119", port=18080)
    assert parsed["success"] is True
    assert parsed["parser_success"] is True
    assert parsed["profile_id"] == action_contracts.SCENARIO_B_NUCLEI_PROFILE
    assert {item["template_id"] for item in parsed["findings"]} == set(action_contracts.SCENARIO_B_NUCLEI_TEMPLATE_IDS)

    missing = parse_nuclei_output(_scenario_b_raw().splitlines()[0] + "\n", host="192.0.2.119", port=18080)
    assert missing["parser_success"] is False
    duplicate_rows = json.loads(_scenario_b_raw().splitlines()[0])
    duplicate = parse_nuclei_output(_scenario_b_raw([duplicate_rows, duplicate_rows]), host="192.0.2.119", port=18080)
    assert duplicate["parser_success"] is False


def test_scenario_b_normalizer_emits_only_synthetic_pair_and_fails_closed(monkeypatch):
    monkeypatch.setenv("GADE_NUCLEI_PROFILE", "scenario-b-fixed-v1")
    monkeypatch.setenv("GADE_SCENARIO_B_TARGET_HOST", TEST_TARGET)
    monkeypatch.setattr(action_contracts, "SCENARIO_B_NUCLEI_PROFILE_ENABLED", True)
    monkeypatch.setattr(action_contracts, "SCENARIO_B_NUCLEI_TARGET", TEST_TARGET)
    monkeypatch.setattr(evidence_normalizer, "SCENARIO_B_NUCLEI_PROFILE_ENABLED", True)
    raw = _scenario_b_raw()
    parsed = parse_nuclei_output(raw, host="192.0.2.119", port=18080)
    ctx = SimpleNamespace(host="192.0.2.119", port=18080, service="http", target="192.0.2.119")
    evidence = normalize_tool_result("nuclei_safe", parsed, raw, ctx=ctx, tool_result_id=42)
    assert [row["evidence_type"] for row in evidence] == [
        "synthetic_configuration_candidate", "synthetic_negative_control_observed"
    ]
    assert all(row["details"]["cve"] is None for row in evidence)
    assert all(row["evidence_ref"] == "tool_result:42" for row in evidence)
    assert all(row["details"]["template_bundle_sha256"] == action_contracts.SCENARIO_B_NUCLEI_BUNDLE_SHA256 for row in evidence)

    invalid = deepcopy(parsed)
    invalid["findings"].pop()
    with pytest.raises(ValueError, match="incomplete"):
        normalize_tool_result("nuclei_safe", invalid, raw, ctx=ctx, tool_result_id=42)
    invalid = deepcopy(parsed)
    invalid["findings"][0]["url"] = "http://192.0.2.120:18080/backup/"
    with pytest.raises(ValueError, match="fixed non-CVE contract"):
        normalize_tool_result("nuclei_safe", invalid, raw, ctx=ctx, tool_result_id=42)
    invalid = deepcopy(parsed)
    invalid["findings"][0]["cve_ids"] = ["CVE-2025-12345"]
    with pytest.raises(ValueError, match="fixed non-CVE contract"):
        normalize_tool_result("nuclei_safe", invalid, raw, ctx=ctx, tool_result_id=42)


def test_worker_keeps_nuclei_disabled_until_exact_fixed_bundle_is_verified(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "false")
    monkeypatch.setenv("GADE_NUCLEI_PROFILE", "scenario-b-fixed-v1")
    assert worker.nuclei_action_state()[0] is False

    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "true")
    monkeypatch.setenv("GADE_NUCLEI_PROFILE", "unknown-profile")
    assert worker.nuclei_action_state()[0] is False

    manifest_path = TEMPLATE_ROOT / "manifest.json"
    monkeypatch.setattr(worker, "SCENARIO_B_NUCLEI_MANIFEST_PATH", str(manifest_path))
    monkeypatch.setattr(worker, "SCENARIO_B_NUCLEI_TEMPLATE_DIR", str(TEMPLATE_ROOT))
    monkeypatch.setenv("GADE_NUCLEI_PROFILE", "scenario-b-fixed-v1")
    monkeypatch.setenv("GADE_NUCLEI_TEMPLATE_MANIFEST", str(manifest_path))
    monkeypatch.setenv("GADE_NUCLEI_TEMPLATES_DIR", str(TEMPLATE_ROOT))
    assert worker.nuclei_action_state() == (True, None)

    original_read_bytes = Path.read_bytes
    tampered_path = TEMPLATE_ROOT / action_contracts.SCENARIO_B_NUCLEI_TEMPLATE_FILES[0]

    def read_tampered_template(path):
        if path.resolve() == tampered_path.resolve():
            return b"tampered"
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read_tampered_template)
    assert worker.nuclei_action_state()[0] is False
