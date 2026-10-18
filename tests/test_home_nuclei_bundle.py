"""The approved home-only Nuclei bundle is a single immutable safe template."""

import json
import os
import subprocess
import sys
from pathlib import Path

from app import action_contracts as contracts
from kali_worker import app as worker
from worker.evidence_normalizer import normalize_tool_result
from worker.parsers.nuclei_parser import parse_nuclei_output


ROOT = Path(__file__).resolve().parents[1] / "home-lab"


def test_approved_home_bundle_is_hash_exact_and_single_template(monkeypatch):
    manifest = json.loads((ROOT / "approved-nuclei-templates.json").read_text(encoding="utf-8"))
    assert manifest["approval_scope"] == "HOME_LAB_EXPLORATORY_B_ENGINEERING_ONLY"
    assert len(manifest["templates"]) == 1
    assert manifest["templates"][0]["path"] == "gade-home-exposed-backup-index.yaml"
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "true")
    monkeypatch.setenv("GADE_NUCLEI_TEMPLATE_MANIFEST", str(ROOT / "approved-nuclei-templates.json"))
    monkeypatch.setenv("GADE_NUCLEI_TEMPLATES_DIR", str(ROOT / "nuclei-templates"))
    assert worker.nuclei_action_state() == (True, None)


def test_home_nuclei_bundle_fails_closed_when_not_enabled(monkeypatch):
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "false")
    available, reason = worker.nuclei_action_state()
    assert available is False
    assert "unavailable" in reason


def test_home_nuclei_argv_is_exactly_the_approved_template(monkeypatch):
    monkeypatch.setattr(contracts, "HOME_LAB_EXPLORATORY", True)
    url = "http://127.0.0.1:18080"
    argv = contracts.nuclei_fixed_argv(url)
    assert argv[:5] == ["nuclei", "-u", url, "-t", contracts.HOME_NUCLEI_TEMPLATE_PATH]
    assert argv[-3:] == ["-duc", "-ni", "-auth=false"]
    assert argv.count("-t") == 1


def test_home_nuclei_identity_fits_existing_database_column():
    env = {**os.environ, "GADE_HOME_LAB_EXPLORATORY": "1"}
    identity = subprocess.check_output(
        [sys.executable, "-c", "from app.action_contracts import NUCLEI_IDENTITY; print(NUCLEI_IDENTITY)"],
        cwd=ROOT.parent, env=env, text=True,
    ).strip()
    assert len(identity) <= 255
    assert contracts.HOME_NUCLEI_TEMPLATE_SHA256 in identity


def test_home_nuclei_manifest_must_match_contract_path_and_hash(monkeypatch, tmp_path):
    template_dir = tmp_path / "approved"
    template_dir.mkdir()
    template = template_dir / "gade-home-exposed-backup-index.yaml"
    template.write_bytes((ROOT / "nuclei-templates" / template.name).read_bytes())
    manifest = tmp_path / "approved.json"
    manifest.write_bytes((ROOT / "approved-nuclei-templates.json").read_bytes())
    monkeypatch.setattr(worker, "HOME_LAB_EXPLORATORY", True)
    monkeypatch.setattr(worker, "HOME_NUCLEI_TEMPLATE_PATH", str(template))
    monkeypatch.setenv("KALI_WORKER_PROFILE", "gade-experiment")
    monkeypatch.setenv("GADE_NUCLEI_ACTION_ENABLED", "true")
    monkeypatch.setenv("GADE_NUCLEI_TEMPLATE_MANIFEST", str(manifest))
    monkeypatch.setenv("GADE_NUCLEI_TEMPLATES_DIR", str(template_dir))
    assert worker.nuclei_action_state() == (True, None)
    monkeypatch.setattr(worker, "HOME_NUCLEI_TEMPLATE_SHA256", "0" * 64)
    available, reason = worker.nuclei_action_state()
    assert available is False and "Action Contract" in reason


def test_synthetic_match_is_a_candidate_not_a_confirmed_cve():
    raw = "[gade-home-exposed-backup-index] [http] [high] http://127.0.0.1:18080/backup/\n"
    parsed = parse_nuclei_output(raw, success=True, host="127.0.0.1", port=18080)
    rows = normalize_tool_result("nuclei_safe", parsed, raw, tool_result_id=7)
    assert len(rows) == 1
    assert rows[0]["evidence_type"] == "synthetic_configuration_candidate"
    assert rows[0]["details"]["cve"] is None
    assert rows[0]["details"]["real_world_impact"] == "NOT_ESTABLISHED"
