import importlib.util
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]


def _target_module(monkeypatch):
    monkeypatch.setenv("GADE_WORKER_INGRESS_AUTH_REQUIRED", "1")
    path = ROOT / "lab" / "mode-b-target" / "l2_auth.py"
    spec = importlib.util.spec_from_file_location("gade_office_l2_auth_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _worker_module():
    from kali_worker import app as worker

    return worker


def _state(target):
    return target.AuthState(
        "synthetic-user", "synthetic-test-password-0123456789",
        "synthetic-reset-key-0123456789",
        enable_l4=True, enable_advanced=True,
    )


def test_office_worker_proof_matches_target_and_nonce_is_one_use(monkeypatch):
    target = _target_module(monkeypatch)
    worker = _worker_module()
    state = _state(target)
    run_id = "0123456789ab"
    case_id = "GADE-A-D7-ENGINEERING-0123456789ab"
    request_id = str(uuid4())
    now = 1_798_000_000
    nonce = "a" * 32
    headers = {
        "X-Run-ID": run_id,
        **worker.gade_office_worker_ingress_headers(
            "synthetic-test-password-0123456789", "POST", "/lab/l4/role-lease",
            run_id, case_id, request_id, now_epoch=now, nonce=nonce,
        ),
    }

    assert state.verify_worker_ingress(
        "POST", "/lab/l4/role-lease", request_id, case_id, headers, now_epoch=now,
    )
    assert not state.verify_worker_ingress(
        "POST", "/lab/l4/role-lease", request_id, case_id, headers, now_epoch=now,
    )


def test_office_worker_proof_binds_route_run_case_and_request(monkeypatch):
    target = _target_module(monkeypatch)
    worker = _worker_module()
    state = _state(target)
    run_id = "0123456789ab"
    case_id = "GADE-A-D7-ENGINEERING-0123456789ab"
    request_id = str(uuid4())
    now = 1_798_000_000
    headers = {
        "X-Run-ID": run_id,
        **worker.gade_office_worker_ingress_headers(
            "synthetic-test-password-0123456789", "POST", "/lab/advanced/l5-canary",
            run_id, case_id, request_id, now_epoch=now, nonce="b" * 32,
        ),
    }

    assert not state.verify_worker_ingress(
        "POST", "/lab/advanced/l5-visibility", request_id, case_id, headers,
        now_epoch=now,
    )
    assert not state.verify_worker_ingress(
        "POST", "/lab/advanced/l5-canary", request_id, case_id + "-other", headers,
        now_epoch=now,
    )
    assert not state.verify_worker_ingress(
        "POST", "/lab/advanced/l5-canary", str(uuid4()), case_id, headers,
        now_epoch=now,
    )


def test_office_worker_proof_fails_closed_for_missing_or_stale_values(monkeypatch):
    target = _target_module(monkeypatch)
    worker = _worker_module()
    state = _state(target)
    request_id = str(uuid4())
    case_id = "GADE-A-D7-ENGINEERING-0123456789ab"
    headers = {"X-Run-ID": "0123456789ab"}

    assert not state.verify_worker_ingress(
        "POST", "/lab/advanced/l7-c2", request_id, case_id, headers,
        now_epoch=1_798_000_000,
    )
    stale_timestamp = 1_798_000_000 - target.WORKER_INGRESS_TIMESTAMP_SKEW_SECONDS - 1
    stale_headers = {
        "X-Run-ID": "0123456789ab",
        **worker.gade_office_worker_ingress_headers(
            "synthetic-test-password-0123456789", "POST", "/lab/advanced/l7-c2",
            "0123456789ab", case_id, request_id, now_epoch=stale_timestamp,
            nonce="c" * 32,
        ),
    }
    assert not state.verify_worker_ingress(
        "POST", "/lab/advanced/l7-c2", request_id, case_id, stale_headers,
        now_epoch=1_798_000_000,
    )


def test_office_gateway_acl_is_transport_only_and_forwards_proof_headers():
    config = (ROOT / "lab" / "mode-b-target" / "nginx.gade-a-d7.conf.template").read_text(
        encoding="utf-8"
    )
    lab_location = config.split("location ^~ /lab/ {", 1)[1].split("}", 1)[0]

    assert "allow __GADE_A_D7_INGRESS_GATEWAY__;" in lab_location
    assert "deny all;" in lab_location
    root_location = config.split("location / {", 1)[1].split("}", 1)[0]
    assert "allow __GADE_A_D7_INGRESS_GATEWAY__;" in root_location
    assert "deny all;" in root_location
    assert 'proxy_set_header X-GADE-Worker-Timestamp $http_x_gade_worker_timestamp;' in lab_location
    assert 'proxy_set_header X-GADE-Worker-Nonce $http_x_gade_worker_nonce;' in lab_location
    assert 'proxy_set_header X-GADE-Worker-Signature $http_x_gade_worker_signature;' in lab_location
