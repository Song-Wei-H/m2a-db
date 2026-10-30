import importlib.util
from pathlib import Path
from types import SimpleNamespace


def test_office_l2_legacy_case_identity_is_bounded_and_fail_closed(monkeypatch):
    target_dir = Path(__file__).resolve().parents[1] / "lab" / "mode-b-target"
    spec = importlib.util.spec_from_file_location("gade_office_l2_identity", target_dir / "l2_auth.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "BLUE_OBSERVER_REQUIRED", True)

    def identity(path, case_id, run_id=""):
        context = SimpleNamespace()
        handler = SimpleNamespace(path=path, headers={
            "X-Request-ID": "request-123", "X-Test-Case-ID": case_id,
            "X-Run-ID": run_id}, state=SimpleNamespace(event_context=context))
        value = module.Handler._identity(handler)
        return value, getattr(context, "run_id", None)

    case = "GADE-L3-MULTI-A-R02-860e280cae6e"
    assert identity("/lab/auth/login", case) == (("request-123", case), "860e280cae6e")
    assert identity("/lab/protected", case) == (("request-123", case), "860e280cae6e")
    assert identity("/lab/execute", case) == (("request-123", case), "")
    assert identity("/lab/auth/login", "unbound-case") == (None, None)
    assert identity("/lab/auth/login", case, "bad run id") == (None, None)
    assert identity("/lab/auth/login", case, "explicit-run") == (("request-123", case), "explicit-run")


def test_target_emits_to_fixed_blue_observer_ingest_endpoint(monkeypatch):
    target_dir = Path(__file__).resolve().parents[1] / "lab" / "mode-b-target"
    spec = importlib.util.spec_from_file_location(
        "gade_office_target_l2_auth", target_dir / "l2_auth.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "COMPONENT_API_KEY", "c" * 48)
    monkeypatch.setattr(module, "BLUE_OBSERVER_KEY", "b" * 48)
    seen = {}

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size):
            return b'{"accepted":true,"alert_ids":["synthetic-alert"]}'

    class Opener:
        def open(self, request, timeout):
            seen["url"] = request.full_url
            seen["timeout"] = timeout
            return Response()

    def build_opener(*handlers):
        seen["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(module.urllib.request, "build_opener", build_opener)
    value = module.component_request(
        module.BLUE_OBSERVER_URL.rsplit("/", 1)[0], "/ingest", method="POST",
        run_id="0123456789ab", case_id="GADE-A-D7-ENGINEERING-0123456789ab",
        request_id="request-0123456789ab",
        body={"source": "target", "event": {"simulation": True}}, observer=True)

    assert value["accepted"] is True
    assert seen["url"] == "http://blue-observer:8090/ingest"
    assert seen["timeout"] == 3
    assert any(isinstance(handler, module.NoRedirect) for handler in seen["handlers"])
