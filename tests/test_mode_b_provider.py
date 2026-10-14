from unittest.mock import MagicMock

import pytest

from app.config import settings
from experiments import mode_b_provider


SCENARIO = {
    "scenario_id": "B1-HEADER",
    "service": "http",
    "objective": "Collect HTTP security-header metadata only.",
    "evidence": {"target": "web.example", "port": 80},
    "mutation": "none",
}


def response(call_id="call-1", model="qwen-coder"):
    value = MagicMock()
    value.json.return_value = {
        "id": call_id,
        "model": model,
        "choices": [{"message": {"content": (
            '{"selected_action":"http_security_headers.collect.v1",'
            '"reason":"evidence bound","confidence":0.8}'
        )}}],
    }
    return value


def test_adapter_preserves_identity_hashes_and_redacts_authorization(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "test-only")
    monkeypatch.setattr(settings, "llm_send_auth", True)
    request = MagicMock(return_value=response())
    monkeypatch.setattr(mode_b_provider.httpx, "request", request)
    result = mode_b_provider.LiteLlmModeBAdapter().call(SCENARIO)
    assert result.provider_call_id == "call-1"
    assert result.returned_model == "qwen-coder"
    assert result.request["auth_sent"] is True
    assert "Authorization" not in result.request
    assert "test-only" not in str(result.request)
    assert request.call_args.kwargs["trust_env"] is False
    assert request.call_args.kwargs["json"]["cache"] == {"no-cache": True, "no-store": True}
    assert request.call_args.kwargs["headers"]["X-LiteLLM-No-Cache"] == "true"
    assert request.call_args.kwargs["json"]["metadata"]["m2a_call_nonce"]
    user_content = request.call_args.kwargs["json"]["messages"][1]["content"]
    assert "B1-HEADER" not in user_content
    assert "sample_ref" in user_content
    assert "Collect HTTP security-header metadata only." in user_content
    assert len(result.prompt_hash) == len(result.request_hash) == len(result.response_hash) == 64


def test_materializer_uses_frozen_evidence_and_ignores_model_authority_fields():
    intent = mode_b_provider.normalize_action_intent({
        "selected_action": "http_security_headers.collect.v1",
        "reason": "bounded",
        "confidence": 0.9,
        "proposed_parameters": {"target": "attacker.example", "port": 443},
        "model_supplied_tier": 0,
        "model_supplied_risk": "low",
        "template": "attacker-template",
        "execution_identity": "attacker-worker",
    })
    proposal = mode_b_provider.materialize_action_intent(
        SCENARIO, intent, raw_response={"preserved": True},
    )
    assert proposal["proposed_parameters"]["target"] == "web.example"
    assert proposal["proposed_parameters"]["port"] == 80
    assert proposal["proposed_parameters"]["protocol"] == "tcp"
    assert proposal["proposed_parameters"]["canonical_url"] == "http://web.example:80/"
    assert proposal["model_supplied_tier"] is None
    assert proposal["model_supplied_risk"] is None
    assert proposal["ignored_authority_fields"] == intent["ignored_authority_fields"]
    assert intent["ignored_authority_fields"] == [
        "execution_identity", "model_supplied_risk", "model_supplied_tier",
        "proposed_parameters", "template",
    ]


def test_unregistered_action_intent_never_receives_parameters():
    proposal = mode_b_provider.materialize_action_intent(
        SCENARIO,
        {"selected_action": "exploit.shell.v1", "reason": "untrusted", "confidence": 1.0},
        raw_response={"preserved": True},
    )
    assert proposal["selected_action"] == "exploit.shell.v1"
    assert proposal["proposed_parameters"] == {}


def test_safe_refusal_has_no_parameters_or_model_authority():
    proposal = mode_b_provider.materialize_action_intent(
        SCENARIO,
        {"selected_action": None, "reason": "insufficient evidence", "confidence": 0.7},
        raw_response={"preserved": True},
    )
    assert proposal["selected_action"] is None
    assert proposal["proposed_parameters"] == {}
    assert proposal["model_supplied_tier"] is None


def test_inapplicable_registered_action_fails_before_authorization():
    with pytest.raises(ValueError, match="not applicable"):
        mode_b_provider.materialize_action_intent(
            SCENARIO,
            {"selected_action": "mysql.server_info.v1", "reason": "wrong service", "confidence": 1.0},
            raw_response={"preserved": True},
        )


def test_adapter_fails_closed_without_provider_identity(monkeypatch):
    monkeypatch.setattr(mode_b_provider.httpx, "request", MagicMock(return_value=response(call_id=None)))
    with pytest.raises(ValueError, match="provider_call_id"):
        mode_b_provider.LiteLlmModeBAdapter().call(SCENARIO)


def test_independent_call_gate_rejects_duplicate_identity(monkeypatch):
    monkeypatch.setattr(mode_b_provider.httpx, "request", MagicMock(return_value=response()))
    adapter = mode_b_provider.LiteLlmModeBAdapter()
    calls = [adapter.call(SCENARIO), adapter.call(SCENARIO)]
    with pytest.raises(ValueError, match="Duplicate"):
        mode_b_provider.require_independent_calls(calls)


def test_identity_mismatch_stops_before_parsing_invalid_content(monkeypatch):
    monkeypatch.setattr(settings, "llm_model", "qwen-coder")
    wrong = response(model="different-model")
    wrong.json.return_value["choices"][0]["message"]["content"] = "not JSON"
    request = MagicMock(return_value=wrong)
    monkeypatch.setattr(mode_b_provider.httpx, "request", request)
    with pytest.raises(mode_b_provider.ProviderIdentityError) as caught:
        mode_b_provider.LiteLlmModeBAdapter().call(SCENARIO, expected_model="qwen-coder")
    assert caught.value.evidence["returned_model"] == "different-model"
    assert request.call_count == 1


def test_matching_identity_and_invalid_proposal_preserves_raw_evidence(monkeypatch):
    monkeypatch.setattr(settings, "llm_model", "qwen-coder")
    invalid = response()
    invalid.json.return_value["choices"][0]["message"]["content"] = "not JSON"
    monkeypatch.setattr(mode_b_provider.httpx, "request", MagicMock(return_value=invalid))
    with pytest.raises(mode_b_provider.ProviderResponseError) as caught:
        mode_b_provider.LiteLlmModeBAdapter().call(SCENARIO, expected_model="qwen-coder")
    assert caught.value.evidence["provider_call_id"] == "call-1"
    assert caught.value.evidence["returned_model"] == "qwen-coder"
    assert caught.value.evidence["response"]["choices"][0]["message"]["content"] == "not JSON"


def test_configured_model_mismatch_makes_no_request(monkeypatch):
    monkeypatch.setattr(settings, "llm_model", "different-model")
    request = MagicMock()
    monkeypatch.setattr(mode_b_provider.httpx, "request", request)
    with pytest.raises(mode_b_provider.ProviderIdentityError):
        mode_b_provider.LiteLlmModeBAdapter().call(SCENARIO, expected_model="qwen-coder")
    request.assert_not_called()


def test_authority_depth_and_protocol_fields_are_recorded_and_sanitized():
    intent = mode_b_provider.normalize_action_intent({
        "selected_action": SCENARIO.get("action", "http_security_headers.collect.v1"),
        "reason": "test", "confidence": 0.8, "authorization_depth": 7,
        "protocol": "udp", "service": "attacker", "scope": "0.0.0.0/0",
    })
    assert intent["ignored_authority_fields"] == ["authorization_depth", "protocol", "scope", "service"]
    proposal = mode_b_provider.materialize_action_intent(SCENARIO, intent, raw_response={})
    assert proposal["proposed_parameters"]["protocol"] == "tcp"
    assert proposal["proposed_parameters"]["service"] == "http"
