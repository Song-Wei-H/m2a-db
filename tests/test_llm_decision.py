from unittest.mock import AsyncMock, MagicMock

import pytest

from app.config import settings
from worker import llm_decision


def test_litellm_decision_uses_controlled_context_and_configured_model(monkeypatch):
    monkeypatch.setattr(settings, "llm_base_url", "http://llm.test/v1")
    monkeypatch.setattr(settings, "llm_model", "openai/qwen3-4b-thinking-2507-heretic")
    monkeypatch.setattr(settings, "llm_api_key", None)
    monkeypatch.setattr(settings, "llm_send_auth", False)
    monkeypatch.setattr(settings, "llm_timeout_seconds", 12.0)

    response = MagicMock()
    response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": (
                        '{"recommended_action":"continue","recommended_tool":"nmap_service",'
                        '"confidence":0.8,"reasoning":["bounded evidence"]}'
                    )
                }
            }
        ]
    }
    monkeypatch.setattr(llm_decision.httpx, "request", MagicMock(return_value=response))

    result = llm_decision.call_litellm({"context_contract": "minimal-decision-context-v1", "match_confidence": 0.9})

    assert result["validated"]["recommended_tool"] == "nmap_service"
    method, url = llm_decision.httpx.request.call_args.args
    request = llm_decision.httpx.request.call_args.kwargs
    assert method == "POST"
    assert url == "http://llm.test/v1/chat/completions"
    assert request["json"]["model"] == "openai/qwen3-4b-thinking-2507-heretic"
    assert request["json"]["temperature"] == 0
    assert request["timeout"] == 12.0
    assert request["trust_env"] is False
    assert "Authorization" not in request["headers"]


def test_litellm_decision_normalizes_string_null_tool(monkeypatch):
    response = MagicMock()
    response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": (
                        '{"recommended_action":"stop","recommended_tool":"null",'
                        '"confidence":0.8,"reasoning":["no further action"]}'
                    )
                }
            }
        ]
    }
    monkeypatch.setattr(llm_decision.httpx, "request", MagicMock(return_value=response))

    result = llm_decision.call_litellm({"match_confidence": 0.9})

    assert result["raw"]["recommended_tool"] == "null"
    assert result["validated"]["recommended_tool"] is None


@pytest.mark.asyncio
async def test_build_payload_includes_unified_enrichment_context_from_snapshot(monkeypatch):
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    session.execute = AsyncMock(return_value=result)
    monkeypatch.setattr(llm_decision, "async_session", lambda: session)
    context = {
        "schema": "m2a-enrichment-context-v1",
        "cve": {"status": "not_evaluated", "best_cve": None, "best_match_confidence": None},
        "osv": {
            "status": "complete",
            "vulnerability_count": 1,
            "trust": "untrusted_external_advisory",
            "evidence_refs": [{"ref": "normalized_results:5", "response_sha256": "b" * 64}],
        },
    }
    decision = MagicMock()
    decision.input_snapshot = {"enrichment_context": context}
    decision.id = 9
    decision.target_id = 2
    decision.open_port_id = 3

    payload = await llm_decision.build_payload(decision)

    assert payload["enrichment_context"] == context
    assert payload["enrichment_context"]["osv"]["evidence_refs"][0]["ref"] == "normalized_results:5"


@pytest.mark.asyncio
async def test_build_payload_back_compat_maps_legacy_parsed_cve_summary(monkeypatch):
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    session.execute = AsyncMock(return_value=result)
    monkeypatch.setattr(llm_decision, "async_session", lambda: session)
    decision = MagicMock()
    decision.input_snapshot = {"parsed_output": {"cve_summary": {"best_cve": "CVE-2024-12345", "max_cvss": 7.5}}}
    decision.id = 10
    decision.target_id = 2
    decision.open_port_id = 3

    payload = await llm_decision.build_payload(decision)

    assert payload["best_cve"] == "CVE-2024-12345"
    assert payload["cvss"] == 7.5
    assert payload["enrichment_context"]["osv"]["status"] == "not_requested"
