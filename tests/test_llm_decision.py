from unittest.mock import MagicMock

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
    monkeypatch.setattr(llm_decision.httpx, "post", MagicMock(return_value=response))

    result = llm_decision.call_litellm({"context_contract": "minimal-decision-context-v1", "match_confidence": 0.9})

    assert result["validated"]["recommended_tool"] == "nmap_service"
    url = llm_decision.httpx.post.call_args.args[0]
    request = llm_decision.httpx.post.call_args.kwargs
    assert url == "http://llm.test/v1/chat/completions"
    assert request["json"]["model"] == "openai/qwen3-4b-thinking-2507-heretic"
    assert request["json"]["temperature"] == 0
    assert request["timeout"] == 12.0
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
    monkeypatch.setattr(llm_decision.httpx, "post", MagicMock(return_value=response))

    result = llm_decision.call_litellm({"match_confidence": 0.9})

    assert result["raw"]["recommended_tool"] == "null"
    assert result["validated"]["recommended_tool"] is None
