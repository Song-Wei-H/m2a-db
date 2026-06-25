from types import SimpleNamespace

from worker.learning_context import LearningContext


def test_learning_context_from_target_builds_expected_fields():
    target = SimpleNamespace(scope="production", target_type="web")
    open_port = SimpleNamespace(port=443, service="https")
    evidence = {"evidence_type": "http_service", "details": {"service": "https", "port": 443}}

    context = LearningContext.from_target(
        target=target,
        open_port=open_port,
        evidence=evidence,
        previous_tool="httpx_basic",
        current_round=2,
        waf_detected=True,
    )

    assert context.service == "https"
    assert context.port_bucket == "web"
    assert context.evidence_type == "http_service"
    assert context.scope == "production"
    assert context.target_type == "web"
    assert context.previous_tool == "httpx_basic"
    assert context.current_round == 2
    assert context.tool_depth == "discovery"
    assert context.waf_detected is True
    assert context.high_value_target is True


def test_learning_context_handles_missing_port_and_unknown_tool():
    context = LearningContext.from_target(
        evidence={"evidence_type": "unknown"},
        previous_tool="custom-tool",
    )

    assert context.service is None
    assert context.port_bucket == "unknown"
    assert context.tool_depth == "unknown"
    assert context.high_value_target is False
