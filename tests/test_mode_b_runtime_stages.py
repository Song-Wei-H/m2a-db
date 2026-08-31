from types import SimpleNamespace

import pytest

from app.action_contracts import ACTION_IDENTITIES, ACTION_TEMPLATES
from app.execution_governance import canonical_parameters
from app.models import Target
from scripts.analyze_mode_b_preflight import run_claim_stage


def action(action_id):
    return SimpleNamespace(
        action_id=action_id,
        validation_tier=1,
        execution_identity=ACTION_IDENTITIES[action_id],
        template_version=ACTION_TEMPLATES[action_id],
    )


def proposal(action_id, *, target, port, service):
    return {
        "selected_action": action_id,
        "proposed_parameters": canonical_parameters(
            target=target, port=port, protocol="tcp", service=service,
            action_id=action_id,
        ),
        "reason": "runtime stage regression",
        "confidence": 0.8,
    }


@pytest.mark.asyncio
async def test_mode_b_replay_stage_allows_baseline_and_blocks_second_claim():
    action_id = "httpx.web_probe.v1"
    result = await run_claim_stage(
        scenario={"scenario_id": "B11-REPLAY"},
        proposal=proposal(action_id, target="web.example", port=80, service="http"),
        action=action(action_id),
        target=Target(id=71, target="web.example", scope="web.example"),
    )
    assert result == {
        "stage": "replay", "baseline_claimed": True,
        "attack_claimed": False, "blocked": True,
    }


@pytest.mark.asyncio
async def test_mode_b_expiry_stage_blocks_claim_after_clock_advance():
    action_id = "tls.certificate_collect.v1"
    result = await run_claim_stage(
        scenario={"scenario_id": "B12-EXPIRY"},
        proposal=proposal(action_id, target="tls.example", port=443, service="tls"),
        action=action(action_id),
        target=Target(id=72, target="tls.example", scope="tls.example"),
    )
    assert result == {
        "stage": "expiry", "baseline_claimed": None,
        "attack_claimed": False, "blocked": True,
    }
