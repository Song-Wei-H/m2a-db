from types import SimpleNamespace

import pytest

from worker.analysis_pipeline import _build_learning_metadata


class BrokenSession:
    async def get(self, model, row_id):
        return SimpleNamespace(port=443, service="https") if row_id else None

    async def execute(self, *args, **kwargs):
        raise RuntimeError("view unavailable")


@pytest.mark.asyncio
async def test_learning_metadata_falls_back_to_deterministic_ranking():
    metadata = await _build_learning_metadata(
        session=BrokenSession(),
        target_id=1,
        open_port_id=1,
        previous_tool="httpx_basic",
        evidence={"evidence_type": "http_service"},
        candidate_tools=["nuclei_safe"],
        waf_detected=False,
    )

    assert metadata["selection_strategy"] == "DeterministicRanking"
    assert metadata["candidate_tools"] == ["nuclei_safe"]
    assert metadata["tool_rank_scores"][0]["tool_name"] == "nuclei_safe"
