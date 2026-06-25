from types import SimpleNamespace

import pytest

from worker.learning_context import LearningContext
from worker.learning_statistics import LearningStatisticsProvider


class FakeResult:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def first(self):
        return self.rows[0] if self.rows else None


class FakeSession:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    async def execute(self, statement, params=None):
        self.calls.append((str(statement), params or {}))
        return FakeResult(self.rows)


def row(**values):
    return SimpleNamespace(_mapping=values)


@pytest.mark.asyncio
async def test_learning_statistics_reads_context_view():
    context = LearningContext.from_target(
        open_port=SimpleNamespace(port=443, service="https"),
        evidence={"evidence_type": "http_service"},
    )
    provider = LearningStatisticsProvider(
        FakeSession(
            [
                row(
                    tool_name="httpx_basic",
                    service="https",
                    evidence_type="http_service",
                    port_bucket="web",
                    total_runs=10,
                    success_count=9,
                    failure_count=1,
                    success_rate=0.9,
                    avg_learning_score=0.82,
                    last_seen="now",
                )
            ]
        )
    )

    stats = await provider.get_tool_statistics(context)
    assert stats["httpx_basic"]["success_rate"] == 0.9
    assert await provider.get_tool_success_rate("httpx_basic", context) == 0.9
    assert await provider.get_average_learning_score("httpx_basic", context) == 0.82
    assert await provider.get_total_observations(context) == 10


@pytest.mark.asyncio
async def test_learning_statistics_defaults_when_no_rows():
    provider = LearningStatisticsProvider(FakeSession([]))

    assert await provider.get_tool_success_rate("nuclei_safe") == 0.5
    assert await provider.get_average_learning_score("nuclei_safe") == 0.5
    assert await provider.get_total_observations() == 0
