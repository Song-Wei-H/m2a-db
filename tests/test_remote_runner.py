from unittest.mock import patch

import httpx
import pytest

from worker.remote_runner import run_remote_tool
from worker.tool_runner import TaskContext


class TimeoutClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json):
        raise httpx.ReadTimeout("timed out")


@pytest.mark.asyncio
async def test_run_remote_tool_converts_httpx_timeout_to_timeout_error():
    ctx = TaskContext(
        task_id=86,
        target_id=14,
        tool_name="httpx_basic",
        host="198.51.100.13",
        port=443,
        protocol="tcp",
        service="ssl/http",
        open_port_id=17,
        decision_score_id=52,
    )

    with patch("worker.remote_runner.httpx.AsyncClient", TimeoutClient):
        with pytest.raises(TimeoutError) as exc:
            await run_remote_tool(ctx)

    reason = str(exc.value)
    assert "remote tool timeout" in reason
    assert "httpx_basic" in reason
    assert "198.51.100.13" in reason
    assert "port=443" in reason
