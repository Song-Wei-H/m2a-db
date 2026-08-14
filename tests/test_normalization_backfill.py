from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from worker.normalization_backfill import backfill_nmap_normalized_results


class ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalars(self):
        return self

    def all(self):
        return self.value


class SessionContext:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *args):
        return False


@pytest.mark.asyncio
async def test_backfill_creates_missing_nmap_normalized_result_once():
    result = SimpleNamespace(
        id=126,
        open_port_id=None,
        parsed_output={"ports": [{"port": 443, "protocol": "tcp", "service": "ssl/http", "product": "nginx", "version": None}]},
        raw_output="443/tcp open ssl/http nginx",
    )
    session = MagicMock()
    session.get = AsyncMock(return_value=SimpleNamespace(target="10.56.67.13"))
    session.execute = AsyncMock(return_value=ScalarResult([result]))
    session.scalar = AsyncMock(return_value=None)
    session.add = MagicMock()
    session.begin = MagicMock(return_value=SessionContext(session))

    with patch("worker.normalization_backfill.async_session", return_value=SessionContext(session)):
        created = await backfill_nmap_normalized_results(29)

    assert created == 1
    normalized = session.add.call_args.args[0]
    assert normalized.tool_result_id == 126
    assert normalized.evidence_type == "network_service"
