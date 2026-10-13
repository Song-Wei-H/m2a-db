"""Read-only reverse reconstruction of one ToolResult execution chain."""
from __future__ import annotations

import argparse
import asyncio
import json

from app.database import async_session
from app.execution_trace import trace_tool_result


async def _main(result_id: int) -> int:
    async with async_session() as db:
        trace = await trace_tool_result(db, result_id)
    print(json.dumps(trace, ensure_ascii=False, indent=2, default=str))
    return 2 if trace["status"] == "NOT_FOUND" else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Trace ToolResult -> ToolTask -> authorization -> proposal -> evidence"
    )
    parser.add_argument("result_id", type=int)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_main(args.result_id)))
