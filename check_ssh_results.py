import sys
sys.path.append('c:/Users/p2166/m2a-db')
from app.models import ToolResult
from app.database import async_session
from sqlalchemy import select
import asyncio

async def check_results():
    async with async_session() as session:
        result = await session.execute(select(ToolResult).where(ToolResult.tool_name == "ssh-enum"))
        tool_results = result.scalars().all()
        print(f'Found {len(tool_results)} results')
        if tool_results:
            for tool_result in tool_results:
                print(f"Tool: {tool_result.tool_name}")
                print(f"Raw output: {tool_result.raw_output}")
                print(f"Parsed output: {tool_result.parsed_output}")
        else:
            print('No results found')

# Run this script
if __name__ == "__main__":
    asyncio.run(check_results())