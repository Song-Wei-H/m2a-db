import asyncio
from unittest.mock import AsyncMock, MagicMock
from worker.learning_feedback import create_learning_feedback

async def test_function():
    # Create a mock session and tool result
    session = AsyncMock()
    tool_result = MagicMock()
    tool_result.id = 1
    tool_result.success = True
    tool_result.parsed_output = {}
    tool_result.tool_name = "nmap"
    tool_result.evidence = None

    # Call the function
    await create_learning_feedback(session, tool_result)
    print("Function executed successfully")

if __name__ == "__main__":
    asyncio.run(test_function())