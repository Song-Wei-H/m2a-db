#!/usr/bin/env python3
"""Debug script to test learning feedback functionality."""

import asyncio
import logging
from app.models import ToolResult
from worker.learning_feedback import create_learning_feedback

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_learning_feedback():
    """Test the learning feedback creation."""
    # Create a mock tool result for testing
    tool_result = ToolResult()
    tool_result.id = 1
    tool_result.success = True
    tool_result.parsed_output = {"status": "done", "findings": ["test"]}
    tool_result.tool_name = "test_tool"
    
    # Test creating learning feedback
    try:
        await create_learning_feedback(None, tool_result)
        print("Learning feedback creation test passed!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_learning_feedback())