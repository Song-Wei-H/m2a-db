import pytest

from app.tool_task_constants import CANCELLED, COMPLETED, FAILED, PENDING, REJECTED, RUNNING
from app.tool_task_state import tool_task_status_values, validate_tool_task_transition


@pytest.mark.parametrize(
    ("current_status", "next_status"),
    [
        (PENDING, RUNNING),
        (PENDING, FAILED),
        (PENDING, CANCELLED),
        (PENDING, REJECTED),
        (RUNNING, COMPLETED),
        (RUNNING, FAILED),
        (RUNNING, CANCELLED),
        (RUNNING, REJECTED),
    ],
)
def test_tool_task_allows_valid_transitions(current_status, next_status):
    validate_tool_task_transition(current_status, next_status)


@pytest.mark.parametrize(
    ("current_status", "next_status"),
    [
        (COMPLETED, RUNNING),
        (FAILED, PENDING),
        (REJECTED, RUNNING),
        (CANCELLED, PENDING),
        (PENDING, COMPLETED),
    ],
)
def test_tool_task_rejects_invalid_transitions(current_status, next_status):
    with pytest.raises(ValueError):
        validate_tool_task_transition(current_status, next_status)


def test_tool_task_status_values_validates_before_update():
    assert tool_task_status_values(RUNNING, FAILED, reject_reason="timeout") == {
        "status": FAILED,
        "reject_reason": "timeout",
    }

    with pytest.raises(ValueError):
        tool_task_status_values(FAILED, PENDING)
