import pytest

from app.tool_task_constants import APPROVAL_REJECTED, APPROVED, NOT_REQUIRED, PENDING_APPROVAL
from app.tool_task_state import approval_status_values, validate_approval_transition


@pytest.mark.parametrize("next_status", [APPROVED, APPROVAL_REJECTED])
def test_approval_allows_pending_to_terminal(next_status):
    validate_approval_transition(PENDING_APPROVAL, next_status)


@pytest.mark.parametrize(
    ("current_status", "next_status"),
    [
        (APPROVED, PENDING_APPROVAL),
        (APPROVAL_REJECTED, APPROVED),
        (NOT_REQUIRED, APPROVED),
        (APPROVED, APPROVAL_REJECTED),
    ],
)
def test_approval_rejects_invalid_transitions(current_status, next_status):
    with pytest.raises(ValueError):
        validate_approval_transition(current_status, next_status)


def test_approval_status_values_validates_before_update():
    assert approval_status_values(PENDING_APPROVAL, APPROVED, approved_by="analyst") == {
        "approval_status": APPROVED,
        "approved_by": "analyst",
    }

    with pytest.raises(ValueError):
        approval_status_values(APPROVAL_REJECTED, APPROVED)
