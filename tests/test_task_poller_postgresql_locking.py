from sqlalchemy.dialects import postgresql

from app.models import ToolTask
from worker.task_poller import _pending_tasks_statement


def test_pending_task_query_locks_only_tool_tasks_on_postgresql():
    sql = str(
        _pending_tasks_statement(limit=10).compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert "LEFT OUTER JOIN execution_authorizations" in sql
    assert "FOR UPDATE OF tool_tasks SKIP LOCKED" in sql
