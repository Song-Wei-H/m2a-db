"""Durable, single-use claims for governed Worker requests.

This is a dispatch replay guard, not an authorization verifier. M2A remains the
source of ExecutionAuthorization; this Worker-local ledger only ensures that a
given authorization ID reaches a handler at most once on a shared local DB.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class ReplayLedgerError(RuntimeError):
    """A governed Worker request could not safely claim its one-shot slot."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def claim_authorization_once(
    database_path: str | None,
    *,
    authorization_id: int,
    task_id: int,
    request_id: str,
    request_hash: str,
) -> None:
    """Atomically persist a single-use authorization claim before dispatch.

    Only identifiers, a request digest, and claim time are stored. A missing,
    in-memory, relative, or unavailable ledger fails closed. The containing
    directory must already exist and be managed by the Worker operator.
    """
    if not database_path or database_path.strip() in {":memory:", "file::memory:"}:
        raise ReplayLedgerError("REPLAY_LEDGER_UNAVAILABLE")

    try:
        path = Path(database_path)
        if (not path.is_absolute() or (path.exists() and not path.is_file())
                or not path.parent.is_dir()):
            raise ReplayLedgerError("REPLAY_LEDGER_UNAVAILABLE")
    except (OSError, TypeError, ValueError) as exc:
        raise ReplayLedgerError("REPLAY_LEDGER_UNAVAILABLE") from exc

    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS worker_authorization_claims (
                   authorization_id TEXT PRIMARY KEY,
                   task_id TEXT NOT NULL,
                   request_id TEXT NOT NULL,
                   request_hash TEXT NOT NULL,
                   claimed_at_utc TEXT NOT NULL
               )"""
        )
        try:
            connection.execute(
                """INSERT INTO worker_authorization_claims
                   (authorization_id, task_id, request_id, request_hash, claimed_at_utc)
                   VALUES (?, ?, ?, ?, ?)""",
                (str(authorization_id), str(task_id), request_id, request_hash,
                 datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            )
        except sqlite3.IntegrityError as exc:
            previous = connection.execute(
                """SELECT task_id, request_id, request_hash
                   FROM worker_authorization_claims WHERE authorization_id = ?""",
                (str(authorization_id),),
            ).fetchone()
            connection.rollback()
            if previous is None:
                raise ReplayLedgerError("REPLAY_LEDGER_UNAVAILABLE") from exc
            if previous != (str(task_id), request_id, request_hash):
                raise ReplayLedgerError("AUTHORIZATION_REPLAY_CONFLICT") from exc
            raise ReplayLedgerError("AUTHORIZATION_ALREADY_CLAIMED") from exc
        connection.commit()
    except ReplayLedgerError:
        raise
    except (OSError, sqlite3.Error) as exc:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        raise ReplayLedgerError("REPLAY_LEDGER_UNAVAILABLE") from exc
    finally:
        if connection is not None:
            connection.close()
