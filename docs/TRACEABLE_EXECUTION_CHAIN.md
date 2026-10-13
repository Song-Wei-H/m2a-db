# Traceable execution chain — current state (before changes)

Baseline: main, 8609b90f1c22214024f4ac7c647118c0b5379c4f. Original and isolated checkout clean on resumption.

| Edge / layer | Baseline evidence | Status / gap |
|---|---|---|
| Evidence | NormalizedResult.normalized_output/tool_result_id; DecisionScore.input_snapshot; OpenPort; frozen files | Existing sources; no immutable direct Proposal evidence binding |
| Decision | DecisionScore = deterministic scoring context; LlmRecommendation = advisory response; DecisionProposal = selected operation entering governance | Distinct semantics; proposal has canonical parameters only |
| Evidence → Proposal | models.py DecisionProposal | MISSING; target/investigation IDs alone do not identify inputs |
| Proposal → Authorization | ExecutionAuthorization.proposal_id FK, initdb/027 | PRESENT for issued grants; no durable DENY authorization evaluation |
| Authorization → Task | ToolTask.execution_authorization_id FK; writer; poller claim/expiry/single-use checks | PRESENT for migrated tools; nullable legacy path remains |
| Task → Result | initdb/007 declares tool_task_id FK; poller persists task/action/investigation IDs | PRESENT in migration; ORM missing FK declaration; live schema still to inspect |
| Request / execution | poller reconstructs parameters; remote_runner sends JSON; Worker checks identity | Parameters checked but no durable independent request/receipt snapshot |
| Reverse trace | report_generator exposes partial fields; experiment trace_complete is a boolean | MISSING result-ID-based reconstruction/integrity validation |

Design: reuse sources and existing models. Add immutable JSON snapshots/hashes and an AuthorizationDecision audit record (ALLOW/DENY/PENDING) linked to the proposal and, only for ALLOW, an existing grant. Do not overload a denied record as a usable grant. Preserve nullable historical references and report missing evidence rather than inventing backfills. Preserve grant-first claim/expiry/single-use behavior.

Evidence authority: Obsidian C:/Users/p2166/Documents/ChatGPT/總規則 (AGENTS, Registry, Context, Evidence/Approval policies, GADE Architecture/Decisions/Runbook/Validation/Known Issues); Notion thesis and isolated-lab pages. Vault contains conflicting historical/current Mode B statements. Frozen artifacts, not page recency or trace-complete assertions, determine experiment validity.

No formal experiment rerun is implied by a schema change. No production Worker transport authentication, RBAC, destination pinning or new tools are introduced by this work.

## Implemented state

Migration `033_execution_trace.sql` adds hashed proposal/evidence snapshots,
append-only `AuthorizationDecision` outcomes, hashed execution requests and
Worker receipts. `trace_tool_result()` reconstructs the chain from a result ID
and reports `COMPLETE`, `PARTIAL`, or `NOT_FOUND`; it never repairs missing
historical edges. Run it read-only with:

```powershell
.\.venv\Scripts\python.exe -m scripts.trace_tool_result <TOOL_RESULT_ID>
```

Only ALLOW has an `ExecutionAuthorization` grant. DENY/PENDING are durable
evaluations with no executable grant. The ToolResult FK is installed `NOT
VALID` so existing rows remain intact while new orphan references fail.
