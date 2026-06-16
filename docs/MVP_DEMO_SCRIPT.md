# M2A Pentest MVP Demo Script

This guide walks through the MVP runtime path from target creation to dashboard and report review. It is intended for a live demo against an approved test target only.

## Demo Prerequisites

- PostgreSQL is running from `docker compose up -d postgres`.
- The FastAPI service is running with `uvicorn app.main:app`.
- The task poller and Kali worker are running.
- `.env` is based on `.env.example` and points to the local PostgreSQL instance.
- The demo target is authorized for scanning.

## 1. Target Creation

Create a new target through the API or dashboard.

Expected result:

- A `targets` row is created.
- A `scan_runs` row is created or queued.
- Target status is `pending` or `running`.

Demo talking point:

The target is the root execution object. All later evidence, decisions, learning feedback, and report sections are tied back to this target.

## 2. ToolTask Generation

Verify that the dispatcher creates the initial discovery task.

Expected result:

- `tool_tasks` contains `nmap_service`.
- The task starts as `pending`.
- No duplicate `nmap_service` task exists for the same target and port context.

Governance check:

- Duplicate prevention blocks existing `pending`, `running`, or `completed` tasks with the same `target_id`, `open_port_id`, and `tool_name`.

## 3. Nmap Stage

Allow the worker to claim and execute `nmap_service`.

Expected result:

- `nmap_service` transitions from `pending` to `running` to `completed`.
- A `tool_results` row is created.
- `parsed_output` contains structured port data.
- `open_ports` rows are created for discovered services.

Demo talking point:

Nmap provides the first structured service inventory. The parser must produce useful JSON instead of `{}` so downstream analysis can reason over discovered services.

## 4. Evidence Normalization

After the `ToolResult` is persisted, the analysis pipeline normalizes evidence.

Expected result:

- Parsed service data is converted into normalized evidence.
- Empty or malformed parser output does not crash the pipeline.
- Confidence scoring receives service, port, and parser success signals.

Demo talking point:

Normalization is the bridge between tool-specific output and generic risk analysis.

## 5. MITRE Mapping

Verify that the analysis pipeline maps findings to MITRE context where possible.

Expected result:

- `decision_scores` can include `mitre_phase`.
- `decision_scores` can include `mitre_technique`.
- The report deduplicates MITRE mappings for presentation.

Demo talking point:

MITRE mapping gives security reviewers a familiar framework for interpreting the next action and risk context.

## 6. Risk Engine v3

Verify that Risk Engine v3 is used as the primary scoring path.

Expected result:

- `decision_scores.risk_score` is populated.
- `severity` is derived from the adjusted risk score.
- Reasoning includes evidence confidence, learning adjustment, runtime adjustment, and CVE context when available.
- Risk Engine v2 remains available as fallback if v3 cannot score unexpectedly.

Demo talking point:

Risk Engine v3 is the authoritative production scoring path and uses target-specific evidence instead of global or unrelated CVE data.

## 7. Auto Loop

After discovery, verify that the loop proposes the next appropriate tool.

Expected result:

- HTTP services produce `httpx_basic`.
- Confirmed HTTP evidence can produce `nuclei_safe`.
- After `nuclei_safe`, the loop can produce `dirb_safe`.
- `next_action=stop` does not create new tasks.
- The target is not completed while eligible follow-up tasks still exist.

Governance check:

- `current_round >= max_rounds` stops task generation.
- Existing tasks prevent duplicate creation.
- Final completion writes an authoritative stop decision.

## 8. Approval Gate

Verify that depth tools requiring approval do not auto-execute.

Expected result:

- Approval-gated tasks are created with `approval_required=true`.
- `approval_status` is `pending_approval`.
- The worker does not execute the task until it is approved.
- After approval, the task can transition to `running` and then `completed` or `failed`.

Demo talking point:

The MVP separates low-risk discovery from depth actions that require human approval.

## 9. Learning Feedback

Verify that every completed or failed `ToolResult` writes learning feedback.

Expected result:

- `learning_feedback.tool_result_id` is populated.
- `decision_id` points to the associated `decision_scores` row.
- `tool_name`, `service`, `evidence_type`, `recommended_action`, `success`, `was_success`, `confidence_delta`, `learning_score`, and `reason` are populated when the model supports them.
- Timeout or blocked execution reduces the learning score.

Demo talking point:

The platform records whether a recommendation produced useful evidence so future scoring can adjust based on actual tool outcomes.

## 10. Dashboard

Open the dashboard API endpoints.

Recommended checks:

- `GET /dashboard/overview`
- `GET /targets/{id}/summary`
- `GET /targets/{id}/tool-results`
- `GET /targets/{id}/decisions`
- `GET /targets/{id}/learning-feedback`

Expected result:

- Responses exclude large raw output blobs.
- Counts match database state.
- Tool results are newest first.
- Decisions are sorted by highest risk first.
- Completed targets show stable summary data.

## 11. Report API

Open the target report endpoint.

Endpoint:

```text
GET /targets/{id}/report
```

Expected sections:

- `target_summary`
- `open_ports`
- `tool_results`
- `decision_scores`
- `risk_ranking`
- `mitre_mapping`
- `learning_feedback`
- `remediation`

Expected result:

- The report contains all major MVP sections.
- Raw output blobs are not returned.
- Historical decisions remain visible.
- If the latest decision is final `stop` with no `next_tool`, `recommended_next_actions` only shows the final stop recommendation.

## 12. Governance Controls

During the demo, call out these controls explicitly:

- Maximum round enforcement.
- Duplicate tool prevention.
- Stop decision enforcement.
- Approval gate for depth tools.
- Timeout and exception convergence to failed `ToolResult`.
- Conservative CVE matching with no technology-only CVE inserts.
- Target completion guard for required HTTP follow-up tools.

## Demo Success Criteria

The demo is successful when:

- A fresh target progresses from creation to report without manual database edits.
- `nmap_service` runs and creates structured open port evidence.
- `httpx_basic` runs for HTTP services and produces structured HTTP evidence.
- Eligible depth tools are created or explicitly gated/skipped with a reason.
- Learning feedback is written for tool outcomes.
- Risk Engine v3 creates traceable `DecisionScore` records.
- Auto loop stops only after governance rules allow completion.
- Dashboard endpoints return operational summaries.
- Report API returns a complete target report with stable response keys.
- No task remains stuck in `running` beyond the worker timeout policy.
