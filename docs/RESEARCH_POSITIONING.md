# Research Positioning

## System Positioning

M2A is best described as a governed autonomous security assessment
orchestrator.

It contains vulnerability scanning behavior, but its system boundary is broader
than a scanner. The core abstraction is not a plugin check; it is a governed
`ToolTask` lifecycle connected to evidence normalization, risk scoring,
decision records, auto-loop governance, learning feedback, dataset generation,
and reporting.

Recommended names:

- Chinese: 治理式自主安全評估協調平台
- English: Governed Autonomous Security Assessment Orchestrator

The term "pentest" can be used when discussing the intended domain, but the
current implementation is more accurately a controlled assessment orchestrator
than a full autonomous exploitation agent.

## Difference From Traditional Vulnerability Scanners

Traditional scanners such as Nessus, OpenVAS, or Greenbone are usually centered
on a scan engine and a plugin or signature catalog. They run checks against
assets, produce findings, and feed reports or vulnerability management
workflows.

M2A is architecturally different:

- Tools are treated as governed execution units, not as direct scanner plugins.
- `ToolTask` state controls execution, retries, approval, and completion.
- `DecisionScore` records explain why the system continues, stops, or requests
  follow-up.
- Evidence is normalized before being used by confidence scoring, risk scoring,
  learning feedback, and reports.
- Multi-round execution is explicit through the auto-loop and round limits.
- Learning data is accumulated as a first-class dataset for future offline
  training.

M2A therefore includes weak scanning, but it is not only a weak scanner.

## Difference From LLM Pentest Agents

LLM pentest agents usually place the language model near the center of the
loop. The model interprets outputs, plans steps, and proposes commands or tool
usage.

M2A's current production path is not LLM-first:

- Runtime decision making is deterministic and database-backed.
- Governance is enforced through tool registry, command templates, scope
  validation, approval state, and ToolTask lifecycle rules.
- Learning and ranking are advisory and do not override deterministic action
  priority.
- Offline model training exists, but models do not participate in runtime
  decisions.

This makes M2A closer to a safety-oriented orchestration architecture than to a
free-form LLM agent.

## Research Contributions Already Implemented

The current codebase supports these concrete contributions:

- Governed ToolTask lifecycle with explicit status and approval states.
- Multi-stage assessment flow from target creation to report generation.
- Multi-round execution with stop conditions, duplicate prevention, and round
  limits.
- Evidence normalization and confidence records.
- Risk Engine v3 integration with explainable `DecisionScore` rows.
- Approval-aware auto loop for depth tools.
- Learning feedback writeback after tool execution.
- Context-aware learning metadata.
- Offline knowledge prior and hybrid ranking metadata.
- Round value labeling for future supervised learning.
- Training repository abstraction and dataset quality checks.
- Offline model training, registry, prediction, and evaluation framework.
- Report and dashboard APIs for operational visibility.

## Current Limitations

The following are not currently completed runtime capabilities:

- Runtime GBM-based ranking.
- Runtime contextual bandit selection.
- Reinforcement learning.
- Public walkthrough knowledge providers.
- Model-driven tool selection.
- Exploit-chain automation.
- Post-exploitation workflows.
- Large-scale empirical validation on real historical datasets.

These items should be described as future work, not as completed results.

## Future Work

Near-term future work should focus on:

- collecting enough labeled round data for reliable supervised learning
- validating label quality across services and tool types
- adding a `GBMRanking(ToolRankingStrategy)` as advisory ranking only
- comparing deterministic, UCB, hybrid, and GBM ranking offline
- adding stronger dataset drift and leakage checks
- expanding reporting for learning and model evaluation

Any runtime model integration should preserve the current governance boundary:
models may rank existing candidate tools, but they must not create new tools,
change action priority, bypass approval, or bypass scope validation.
