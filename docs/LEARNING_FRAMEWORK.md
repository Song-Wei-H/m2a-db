# Adaptive Learning Framework

The learning layer is advisory only. It never changes action priority, bypasses
approval, creates ToolTasks, or introduces tools outside the deterministic
candidate set.

Runtime flow:

```text
Decision/Risk output
-> deterministic candidate_tools
-> governance remains enforced by existing tool_policy/scope/approval path
-> LearningContext
-> OfflineKnowledgeProvider
-> OfflineKnowledgePrior
-> LearningStatisticsProvider
-> UCBRanking
-> HybridRanking
-> decision snapshot metadata
-> governed auto-loop / ToolTask path remains unchanged
```

Current strategies:

- `DeterministicRanking`: preserves candidate order.
- `LearningRanking`: ranks candidates by success rate, average learning score,
  and recent learning score.
- `UCBRanking`: applies UCB1 exploration over local context observations.
- `HybridRanking`: combines offline priors with UCB scores.

Built-in offline prior rules:

```text
HTTP: httpx_basic=1.00, nuclei_safe=0.85, dirb_safe=0.60
SSH: ssh-enum=1.00
MySQL: mysql-info=1.00
Unknown: nmap_service=0.80
```

The built-in provider is intentionally small. It does not include HTB,
VulnHub, Pentest-R1, public walkthroughs, exploit chains, or offensive
datasets. Future providers should implement the same `OfflineKnowledgeProvider`
interface:

- `HTBKnowledgeProvider`
- `VulnHubKnowledgeProvider`
- `PentestR1KnowledgeProvider`
- `InternalKnowledgeProvider`

Future strategies can replace `ToolRankingStrategy` without changing Decision
Engine, ToolTask lifecycle, Risk Engine, or approval gates:

- `UCBRanking`
- `ContextualBanditRanking`
- `GBMRanking`
- `RLRanking`

Round value labeling is also advisory and offline-friendly. It compares an
observed round with the following state and writes rule-based labels for future
datasets:

```text
ToolResult
-> Analysis Pipeline
-> DecisionScore metadata
-> RoundValueLabelBuilder
-> round_learning_labels
-> TrainingDatasetBuilder / TrainingDataReport
```

The label builder does not predict outcomes, train models, create ToolTasks,
change ranking, or alter governance. The current round value rules are:

- new finding: +1
- new CVE: +2
- new critical finding: +3
- risk increase: +1
- confidence increase: +1
- no change: 0
- tool timeout: -1
- duplicate finding: -1

Safety constraints:

- Ranking receives candidate tools only; it never creates candidates.
- Ranking never creates ToolTasks.
- Ranking never changes `next_action`.
- Ranking never turns `stop` into `continue`.
- Ranking never lowers `verify` or `remediate` into `continue`.
- Ranking never bypasses tool policy, scope validation, approval, dangerous
  character validation, or ToolTask lifecycle state machines.
