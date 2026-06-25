# Adaptive Learning Framework

The learning layer is advisory only. It never changes action priority, bypasses
approval, creates ToolTasks, or introduces tools outside the deterministic
candidate set.

Runtime flow:

```text
Decision/Risk output
-> deterministic candidate_tools
-> LearningContext
-> LearningStatisticsProvider
-> ToolRankingStrategy
-> decision snapshot metadata
-> governed auto-loop / ToolTask path remains unchanged
```

Current strategies:

- `DeterministicRanking`: preserves candidate order.
- `LearningRanking`: ranks candidates by success rate, average learning score,
  and recent learning score.

Future strategies can replace `ToolRankingStrategy` without changing Decision
Engine, ToolTask lifecycle, Risk Engine, or approval gates:

- `UCBRanking`
- `ContextualBanditRanking`
- `GBMRanking`
- `RLRanking`

The first future UCB1 step should add an exploration term to the ranking score
using `total_runs` from `learning_tool_context_score`, while preserving the same
`rank_tools(candidate_tools, context)` interface.
