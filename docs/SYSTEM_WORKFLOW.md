# System Workflow

This document describes the implemented M2A workflow from target creation to
offline model evaluation. It reflects the current code structure and does not
claim runtime ML-driven decisions.

## End-to-End Flow

```text
Target
  -> ScanRun
  -> initial ToolTask
  -> task_poller
  -> governed tool execution
  -> ToolResult
  -> parser
  -> Analysis Pipeline
  -> NormalizedResult
  -> EvidenceConfidence
  -> Risk Engine v3
  -> DecisionScore
  -> LearningPipeline
  -> round_learning_labels
  -> Auto Loop
  -> next ToolTask or stop
  -> Report Generator
  -> Dashboard / Report API
  -> Offline Dataset Loader
  -> Offline Model Training and Evaluation
```

## Target Creation

Primary modules:

- `app/api/targets.py`
- `worker/task_generator.py`
- `app/tool_task_writer.py`

Flow:

```text
POST /targets
-> Target row
-> ScanRun row
-> initial governed ToolTask
```

The initial task is expected to use an allowlisted discovery tool such as
`nmap_service`. The API path does not create raw shell commands.

## ToolTask Execution

Primary modules:

- `worker/task_poller.py`
- `worker/safety.py`
- `worker/tool_runner.py`
- `worker/remote_runner.py`

Flow:

```text
pending ToolTask
-> approval status check
-> scope and safety validation
-> status running
-> command template execution
-> ToolResult persisted
-> status completed or failed
```

Tasks requiring approval remain pending until approved. Rejected tasks are not
executed.

## ToolResult Parsing

Primary modules:

- `worker/parsers/*`
- `worker/evidence_normalizer.py`

Flow:

```text
ToolResult.raw_output
-> parser
-> parsed_output
-> normalized evidence
```

Parsers are expected to return stable JSON dictionaries and avoid crashing on
empty or failed tool output.

## Analysis and Decision

Primary modules:

- `worker/analysis_pipeline.py`
- `worker/confidence_scoring.py`
- `worker/mitre_mapper.py`
- `worker/cve_matcher.py`
- `worker/cve_enrichment.py`
- `worker/risk_engine_v3.py`
- `worker/auto_loop.py`

Flow:

```text
normalized evidence
-> EvidenceConfidence
-> CVE summary from local DB matches
-> Risk Engine v3
-> DecisionScore
-> auto-loop stop or next_tool evaluation
```

`DecisionScore` stores the risk score, severity, next action, next tool,
reasoning, MITRE fields, and input snapshot metadata.

## Governance and Auto Loop

Primary modules:

- `worker/auto_loop.py`
- `worker/task_generator.py`
- `app/tool_task_writer.py`
- `app/tool_task_state.py`

Flow:

```text
DecisionScore.next_action / next_tool
-> max_round check
-> duplicate task check
-> approval requirement check
-> create governed ToolTask or write stop reason
```

The auto loop must not create duplicate active tasks for the same target,
open port, and tool name. Depth tools may require approval.

## Learning Pipeline

Primary modules:

- `worker/learning_pipeline.py`
- `worker/round_label_builder.py`
- `worker/feature_builder.py`
- `worker/training_repository.py`
- `worker/training_data_report.py`

Flow:

```text
Decision snapshot and observed state
-> RoundLearningLabel
-> Feature Vector
-> TrainingRepository.append_round
-> round_learning_labels
-> TrainingDataReport
```

The learning pipeline is side-channel only. If repository persistence fails,
the failure is logged as a warning and execution continues.

## Adaptive Ranking Metadata

Primary modules:

- `worker/learning_context.py`
- `worker/learning_statistics.py`
- `worker/offline_knowledge_provider.py`
- `worker/offline_knowledge_prior.py`
- `worker/ucb_ranking.py`
- `worker/hybrid_ranking.py`

Flow:

```text
candidate_tools
-> LearningContext
-> OfflineKnowledgePrior
-> LearningStatisticsProvider
-> UCBRanking
-> HybridRanking
-> decision snapshot metadata
```

The current ranking layer is advisory. It records scores and metadata but does
not override deterministic action priority or governance.

## Report and Dashboard

Primary modules:

- `worker/report_generator.py`
- `app/api/targets.py`
- `app/schemas.py`

Flow:

```text
Target id
-> generate_target_report
-> target_summary
-> open_ports
-> tool_results
-> normalized_results
-> evidence_confidence
-> decision_scores
-> risk_ranking
-> learning summaries
-> remediation
```

Dashboard endpoints reuse report data where appropriate and avoid returning
large raw output blobs.

## Offline Model Workflow

Primary modules:

- `worker/model_dataset_loader.py`
- `worker/gbm_trainer.py`
- `worker/gbm_predictor.py`
- `worker/model_evaluator.py`
- `worker/model_registry.py`
- `worker/model_report.py`
- `worker/model_readiness.py`

Flow:

```text
TrainingRepository.load_dataset
-> split_dataset
-> readiness check
-> feature matrix
-> label vector
-> offline GBMTrainer
-> local model registry
-> offline predictor
-> evaluator
-> model report
```

Offline models are not connected to the runtime decision engine. A future
runtime integration should be implemented as a new `ToolRankingStrategy`, not
as a change to the Decision Engine or governance layer.
