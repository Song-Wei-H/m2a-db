# M2A Architecture

M2A is a governed autonomous security assessment orchestrator. It is not a
single vulnerability scanner and it is not a runtime ML-driven pentest agent.
The current implementation coordinates allowlisted tools through governed
`ToolTask` records, analyzes evidence, records decisions, accumulates learning
data, and exposes reports and dashboard APIs.

## Subsystems

```text
Execution
  -> Governance
  -> Analysis and Decision
  -> Learning Data Pipeline
  -> Offline Training
```

The execution path can run without the learning and offline training layers.
Learning failures are expected to be non-blocking.

## Execution Subsystem

Primary modules:

- `app/api/targets.py`
- `worker/task_poller.py`
- `worker/tool_runner.py`
- `worker/remote_runner.py`
- `worker/analysis_pipeline.py`
- `worker/auto_loop.py`
- `worker/report_generator.py`

Core runtime flow:

```text
Target
-> initial ToolTask
-> task_poller claim
-> tool execution
-> ToolResult
-> parser
-> normalized evidence
-> DecisionScore
-> auto loop
-> next governed ToolTask or stop
-> report/dashboard API
```

`ToolTask` is the runtime execution unit. The worker only fetches executable
tasks and must respect status, approval, scope, and command template rules.

## Governance Subsystem

Primary modules:

- `app/tool_task_constants.py`
- `app/tool_task_state.py`
- `app/tool_task_writer.py`
- `app/routers/approval.py`
- `app/tool_catalog.py`
- `app/tool_task_dispatcher.py`
- `worker/safety.py`
- `worker/command_templates.py`
- `worker/task_generator.py`
- `worker/auto_loop.py`

Governance responsibilities:

- enforce allowlisted tools
- avoid raw shell or arbitrary argv execution
- validate scope before execution
- enforce approval gates for depth or higher-risk tasks
- prevent duplicate active ToolTasks
- enforce ToolTask status transitions
- record stop reasons through `auto_loop_decisions`

The current architecture treats governance as part of the execution contract,
not as an optional layer around a scanner.

## Analysis and Decision Subsystem

Primary modules:

- `worker/evidence_normalizer.py`
- `worker/confidence_scoring.py`
- `worker/mitre_mapper.py`
- `worker/cve_matcher.py`
- `worker/cve_enrichment.py`
- `worker/risk_engine_v3.py`
- `worker/analysis_pipeline.py`
- `worker/auto_loop.py`

The analysis pipeline transforms parser output into normalized evidence,
confidence records, risk scores, and `DecisionScore` rows. Decisions can
recommend follow-up tools, stop execution, or require approval, but tool
creation still goes through the governed ToolTask path.

## Learning Subsystem

Primary modules:

- `worker/learning_context.py`
- `worker/learning_statistics.py`
- `worker/learning_engine.py`
- `worker/learning_feedback.py`
- `worker/offline_knowledge_provider.py`
- `worker/offline_knowledge_prior.py`
- `worker/tool_ranking.py`
- `worker/ucb_ranking.py`
- `worker/hybrid_ranking.py`
- `worker/learning_pipeline.py`
- `worker/round_label_builder.py`
- `worker/feature_builder.py`
- `worker/training_repository.py`
- `worker/training_data_report.py`

Learning is advisory and data-producing. It may write metadata into decision
snapshots and append dataset rows, but it must not modify runtime action
priority, create ToolTasks, bypass approval, or change governance behavior.

The implemented learning layers include:

- context-aware learning metadata
- learning feedback writeback
- offline knowledge prior
- UCB and hybrid ranking metadata
- round value labels
- feature vectors
- dataset repository abstraction
- dataset validation and export
- data quality reports

## Offline Training Subsystem

Primary modules:

- `worker/model_dataset_loader.py`
- `worker/gbm_trainer.py`
- `worker/gbm_predictor.py`
- `worker/model_evaluator.py`
- `worker/model_registry.py`
- `worker/model_report.py`
- `worker/model_readiness.py`

Offline training is isolated from execution. The runtime pipeline does not
import the trainer, predictor, evaluator, or registry. Current model support is
experimental and offline-only.

Offline training flow:

```text
TrainingRepository
-> Dataset Loader
-> Feature Matrix
-> Label Vector
-> GBMTrainer
-> GBMModel
-> LocalModelRegistry
-> Offline Predictor
-> ModelEvaluator
-> ModelReport
```

The architecture supports future runtime ranking integration through a new
`ToolRankingStrategy`, but that integration is not currently enabled.

## System Boundary

Implemented:

- governed task execution
- multi-stage and multi-round assessment
- approval-aware auto loop
- evidence normalization
- confidence and risk scoring
- report and dashboard APIs
- learning feedback and training dataset generation
- offline model training framework

Not implemented as runtime capabilities:

- ML-driven runtime tool selection
- exploit-chain automation
- post-exploitation orchestration
- autonomous credential attacks
- phishing or payload delivery
- model-driven governance bypass
