# Legacy Unused Archive

These files were archived after a static repository reference audit found no
production imports or runtime call references.

They were moved instead of deleted so their content remains available for
manual review and Git can track the rename history.

Archived files:

- `dispatcher.py`: legacy combined dispatcher/remote execution loop. Current
  execution uses `scan_run_dispatcher.py` for initial scan task creation and
  `worker/task_poller.py` with `worker/remote_runner.py` for ToolTask execution.
- `nmap_parser.py`: legacy top-level ScanResult parser. Current parsing uses
  `worker/parsers/nmap_parser.py`.
- `worker_decision_engine.py`: legacy worker decision shim. Current production
  scoring uses `worker/risk_engine_v3.py` through `worker/analysis_pipeline.py`.
- `worker_template_governance.py`: unused template helper; template validation
  is handled by `worker/task_poller.py`, `worker/safety.py`, and enabled
  `CommandTemplate` rows.
- `debug_learning_feedback.py`: manual debug helper.
- `check_tool_results.py`: manual inspection helper.
- `check_ssh_results.py`: manual inspection helper.

Do not restore these files into the production path without first checking for
duplicate behavior against the current worker and API pipeline.
