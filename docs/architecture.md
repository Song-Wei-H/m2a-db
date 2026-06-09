# System Architecture

## Core Flow

Target
↓
scan_runs
↓
Dispatcher
↓
Kali Worker
↓
Tool Execution
↓
tool_results
↓
Parser
↓
normalized_result
↓
evidence_confidence
↓
learning_feedback
↓
Risk Engine V3
↓
Decision Engine
↓
Approval Layer
↓
tool_tasks
↓
Multi-Round Loop
↓
Report Generator

---

## Core Components

### FastAPI

* REST API
* Target ingestion
* Query endpoints
* Report endpoints

### PostgreSQL

Stores

* targets
* scan_runs
* open_ports
* tool_results
* normalized_result
* evidence_confidence
* learning_feedback
* decision_scores
* tool_tasks

### Dispatcher

Responsibilities

* poll pending tasks
* validate scope
* enforce approval
* submit jobs to workers

### Kali Worker

Responsibilities

* execute allowlisted tools
* use shell=False
* return raw output
* never receive arbitrary commands

### Risk Engine V3

Responsibilities

* risk scoring
* severity classification
* next action support

### Decision Engine

Responsibilities

* choose next tool
* determine continue/verify/remediate/stop

### Learning Engine

Responsibilities

* calculate learning_score
* record historical outcomes
* influence future scoring

### Report Generator

Responsibilities

* vulnerability report
* process report
