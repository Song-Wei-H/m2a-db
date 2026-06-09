# M2A Pentest Platform - Project Context

## Project Goal

基於 MITRE ATT&CK 行為映射之 AI 自主滲透測試代理設計與評估。

系統透過多輪決策、自動化工具執行、風險評分、學習回饋與報告產出，建立可治理（Governed）的自主弱點驗證平台。

---

# Current Architecture

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
Multi-Round Loop
↓
Report Generator

---

# Completed Stages

Stage 1 – Target Ingestion

Stage 2 – PostgreSQL Integration

Stage 3 – Dispatcher

Stage 4 – Kali Worker

Stage 5 – scan_results + open_ports parsing

Stage 6 – Tool Decision Engine

Stage 7 – LLM Security Boundary

Stage 8 – Normalized Result Pipeline

Stage 9 – Evidence Confidence Engine

Stage 10 – Human Approval Layer

Stage 11 – Governed Command Execution

Stage 12 – Risk Engine V3

---

# Tool Policy

Allowed Tools

* nmap_service
* httpx_basic
* nuclei_safe
* dirb_safe
* ssh-enum
* mysql-info

Forbidden

* hydra
* password spraying
* brute force
* arbitrary shell commands

---

# Decision Rules

Priority

1. KEV + Critical CVSS
   → remediate

2. Verification Required
   → verify

3. next_tool exists
   → continue

4. next_tool is null
   → stop

---

# Remaining Work

## Stage A

Decision Engine Fix

* remove inconsistent state
* next_tool exists but stop

## Stage B

Learning Feedback Completion

Fields

* tool_name
* success
* service
* evidence_type
* learning_score
* reason

## Stage C

Parser Completion

* nmap_parser
* httpx_parser
* nuclei_parser
* dirb_parser
* ssh_enum_parser
* mysql_info_parser

Goal

parsed_output should contain structured evidence.

## Stage D

Auto Multi-Round Loop

Requirements

* max_round
* duplicate prevention
* approval gate
* stop condition
* retry limit

## Stage E

Report Generator

1. Vulnerability Report

2. Process / Decision Trace Report

## Stage F

Dashboard APIs

GET /targets/{id}/summary

GET /targets/{id}/decisions

GET /targets/{id}/tool-results

GET /targets/{id}/report/vulnerability

GET /targets/{id}/report/process

---

# MVP Completion Definition

Target
↓
Nmap
↓
Open Ports
↓
Tool Selection
↓
Tool Execution
↓
Parser
↓
Normalized Result
↓
Evidence Confidence
↓
Learning Feedback
↓
Risk Engine V3
↓
Decision Engine
↓
Multi-Round Loop
↓
Remediation / Stop
↓
Vulnerability Report
↓
Decision Trace Report
