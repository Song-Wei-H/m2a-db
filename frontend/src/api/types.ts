export type Severity = "critical" | "high" | "medium" | "low" | string;

export type DashboardOverview = {
  targets_total: number;
  targets_completed: number;
  targets_running: number;
  targets_failed: number;
  tool_results_total: number;
  decisions_total: number;
  learning_feedback_total: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  cve_backed_findings: number;
};

export type TargetSummary = {
  target_id: number | null;
  target: string | null;
  target_type: string | null;
  scope: string | null;
  status: string | null;
  current_round: number | null;
  max_rounds: number | null;
  open_port_count: number;
  tool_result_count: number;
  decision_count: number;
  learning_feedback_count: number;
  highest_risk_score?: number | null;
  highest_severity?: Severity | null;
};

export type RunStatus = {
  target_id: number;
  target: string;
  status: string;
  current_round: number | null;
  max_rounds: number | null;
  pending_task_count: number;
  running_task_count: number;
  completed_task_count: number;
  failed_task_count: number;
  latest_decision: Record<string, unknown> | null;
  latest_next_action: string | null;
  latest_next_tool: string | null;
  report_ready: boolean;
};

export type OpenPort = {
  id?: number;
  target_id?: number | null;
  scan_run_id?: number | null;
  ip?: string | null;
  port?: number | null;
  protocol?: string | null;
  service?: string | null;
  product?: string | null;
  version?: string | null;
  extra_info?: string | null;
  state?: string | null;
  created_at?: string | null;
};

export type ToolResult = {
  tool_name?: string | null;
  success?: boolean | null;
  evidence_type?: string | null;
  service?: string | null;
  risk_level?: string | null;
  created_at?: string | null;
  parsed_output?: Record<string, unknown> | null;
};

export type Decision = {
  risk_score?: number | null;
  severity?: Severity | null;
  next_action?: string | null;
  next_tool?: string | null;
  confidence?: number | null;
  reason?: string | null;
  mitre_phase?: string | null;
  mitre_technique?: string | null;
};

export type LearningFeedback = {
  tool_name?: string | null;
  success?: boolean | null;
  confidence_delta?: number | null;
  learning_score?: number | null;
  reason?: string | null;
  created_at?: string | null;
};

export type TargetReport = {
  target_summary: TargetSummary;
  open_ports: OpenPort[];
  tool_results: ToolResult[];
  decision_scores: Decision[];
  risk_ranking: {
    highest_risk_score?: number | null;
    highest_severity?: Severity | null;
    recommended_next_actions?: Decision[];
    [key: string]: unknown;
  };
  mitre_mapping: Array<Record<string, unknown>>;
  learning_feedback: LearningFeedback[];
  remediation: Array<Record<string, unknown>>;
  matched_cves: Array<Record<string, unknown>>;
  tool_tasks: Array<Record<string, unknown>>;
  normalized_results: Array<Record<string, unknown>>;
  remediation_guidance: string[];
  evidence_confidence: Array<Record<string, unknown>>;
  auto_loop_decisions: Array<Record<string, unknown>>;
  learning_feedback_summary: Record<string, unknown>;
  learning_summary?: Array<Record<string, unknown>>;
  learning_ranking_summary?: Array<Record<string, unknown>>;
  round_value_summary?: Array<Record<string, unknown>>;
};

export type ReportArtifact = {
  path: string;
  size: number;
  sha256: string;
  download_url: string;
};

export type ReportExportResponse = {
  target_id: number;
  format: string;
  files: Record<string, string>;
  artifacts: Record<string, ReportArtifact>;
};

export type TargetCreatePayload = {
  target: string;
  target_type: "ip" | "domain" | "cidr";
  scope: "internal" | "external";
};

export type TargetCreateResponse = {
  target_id: number;
  scan_run_id: number;
  status: string;
};

export type PendingApproval = {
  task_id: number;
  target_id: number;
  target: string;
  scope?: string | null;
  tool_name: string;
  proposal_reason?: string | null;
  approval_reason?: string | null;
  created_at: string;
};
