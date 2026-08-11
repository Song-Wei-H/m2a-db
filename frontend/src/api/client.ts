import type {
  DashboardOverview,
  LearningFeedback,
  OpenPort,
  RunStatus,
  TargetCreatePayload,
  TargetCreateResponse,
  TargetReport,
  TargetSummary,
  ToolResult,
  Decision
} from "./types";
import type { ReportExportResponse } from "./types";

const DEFAULT_API_BASE = import.meta.env.VITE_M2A_API_BASE ?? "";

export function getApiBase() {
  return localStorage.getItem("m2a.apiBase") || DEFAULT_API_BASE;
}

export function setApiBase(value: string) {
  localStorage.setItem("m2a.apiBase", value.trim());
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${getApiBase()}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...init?.headers
    },
    ...init
  });

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: string };
      detail = body.detail ?? detail;
    } catch {
      // Keep HTTP status text when the response is not JSON.
    }
    throw new Error(detail);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  dashboardOverview: () => request<DashboardOverview>("/dashboard/overview"),
  createTarget: (payload: TargetCreatePayload) =>
    request<TargetCreateResponse>("/targets", { method: "POST", body: JSON.stringify(payload) }),
  targetSummary: (targetId: number) => request<TargetSummary>(`/targets/${targetId}/summary`),
  targetReport: (targetId: number) => request<TargetReport>(`/targets/${targetId}/report`),
  targetRunStatus: (targetId: number) => request<RunStatus>(`/targets/${targetId}/run-status`),
  targetOpenPorts: (targetId: number) => request<OpenPort[]>(`/targets/${targetId}/open-ports`),
  targetToolResults: (targetId: number) => request<ToolResult[]>(`/targets/${targetId}/tool-results`),
  targetDecisions: (targetId: number) => request<Decision[]>(`/targets/${targetId}/decisions`),
  targetLearningFeedback: (targetId: number) =>
    request<LearningFeedback[]>(`/targets/${targetId}/learning-feedback`),
  exportReport: (targetId: number, format: "html" | "pdf" | "json" | "all") =>
    request<ReportExportResponse>(
      `/targets/${targetId}/report/export?format=${format}`
    ),
  reportDownloadUrl: (targetId: number, format: "html" | "pdf" | "json") =>
    `${getApiBase()}/targets/${targetId}/report/download?format=${format}`,
  latestReportUrl: (targetId: number) => `${getApiBase()}/targets/${targetId}/report/latest`,
  pendingApprovals: () => request<number[]>("/approvals/pending"),
  approveTask: (taskId: number, reason?: string) =>
    request<{ status: string; task_id: number }>(`/approvals/${taskId}/approve`, {
      method: "POST",
      body: JSON.stringify({ approved_by: "m2a-ui", reason })
    }),
  rejectTask: (taskId: number, reason?: string) =>
    request<{ status: string; task_id: number }>(`/approvals/${taskId}/reject`, {
      method: "POST",
      body: JSON.stringify({ approved_by: "m2a-ui", reason })
    })
};
