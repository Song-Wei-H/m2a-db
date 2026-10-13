import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Play } from "lucide-react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { DecisionCard } from "../components/DecisionCard";
import { EvidenceCard } from "../components/EvidenceCard";
import { MITREBadge, RiskBadge } from "../components/Badges";
import { EmptyState, ErrorState, Loading } from "../components/Status";
import { Timeline } from "../components/Timeline";
import { ToolQueue } from "../components/ToolQueue";
import { WorkerStatus } from "../components/WorkerStatus";
import { ReportViewer } from "../components/ReportViewer";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Dialog } from "../components/ui/dialog";
import { Input } from "../components/ui/input";
import { useKnownTargets } from "../hooks/useKnownTargets";
import { AttackAuthorizationMatrix } from "../components/AttackAuthorizationMatrix";
import type { AuthorizationDecision } from "../api/types";

export function TargetDetail() {
  const targetId = Number(useParams().targetId);
  const knownTargets = useKnownTargets();
  const queryClient = useQueryClient();
  const [automationMessage, setAutomationMessage] = useState<string | null>(null);
  const [retestOpen, setRetestOpen] = useState(false);
  const [retestReason, setRetestReason] = useState("");
  const [authorizationDepthDraft, setAuthorizationDepthDraft] = useState(1);
  useEffect(() => {
    if (Number.isInteger(targetId) && targetId > 0) knownTargets.add(targetId);
  }, [knownTargets, targetId]);

  const report = useQuery({ queryKey: ["target-report", targetId], queryFn: () => api.targetReport(targetId), enabled: targetId > 0 });
  const authorizationProfile = useQuery({ queryKey: ["target-authorization", targetId], queryFn: () => api.targetAuthorization(targetId), enabled: targetId > 0 });
  const authorizationLevels = useQuery({ queryKey: ["attack-authorization-levels"], queryFn: api.attackAuthorizationLevels });
  const authorizationDecisions = useQuery({ queryKey: ["target-authorization-decisions", targetId], queryFn: () => api.targetAuthorizationDecisions(targetId), enabled: targetId > 0 });
  useEffect(() => {
    if (authorizationProfile.data) setAuthorizationDepthDraft(authorizationProfile.data.authorization_depth);
  }, [authorizationProfile.data]);
  const saveAuthorization = useMutation({
    mutationFn: () => api.updateTargetAuthorization(targetId, authorizationDepthDraft),
    onSuccess: () => {
      setAutomationMessage("授權深度已更新；後續 action 仍須通過其他治理檢查。");
      void queryClient.invalidateQueries({ queryKey: ["target-authorization", targetId] });
      void queryClient.invalidateQueries({ queryKey: ["target-authorization-decisions", targetId] });
    },
    onError: (error: Error) => setAutomationMessage(`授權深度更新失敗：${error.message}`)
  });
  const automation = useMutation({
    mutationFn: () => api.startTargetAutomation(targetId),
    onSuccess: (result) => {
      setAutomationMessage(result.status === "already_running" ? "此目標的自動化已在執行。" : "此目標的自動化已啟動。");
      void queryClient.invalidateQueries({ queryKey: ["target-run-status", targetId] });
    },
    onError: (error: Error) => setAutomationMessage(`啟動失敗：${error.message}`)
  });
  const retest = useMutation({
    mutationFn: () => api.retestTarget(targetId, retestReason.trim()),
    onSuccess: () => {
      setAutomationMessage("重新測試已啟動。");
      setRetestOpen(false);
      setRetestReason("");
      void queryClient.invalidateQueries({ queryKey: ["target-report", targetId] });
      void queryClient.invalidateQueries({ queryKey: ["target-run-status", targetId] });
    },
    onError: (error: Error) => setAutomationMessage(`重新測試失敗：${error.message}`)
  });
  const [status, ports, decisions, learning] = useQueries({
    queries: [
      { queryKey: ["target-run-status", targetId], queryFn: () => api.targetRunStatus(targetId), enabled: targetId > 0, refetchInterval: 10_000 },
      { queryKey: ["target-open-ports", targetId], queryFn: () => api.targetOpenPorts(targetId), enabled: targetId > 0 },
      { queryKey: ["target-decisions", targetId], queryFn: () => api.targetDecisions(targetId), enabled: targetId > 0 },
      { queryKey: ["target-learning", targetId], queryFn: () => api.targetLearningFeedback(targetId), enabled: targetId > 0 }
    ]
  });

  if (report.isLoading) return <Loading />;
  if (report.isError) return <ErrorState message={report.error.message} />;
  if (!report.data) return <EmptyState title="找不到目標" message="後端沒有回傳此目標的報告。" />;

  const summary = report.data.target_summary;
  const timelineItems = [
    ...report.data.tool_results.map((result) => ({
      title: result.tool_name || "工具結果",
      time: result.created_at,
      detail: result.risk_level || result.evidence_type || null
    })),
    ...report.data.learning_feedback.map((feedback) => ({
      title: `學習回饋：${feedback.tool_name || "工具"}`,
      time: feedback.created_at,
      detail: feedback.reason || null
    }))
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <div>
            <CardTitle>目標自動化</CardTitle>
            {automationMessage && <p className="mt-1 text-sm text-muted-foreground">{automationMessage}</p>}
          </div>
          <Button
            onClick={() => summary.status === "completed" ? setRetestOpen(true) : automation.mutate()}
            disabled={automation.isPending || retest.isPending}
          >
            <Play className="h-4 w-4" />
            {automation.isPending || retest.isPending ? "啟動中…" : summary.status === "completed" ? "重新測試" : "啟動此目標自動化"}
          </Button>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          <SummaryItem label="目標" value={summary.target || `目標 ${targetId}`} />
          <SummaryItem label="狀態" value={formatStatus(summary.status)} />
          <SummaryItem label="目前輪次" value={`${summary.current_round ?? "無資料"} / ${summary.max_rounds ?? "無資料"}`} />
          <div>
            <div className="section-title">風險分數</div>
            <div className="mt-1"><RiskBadge score={summary.highest_risk_score} severity={summary.highest_severity} /></div>
          </div>
          <SummaryItem label="信心度" value={latestConfidence(decisions.data)} />
          <SummaryItem label="目前工具" value={status.data?.latest_next_tool || "閒置"} />
          <SummaryItem label="下一個工具" value={status.data?.latest_next_tool || report.data.risk_ranking.recommended_next_actions?.[0]?.next_tool || "停止"} />
        </CardContent>
      </Card>
      <Dialog open={retestOpen} title="重新測試目標" onClose={() => setRetestOpen(false)}>
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">Target {targetId} 已完成。請記錄重新測試理由，系統將建立新的 nmap 初始任務。</p>
          <Input value={retestReason} onChange={(event) => setRetestReason(event.target.value)} placeholder="重新測試理由" />
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => setRetestOpen(false)}>取消</Button>
            <Button disabled={retestReason.trim().length < 3} onClick={() => retest.mutate()}>確認重新測試</Button>
          </div>
        </div>
      </Dialog>

      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle>時間軸</CardTitle></CardHeader>
            <CardContent><Timeline items={timelineItems} /></CardContent>
          </Card>
          <ReportViewer report={report.data} />
          <Card>
            <CardHeader><CardTitle>Vulnerability Queue · Assessment Coverage</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {report.data.vulnerability_coverage && (
                <div className="grid gap-2 text-sm sm:grid-cols-3 xl:grid-cols-5">
                  <QueueMetric label="Candidates" value={report.data.vulnerability_coverage.total_candidates} />
                  <QueueMetric label="Terminal" value={report.data.vulnerability_coverage.terminal_candidates} />
                  <QueueMetric label="Verified" value={report.data.vulnerability_coverage.verified} />
                  <QueueMetric label="Depth denied" value={report.data.vulnerability_coverage.denied_by_depth} />
                  <QueueMetric label="Disposition coverage" value={`${Math.round((report.data.vulnerability_coverage.disposition_coverage_rate ?? report.data.vulnerability_coverage.coverage_rate) * 100)}%`} />
                  <QueueMetric label="Validation coverage" value={`${Math.round((report.data.vulnerability_coverage.validation_coverage_rate ?? 0) * 100)}%`} />
                </div>
              )}
              {(report.data.vulnerability_queue ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">目前沒有已建立的 vulnerability candidate lifecycle 記錄。</p>
              ) : (report.data.vulnerability_queue ?? []).map((candidate) => (
                <div key={candidate.candidate_id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-3 text-sm">
                  <span className="font-medium">{candidate.cve} · {candidate.service || "service unknown"}/{candidate.open_port_id ? `port ${candidate.open_port_id}` : "target"}</span>
                  <span className="text-muted-foreground">L{candidate.required_depth ?? "—"} · {candidate.status} · {candidate.validation_coverage ?? "NOT_EVALUATED"}{candidate.terminal_reason ? ` · ${candidate.terminal_reason}` : ""}</span>
                </div>
              ))}
              <p className="text-xs text-muted-foreground">Disposition coverage 表示候選都有處置；validation coverage 表示有實際技術驗證證據。兩者都不代表成功利用。</p>
              {(report.data.vulnerability_coverage?.legacy_untracked_candidate_contexts ?? 0) > 0 && (
                <p className="text-xs text-amber-600 dark:text-amber-400">尚有 {report.data.vulnerability_coverage?.legacy_untracked_candidate_contexts} 筆歷史 CVE context 未用新 queue 語義評估；歷史資料不回填。</p>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Engagement 授權深度</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {authorizationProfile.data && authorizationLevels.data ? (
                <>
                  <div className="text-sm text-muted-foreground">
                    目前設定：第 {authorizationProfile.data.authorization_depth} 層 · {authorizationProfile.data.policy_version} · 範圍分類：{authorizationProfile.data.scope || "未設定"} · 到期：{authorizationProfile.data.expires_at ? new Date(authorizationProfile.data.expires_at).toLocaleString() : "未設定"}
                  </div>
                  <AttackAuthorizationMatrix
                    levels={authorizationLevels.data.levels}
                    value={authorizationDepthDraft}
                    onChange={setAuthorizationDepthDraft}
                  />
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="text-xs text-muted-foreground">
                      生效時間：{new Date(authorizationProfile.data.effective_from).toLocaleString()} · 設定來源：{authorizationProfile.data.configured_by}
                    </div>
                    <Button
                      disabled={saveAuthorization.isPending || authorizationDepthDraft === authorizationProfile.data.authorization_depth}
                      onClick={() => saveAuthorization.mutate()}
                    >
                      {saveAuthorization.isPending ? "儲存中…" : "儲存授權深度"}
                    </Button>
                  </div>
                </>
              ) : authorizationProfile.isError ? (
                <ErrorState message={authorizationProfile.error.message} />
              ) : (
                <Loading />
              )}
            </CardContent>
          </Card>
          <AuthorizationDecisionPanel decisions={authorizationDecisions.data ?? []} levels={authorizationLevels.data?.levels ?? []} />
          <div className="grid gap-4 xl:grid-cols-2">
            <EvidenceCard title="證據" data={report.data.evidence_confidence} />
            <EvidenceCard title="正規化結果" data={report.data.normalized_results} />
            <EvidenceCard title="學習回饋" data={learning.data ?? report.data.learning_feedback} />
            <EvidenceCard title="CVE 比對" data={report.data.matched_cves} />
          </div>
          <Card>
            <CardHeader><CardTitle>決策歷史</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {(decisions.data ?? report.data.decision_scores).map((decision, index) => <DecisionCard key={index} decision={decision} index={index} toolTasks={report.data.tool_tasks} />)}
            </CardContent>
          </Card>
        </div>
        <div className="space-y-4">
          <WorkerStatus status={status.data} />
          <ToolQueue tasks={report.data.tool_tasks} />
          <Card>
            <CardHeader><CardTitle>開放連接埠</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {(ports.data ?? report.data.open_ports).map((port, index) => (
                <div className="rounded-md border border-border bg-muted/25 p-3 text-sm" key={index}>
                  {port.port}/{port.protocol} - {port.service || "unknown"} - {port.state || "n/a"}
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>MITRE 對應</CardTitle></CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              {report.data.mitre_mapping.map((item, index) => <MITREBadge key={index} phase={item.mitre_phase} technique={item.mitre_technique} />)}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function AuthorizationDecisionPanel({
  decisions,
  levels
}: {
  decisions: AuthorizationDecision[];
  levels: Array<{ level: number; name_zh: string }>;
}) {
  const levelName = (level?: number | null) => {
    if (!level) return "未對應";
    return `${level} / ${levels.find((item) => item.level === level)?.name_zh ?? "未知層級"}`;
  };
  return (
    <Card>
      <CardHeader><CardTitle>授權檢查紀錄</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        {decisions.length === 0 ? <p className="text-sm text-muted-foreground">尚無 action 授權檢查紀錄。</p> : decisions.slice(0, 10).map((decision) => (
          <div key={decision.proposal_id} className="rounded-md border border-border bg-muted/20 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="font-medium">{decision.action_id}</div>
              <span className={`rounded border px-2 py-1 text-xs font-semibold ${decision.outcome === "ALLOW" ? "border-emerald-500/50 text-emerald-600 dark:text-emerald-400" : decision.outcome === "DENY" ? "border-red-500/50 text-red-500" : "border-amber-500/50 text-amber-600 dark:text-amber-400"}`}>
                {decision.outcome === "ALLOW" ? "ALLOW" : decision.outcome === "DENY" ? "DENY" : decision.outcome}
              </span>
            </div>
            <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2 xl:grid-cols-3">
              <CheckItem label="Engagement depth" value={levelName(decision.engagement_depth)} />
              <CheckItem label="Action required depth" value={levelName(decision.required_depth)} />
              <CheckItem label="Depth check" value={decision.depth_check || "UNAVAILABLE"} />
              <CheckItem label="Evidence check" value={decision.evidence_check || "UNAVAILABLE"} />
              <CheckItem label="Scope check" value={decision.scope_check || "UNAVAILABLE"} />
              <CheckItem label="Approval check" value={decision.approval_check || "UNAVAILABLE"} />
            </div>
            <p className="mt-3 text-sm text-muted-foreground">{decision.reason_code ? `${decision.reason_code} · ` : ""}{decision.reason}</p>
          </div>
        ))}
        <p className="text-xs text-muted-foreground">此紀錄只呈現已保存的檢查結果；runtime scope、expiry、重放與參數一致性仍由執行閘門獨立驗證。</p>
      </CardContent>
    </Card>
  );
}

function CheckItem({ label, value }: { label: string; value: string }) {
  return <div className="rounded border border-border px-2 py-1.5"><span className="text-muted-foreground">{label}：</span><span className="font-medium">{value}</span></div>;
}

function formatStatus(status?: string | null) {
  return ({ pending: "等待中", running: "執行中", completed: "已完成", failed: "失敗" } as Record<string, string>)[String(status)] || status || "無資料";
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="section-title">{label}</div>
      <div className="mt-1 truncate font-medium">{value}</div>
    </div>
  );
}

function QueueMetric({ label, value }: { label: string; value: string | number }) {
  return <div className="rounded border border-border px-2 py-1.5"><span className="text-muted-foreground">{label}：</span><span className="font-semibold">{value}</span></div>;
}

function latestConfidence(decisions?: Array<{ confidence?: number | null }>) {
  const value = decisions?.find((decision) => typeof decision.confidence === "number")?.confidence;
  return typeof value === "number" ? `${Math.round(value * 100)}%` : "n/a";
}
