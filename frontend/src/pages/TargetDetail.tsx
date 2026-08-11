import { useQueries, useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
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
import { useKnownTargets } from "../hooks/useKnownTargets";

export function TargetDetail() {
  const targetId = Number(useParams().targetId);
  const knownTargets = useKnownTargets();
  useEffect(() => {
    if (Number.isInteger(targetId) && targetId > 0) knownTargets.add(targetId);
  }, [knownTargets, targetId]);

  const report = useQuery({ queryKey: ["target-report", targetId], queryFn: () => api.targetReport(targetId), enabled: targetId > 0 });
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
  if (!report.data) return <EmptyState title="Target not found" message="The backend did not return a target report." />;

  const summary = report.data.target_summary;
  const timelineItems = [
    ...report.data.tool_results.map((result) => ({
      title: result.tool_name || "Tool result",
      time: result.created_at,
      detail: result.risk_level || result.evidence_type || null
    })),
    ...report.data.learning_feedback.map((feedback) => ({
      title: `Learning: ${feedback.tool_name || "tool"}`,
      time: feedback.created_at,
      detail: feedback.reason || null
    }))
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="grid gap-4 pt-4 md:grid-cols-2 xl:grid-cols-5">
          <SummaryItem label="Target" value={summary.target || `Target ${targetId}`} />
          <SummaryItem label="Status" value={summary.status || "n/a"} />
          <SummaryItem label="Current Round" value={`${summary.current_round ?? "n/a"} / ${summary.max_rounds ?? "n/a"}`} />
          <div>
            <div className="section-title">Risk Score</div>
            <div className="mt-1"><RiskBadge score={summary.highest_risk_score} severity={summary.highest_severity} /></div>
          </div>
          <SummaryItem label="Confidence" value={latestConfidence(decisions.data)} />
          <SummaryItem label="Current Tool" value={status.data?.latest_next_tool || "idle"} />
          <SummaryItem label="Next Tool" value={status.data?.latest_next_tool || report.data.risk_ranking.recommended_next_actions?.[0]?.next_tool || "stop"} />
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle>Timeline</CardTitle></CardHeader>
            <CardContent><Timeline items={timelineItems} /></CardContent>
          </Card>
          <ReportViewer report={report.data} />
          <div className="grid gap-4 xl:grid-cols-2">
            <EvidenceCard title="Evidence" data={report.data.evidence_confidence} />
            <EvidenceCard title="Normalized Results" data={report.data.normalized_results} />
            <EvidenceCard title="Learning Feedback" data={learning.data ?? report.data.learning_feedback} />
            <EvidenceCard title="CVE Matches" data={report.data.matched_cves} />
          </div>
          <Card>
            <CardHeader><CardTitle>Decision History</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {(decisions.data ?? report.data.decision_scores).map((decision, index) => <DecisionCard key={index} decision={decision} index={index} />)}
            </CardContent>
          </Card>
        </div>
        <div className="space-y-4">
          <WorkerStatus status={status.data} />
          <ToolQueue tasks={report.data.tool_tasks} />
          <Card>
            <CardHeader><CardTitle>Open Ports</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {(ports.data ?? report.data.open_ports).map((port, index) => (
                <div className="rounded-md border border-border bg-muted/25 p-3 text-sm" key={index}>
                  {port.port}/{port.protocol} - {port.service || "unknown"} - {port.state || "n/a"}
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>MITRE Mapping</CardTitle></CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              {report.data.mitre_mapping.map((item, index) => <MITREBadge key={index} phase={item.mitre_phase} technique={item.mitre_technique} />)}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="section-title">{label}</div>
      <div className="mt-1 truncate font-medium">{value}</div>
    </div>
  );
}

function latestConfidence(decisions?: Array<{ confidence?: number | null }>) {
  const value = decisions?.find((decision) => typeof decision.confidence === "number")?.confidence;
  return typeof value === "number" ? `${Math.round(value * 100)}%` : "n/a";
}
