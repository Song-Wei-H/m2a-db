import { useQueries, useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Activity, AlertTriangle, CheckCircle2, Clock3, Crosshair, Download, Gauge, Maximize2, RefreshCw, ServerCog, Target } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { api } from "../api/client";
import type { ToolResult } from "../api/types";
import { MetricCard } from "../components/MetricCard";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { EmptyState, ErrorState, Loading } from "../components/Status";
import { TargetCard } from "../components/TargetCard";
import { DecisionCard } from "../components/DecisionCard";
import { useKnownTargets } from "../hooks/useKnownTargets";
import { asNumber } from "../lib/utils";
import { Button } from "../components/ui/button";
import { useToast } from "../components/ToastProvider";

const chartColors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#38bdf8"];

export function Dashboard() {
  const { ids } = useKnownTargets();
  const { notify } = useToast();
  const overview = useQuery({ queryKey: ["dashboard"], queryFn: api.dashboardOverview, refetchInterval: 30_000 });
  const targetQueries = useQueries({
    queries: ids.slice(0, 6).map((id) => ({
      queryKey: ["target-summary", id],
      queryFn: () => api.targetSummary(id)
    }))
  });
  const statusQueries = useQueries({
    queries: ids.slice(0, 6).map((id) => ({
      queryKey: ["target-run-status", id],
      queryFn: () => api.targetRunStatus(id),
      refetchInterval: 10_000
    }))
  });
  const toolResultQueries = useQueries({
    queries: ids.slice(0, 6).map((id) => ({
      queryKey: ["target-tool-results", id],
      queryFn: () => api.targetToolResults(id),
      refetchInterval: 30_000
    }))
  });
  const targets = targetQueries.flatMap((query) => (query.data ? [query.data] : []));
  const runStatuses = statusQueries.flatMap((query) => (query.data ? [query.data] : []));
  const toolResults = toolResultQueries.flatMap((query) => query.data ?? []);
  const decisions = useQueries({
    queries: ids.slice(0, 3).map((id) => ({
      queryKey: ["target-decisions", id],
      queryFn: () => api.targetDecisions(id)
    }))
  }).flatMap((query) => query.data ?? []);

  if (overview.isLoading) return <Loading />;
  if (overview.isError) return <ErrorState message={overview.error.message} />;
  if (!overview.data) return <EmptyState title="Dashboard unavailable" message="The backend did not return dashboard overview data." />;

  const data = overview.data;
  const pending = Math.max(data.targets_total - data.targets_completed - data.targets_running - data.targets_failed, 0);
  const severityData = [
    { name: "Critical", value: data.critical_findings },
    { name: "High", value: data.high_findings },
    { name: "Medium", value: data.medium_findings },
    { name: "CVE-backed", value: data.cve_backed_findings }
  ];
  const riskTrend = targets.map((target, index) => ({
    name: target.target || `T-${target.target_id}`,
    risk: asNumber(target.highest_risk_score),
    index: index + 1
  }));
  const toolUsage = targets.map((target) => ({ name: target.target || `T-${target.target_id}`, tools: target.tool_result_count }));
  const activeWorkers = runStatuses.reduce((sum, status) => sum + status.running_task_count, 0);
  const toolSuccessRate = formatToolSuccessRate(toolResults);
  const mitreDistribution = decisions.reduce<Record<string, number>>((acc, decision) => {
    const key = decision.mitre_phase || "Unmapped";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">Live governed assessment posture from FastAPI endpoints.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => overview.refetch()}>
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              void document.documentElement.requestFullscreen?.();
              notify({ title: "Dashboard fullscreen requested", tone: "success" });
            }}
          >
            <Maximize2 className="h-4 w-4" />
            Full screen
          </Button>
          <Button
            onClick={() => {
              navigator.clipboard?.writeText(JSON.stringify(data, null, 2));
              notify({ title: "Dashboard data copied", message: "Overview JSON is on the clipboard.", tone: "success" });
            }}
          >
            <Download className="h-4 w-4" />
            Export
          </Button>
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard title="Total Targets" value={data.targets_total} icon={Target} />
        <MetricCard title="Running Targets" value={data.targets_running} icon={Activity} tone="green" />
        <MetricCard title="Completed Targets" value={data.targets_completed} icon={CheckCircle2} tone="green" />
        <MetricCard title="Pending Targets" value={pending} icon={Clock3} tone="yellow" />
        <MetricCard title="Average Risk" value={averageRisk(targets)} icon={Gauge} tone="orange" />
        <MetricCard title="High Risk Count" value={data.critical_findings + data.high_findings} icon={AlertTriangle} tone="red" />
        <MetricCard title="Tool Success Rate" value={toolSuccessRate} icon={Crosshair} detail="From /tool-results" />
        <MetricCard title="Current Active Workers" value={activeWorkers} icon={ServerCog} detail="Running tool tasks" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartCard title="Risk Trend">
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={riskTrend}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="index" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Area type="monotone" dataKey="risk" stroke="#38bdf8" fill="#0ea5e9" fillOpacity={0.18} />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Findings by Severity">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Bar dataKey="value">
                {severityData.map((_, index) => (
                  <Cell key={index} fill={chartColors[index]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Tool Usage">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={toolUsage}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Bar dataKey="tools" fill="#38bdf8" />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="MITRE ATT&CK Distribution">
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={Object.entries(mitreDistribution).map(([name, value]) => ({ name, value }))} dataKey="value" nameKey="name">
                {Object.keys(mitreDistribution).map((_, index) => (
                  <Cell key={index} fill={chartColors[index % chartColors.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Recent Targets</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {targets.length ? targets.map((target) => <TargetCard key={target.target_id} target={target} />) : <EmptyState title="No target summaries" message="Create or look up a target to seed this UI from existing APIs." />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recent Decisions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {decisions.length ? decisions.slice(0, 3).map((decision, index) => <DecisionCard decision={decision} index={index} key={index} />) : <EmptyState title="No decisions" message="Decision history appears after target reports expose decisions." />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recent Reports</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {targets.length ? targets.map((target) => <TargetCard key={target.target_id} target={target} />) : <EmptyState title="No reports" message="Reports are available per target once a target ID is known." />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function averageRisk(targets: Array<{ highest_risk_score?: number | null }>) {
  const scores = targets.map((target) => target.highest_risk_score).filter((score): score is number => typeof score === "number");
  if (!scores.length) return "n/a";
  return (scores.reduce((sum, score) => sum + score, 0) / scores.length).toFixed(1);
}

function formatToolSuccessRate(results: ToolResult[]) {
  const measured = results.filter((result) => typeof result.success === "boolean");
  if (!measured.length) return "n/a";
  const successful = measured.filter((result) => result.success).length;
  return `${Math.round((successful / measured.length) * 100)}%`;
}
