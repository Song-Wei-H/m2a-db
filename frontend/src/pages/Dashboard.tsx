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
  if (!overview.data) return <EmptyState title="儀表板無法使用" message="後端沒有回傳儀表板摘要資料。" />;

  const data = overview.data;
  const pending = Math.max(data.targets_total - data.targets_completed - data.targets_running - data.targets_failed, 0);
  const severityData = [
    { name: "重大", value: data.critical_findings },
    { name: "高", value: data.high_findings },
    { name: "中", value: data.medium_findings },
    { name: "具 CVE 證據", value: data.cve_backed_findings }
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
          <h1 className="text-2xl font-semibold tracking-tight">儀表板</h1>
          <p className="text-sm text-muted-foreground">顯示 FastAPI 提供的即時受治理測試狀態。</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => overview.refetch()}>
            <RefreshCw className="h-4 w-4" />
            重新整理
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              void document.documentElement.requestFullscreen?.();
              notify({ title: "已切換儀表板全螢幕", tone: "success" });
            }}
          >
            <Maximize2 className="h-4 w-4" />
            全螢幕
          </Button>
          <Button
            onClick={() => {
              navigator.clipboard?.writeText(JSON.stringify(data, null, 2));
              notify({ title: "儀表板資料已複製", message: "摘要 JSON 已複製到剪貼簿。", tone: "success" });
            }}
          >
            <Download className="h-4 w-4" />
            匯出
          </Button>
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard title="目標總數" value={data.targets_total} icon={Target} />
        <MetricCard title="執行中目標" value={data.targets_running} icon={Activity} tone="green" />
        <MetricCard title="已完成目標" value={data.targets_completed} icon={CheckCircle2} tone="green" />
        <MetricCard title="等待中目標" value={pending} icon={Clock3} tone="yellow" />
        <MetricCard title="平均風險" value={averageRisk(targets)} icon={Gauge} tone="orange" />
        <MetricCard title="高風險數量" value={data.critical_findings + data.high_findings} icon={AlertTriangle} tone="red" />
        <MetricCard title="工具成功率" value={toolSuccessRate} icon={Crosshair} detail="來源：工具結果" />
        <MetricCard title="目前執行中 Worker" value={activeWorkers} icon={ServerCog} detail="執行中的工具任務" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartCard title="風險趨勢">
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
        <ChartCard title="依嚴重度分類的發現">
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
        <ChartCard title="工具使用情形">
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
        <ChartCard title="MITRE ATT&CK 分布">
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
            <CardTitle>最近目標</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {targets.length ? targets.map((target) => <TargetCard key={target.target_id} target={target} />) : <EmptyState title="尚無目標摘要" message="建立或開啟目標後即可顯示資料。" />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>最近決策</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {decisions.length ? decisions.slice(0, 3).map((decision, index) => <DecisionCard decision={decision} index={index} key={index} />) : <EmptyState title="尚無決策" message="產生目標報告後將顯示決策歷史。" />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>最近報告</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {targets.length ? targets.map((target) => <TargetCard key={target.target_id} target={target} />) : <EmptyState title="尚無報告" message="開啟目標後即可取得該目標報告。" />}
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
