import { ArrowRight, BrainCircuit, CheckCircle2, Gauge, ShieldCheck, Wrench, type LucideIcon } from "lucide-react";
import type { Decision, ToolTask } from "../api/types";
import { Card, CardContent } from "./ui/card";
import { MITREBadge, RiskBadge } from "./Badges";
import { formatPercent } from "../lib/utils";

export function DecisionCard({ decision, index, toolTasks }: { decision: Decision; index: number; toolTasks?: ToolTask[] }) {
  const adoption = toolAdoptionStatus(decision, toolTasks);
  return (
    <Card>
      <CardContent className="pt-4">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-xs uppercase text-muted-foreground">決策 #{index + 1}</div>
            <div className="mt-1 text-base font-semibold">{decision.next_action || "等待決策"}</div>
          </div>
          <RiskBadge score={decision.risk_score} severity={decision.severity} />
        </div>
        <div className="grid gap-3 lg:grid-cols-5">
          <FlowNode icon={BrainCircuit} label="證據" value={decision.reason || "等待證據"} />
          <FlowNode icon={Gauge} label="信心度" value={formatPercent(decision.confidence)} />
          <FlowNode icon={ShieldCheck} label="治理結果" value={decision.next_action || "等待中"} />
          <FlowNode icon={CheckCircle2} label="選定工具" value={decision.next_tool || "停止"} />
          <FlowNode icon={Wrench} label="工具採用狀態" value={adoption} />
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <MITREBadge phase={decision.mitre_phase} technique={decision.mitre_technique} />
          <span className="rounded-md border border-border bg-muted/30 px-2 py-1 text-xs text-muted-foreground">
            當後端提供擴充欄位時，此處會顯示先驗學習與 UCB 決策軌跡。
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

export function toolAdoptionStatus(decision: Decision, toolTasks?: ToolTask[]): string {
  if (!decision.next_tool) return "未選擇工具";
  if (!toolTasks) return "無資料（未提供 ToolTask lineage）";
  const decisionId = decision.decision_score_id ?? decision.id;
  const task = toolTasks.find((item) =>
    decisionId != null
      ? item.decision_score_id === decisionId && item.tool_name === decision.next_tool
      : item.tool_name === decision.next_tool
  );
  if (!task) return "無資料（尚未建立對應 ToolTask）";
  const status = String(task.status || "unknown").toLowerCase();
  if (status === "completed") return "已採用：執行完成";
  if (status === "running") return "已採用：執行中";
  if (status === "pending") return "已採用：等待執行";
  if (status === "failed") return `已採用：執行失敗${task.reject_reason ? `（${task.reject_reason}）` : ""}`;
  if (status === "rejected" || status === "cancelled") {
    return `未採用：${task.reject_reason || (status === "rejected" ? "已拒絕" : "已取消")}`;
  }
  return `狀態：${status}`;
}

function FlowNode({
  icon: Icon,
  label,
  value
}: {
  icon: LucideIcon;
  label: string;
  value: string;
}) {
  return (
    <div className="relative rounded-md border border-border bg-muted/25 p-3">
      <div className="flex items-center gap-2 text-xs uppercase text-muted-foreground">
        <Icon className="h-4 w-4 text-primary" />
        {label}
      </div>
      <div className="mt-2 max-h-16 overflow-hidden text-sm">{value}</div>
      <ArrowRight className="absolute -right-3 top-1/2 hidden h-4 w-4 -translate-y-1/2 text-border lg:block" />
    </div>
  );
}
