import { ArrowRight, Ban, BrainCircuit, CheckCircle2, Gauge, ShieldCheck, type LucideIcon } from "lucide-react";
import type { Decision } from "../api/types";
import { Card, CardContent } from "./ui/card";
import { MITREBadge, RiskBadge } from "./Badges";
import { formatPercent } from "../lib/utils";

export function DecisionCard({ decision, index }: { decision: Decision; index: number }) {
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
          <FlowNode icon={Ban} label="未採用工具" value="已停用：端點未開放" />
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
