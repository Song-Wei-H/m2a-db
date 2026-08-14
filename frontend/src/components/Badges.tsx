import { cn } from "../lib/utils";

const severityClass: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/15 text-red-200",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-200",
  medium: "border-yellow-500/40 bg-yellow-500/15 text-yellow-100",
  low: "border-green-500/40 bg-green-500/15 text-green-200"
};

export function SeverityBadge({ severity }: { severity?: string | null }) {
  const value = (severity || "unknown").toLowerCase();
  const labels: Record<string, string> = { critical: "重大", high: "高", medium: "中", low: "低", unknown: "未知" };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium capitalize",
        severityClass[value] ?? "border-slate-500/40 bg-slate-500/15 text-slate-200"
      )}
    >
      {labels[value] || value}
    </span>
  );
}

export function RiskBadge({ score, severity }: { score?: number | null; severity?: string | null }) {
  const inferred =
    severity ||
    (score === null || score === undefined
      ? "unknown"
      : score >= 9
        ? "critical"
        : score >= 7
          ? "high"
          : score >= 4
            ? "medium"
            : "low");
  return (
    <span className="inline-flex items-center gap-2">
      <SeverityBadge severity={inferred} />
      <span className="font-mono text-sm text-foreground">{score ?? "無資料"}</span>
    </span>
  );
}

export function MITREBadge({ phase, technique }: { phase?: unknown; technique?: unknown }) {
  return (
    <span className="inline-flex max-w-full items-center rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2 py-1 text-xs text-cyan-100">
      <span className="truncate">{String(phase || "尚未對應")}</span>
      <span className="mx-1 text-cyan-500">/</span>
      <span className="truncate">{String(technique || "技術待確認")}</span>
    </span>
  );
}
