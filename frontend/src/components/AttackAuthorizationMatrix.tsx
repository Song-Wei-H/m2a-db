import { ShieldCheck, LockKeyhole } from "lucide-react";
import type { AttackAuthorizationLevel } from "../api/types";
import { Button } from "./ui/button";

const PRESETS = [
  { label: "弱點評估", depth: 1 },
  { label: "滲透測試", depth: 3 },
  { label: "紅藍隊演練", depth: 7 }
];

export function AttackAuthorizationMatrix({
  levels,
  value,
  onChange,
  compact = false
}: {
  levels: AttackAuthorizationLevel[];
  value: number;
  onChange: (depth: number) => void;
  compact?: boolean;
}) {
  const selected = levels.find((level) => level.level === value);

  return (
    <section aria-label="Engagement authorization depth" className="space-y-4">
      <p className="text-sm text-muted-foreground">
        選擇本次安全評估允許的最大行為深度。較高層級包含前方層級，但實際行動仍須符合證據、工具契約、目標範圍與執行授權條件。
      </p>
      <p className="text-xs text-muted-foreground">這是 M2A 的授權上限選擇器，不代表目前攻擊進度；ATT&amp;CK tactics 分類與授權深度是不同概念。</p>
      <p className="text-xs text-amber-700 dark:text-amber-400">目前此矩陣套用於 8 個 authorization-first Action。legacy `dirb_safe` 尚未完成 Action Contract 遷移，仍在矩陣涵蓋範圍之外。</p>
      <div className={`grid gap-2 ${compact ? "grid-cols-2" : "grid-cols-2 md:grid-cols-4 2xl:grid-cols-7"}`}>
        {levels.map((level) => {
          const included = level.level <= value;
          const isSelected = level.level === value;
          return (
            <button
              key={level.level}
              type="button"
              aria-pressed={isSelected}
              aria-label={`選擇第 ${level.level} 層：${level.name_zh}`}
              onClick={() => onChange(level.level)}
              className={`min-h-32 rounded-lg border p-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                isSelected
                  ? "border-primary bg-primary/10 ring-1 ring-primary"
                  : included
                    ? "border-emerald-500/50 bg-emerald-500/5 hover:bg-emerald-500/10"
                    : "border-border bg-muted/20 text-muted-foreground hover:bg-muted/50"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-lg font-semibold">{level.level}</span>
                {included ? <ShieldCheck className="h-4 w-4 text-emerald-500" /> : <LockKeyhole className="h-4 w-4" />}
              </div>
              <div className="mt-2 text-sm font-medium leading-snug">{level.name_zh}</div>
              <div className="mt-1 text-xs leading-snug">{level.tactics.join(" · ")}</div>
              <div className={`mt-2 text-[11px] font-medium ${included ? "text-emerald-600 dark:text-emerald-400" : ""}`}>
                {isSelected ? "授權上限" : included ? "包含於授權" : "未授權"}
              </div>
            </button>
          );
        })}
      </div>
      <div className="rounded-md border border-border bg-muted/20 p-3 text-sm" aria-live="polite">
        <div className="font-medium">{selected ? `第 ${selected.level} 層：${selected.name_zh}` : "載入授權層級…"}</div>
        {selected ? <p className="mt-1 text-muted-foreground">{selected.description}</p> : null}
        {selected && selected.registered_actions.length > 0 ? (
          <p className="mt-2 text-xs text-muted-foreground">目前對應 action：{selected.registered_actions.join("、")}</p>
        ) : selected ? (
          <p className="mt-2 text-xs text-muted-foreground">此層本身目前沒有已註冊的可執行 action；前序包含層級仍依各自 action contract 執行。</p>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="mr-1 text-xs text-muted-foreground">快速預設（只設定選擇值）：</span>
        {PRESETS.map((preset) => (
          <Button
            key={preset.label}
            type="button"
            size="sm"
            variant={value === preset.depth ? "secondary" : "outline"}
            aria-pressed={value === preset.depth}
            onClick={() => onChange(preset.depth)}
          >
            {preset.label}
          </Button>
        ))}
      </div>
    </section>
  );
}
