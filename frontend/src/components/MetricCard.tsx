import type { LucideIcon } from "lucide-react";
import { Card, CardContent } from "./ui/card";
import { cn } from "../lib/utils";

export function MetricCard({
  title,
  value,
  icon: Icon,
  tone = "blue",
  detail
}: {
  title: string;
  value: string | number;
  icon: LucideIcon;
  tone?: "blue" | "red" | "orange" | "green" | "yellow";
  detail?: string;
}) {
  const tones = {
    blue: "text-cyan-300 bg-cyan-500/10",
    red: "text-red-300 bg-red-500/10",
    orange: "text-orange-300 bg-orange-500/10",
    green: "text-green-300 bg-green-500/10",
    yellow: "text-yellow-200 bg-yellow-500/10"
  };
  return (
    <Card>
      <CardContent className="flex items-center justify-between gap-3 pt-4">
        <div className="min-w-0">
          <p className="text-xs uppercase text-muted-foreground">{title}</p>
          <p className="mt-1 text-2xl font-semibold">{value}</p>
          {detail ? <p className="mt-1 truncate text-xs text-muted-foreground">{detail}</p> : null}
        </div>
        <div className={cn("rounded-md p-2", tones[tone])}>
          <Icon className="h-5 w-5" />
        </div>
      </CardContent>
    </Card>
  );
}
