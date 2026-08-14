import { Activity, Cpu, ServerCog } from "lucide-react";
import type { RunStatus } from "../api/types";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";

export function WorkerStatus({ status }: { status?: RunStatus }) {
  const active = status?.running_task_count ?? 0;
  const total =
    (status?.pending_task_count ?? 0) +
    (status?.running_task_count ?? 0) +
    (status?.completed_task_count ?? 0) +
    (status?.failed_task_count ?? 0);
  const progress = total ? Math.round((((status?.completed_task_count ?? 0) + (status?.failed_task_count ?? 0)) / total) * 100) : 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ServerCog className="h-4 w-4 text-primary" />
          Worker 狀態
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-md border border-border bg-muted/30 p-3">
            <div className="flex items-center gap-2 text-xs uppercase text-muted-foreground">
              <Activity className="h-4 w-4 text-green-300" />
              執行中 Worker
            </div>
            <div className="mt-1 text-2xl font-semibold">{active}</div>
          </div>
          <div className="rounded-md border border-border bg-muted/30 p-3">
            <div className="flex items-center gap-2 text-xs uppercase text-muted-foreground">
              <Cpu className="h-4 w-4 text-primary" />
              執行中工具
            </div>
            <div className="mt-1 truncate text-sm font-medium">{status?.latest_next_tool || "閒置"}</div>
          </div>
        </div>
        <div>
          <div className="mb-2 flex justify-between text-xs text-muted-foreground">
            <span>進度</span>
            <span>{progress}%</span>
          </div>
          <progress
            className="h-2 w-full overflow-hidden rounded-full [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-primary"
            value={progress}
            max={100}
          />
        </div>
      </CardContent>
    </Card>
  );
}
