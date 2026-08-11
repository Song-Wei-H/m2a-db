import { CheckCircle2, Clock3, PlayCircle, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { compactText } from "../lib/utils";

const statusIcon = {
  pending: Clock3,
  running: PlayCircle,
  completed: CheckCircle2,
  failed: XCircle
};

export function ToolQueue({ tasks }: { tasks: Array<Record<string, unknown>> }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Tool Queue</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {tasks.length ? (
          tasks.map((task, index) => {
            const status = String(task.status || "pending").toLowerCase();
            const Icon = statusIcon[status as keyof typeof statusIcon] ?? Clock3;
            return (
              <div className="flex items-center justify-between rounded-md border border-border bg-muted/30 p-3" key={index}>
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium">{compactText(task.tool_name)}</div>
                  <div className="text-xs text-muted-foreground">Priority {compactText(task.priority)}</div>
                </div>
                <div className="flex items-center gap-2 text-xs uppercase text-muted-foreground">
                  <Icon className="h-4 w-4 text-primary" />
                  {status}
                </div>
              </div>
            );
          })
        ) : (
          <p className="text-sm text-muted-foreground">No queued tool tasks in this report.</p>
        )}
      </CardContent>
    </Card>
  );
}
