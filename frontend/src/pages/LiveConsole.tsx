import { useQueries } from "@tanstack/react-query";
import { Terminal } from "lucide-react";
import { api } from "../api/client";
import { EvidenceCard } from "../components/EvidenceCard";
import { EmptyState, ErrorState } from "../components/Status";
import { WorkerStatus } from "../components/WorkerStatus";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Select } from "../components/ui/select";
import { useKnownTargets } from "../hooks/useKnownTargets";
import { useRealtimeFeed } from "../hooks/useRealtimeFeed";
import { useState } from "react";

export function LiveConsole() {
  const { ids } = useKnownTargets();
  const [selectedId, setSelectedId] = useState(ids[0] ?? 0);
  const realtime = useRealtimeFeed(selectedId);
  const [status, report] = useQueries({
    queries: [
      { queryKey: ["target-run-status", selectedId], queryFn: () => api.targetRunStatus(selectedId), enabled: selectedId > 0, refetchInterval: 5_000 },
      { queryKey: ["target-report", selectedId], queryFn: () => api.targetReport(selectedId), enabled: selectedId > 0, refetchInterval: 10_000 }
    ]
  });

  if (!ids.length) return <EmptyState title="尚未選擇目標" message="請先開啟或建立目標，即時主控台才能取得執行狀態。" />;
  const firstError = status.isError ? status.error : report.isError ? report.error : null;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Terminal className="h-4 w-4 text-primary" />即時主控台</CardTitle>
        </CardHeader>
        <CardContent>
          <Select value={String(selectedId)} onChange={(event) => setSelectedId(Number(event.target.value))}>
            {ids.map((id) => <option value={id} key={id}>目標 {id}</option>)}
          </Select>
        </CardContent>
      </Card>
      {firstError ? <ErrorState message={firstError.message} /> : null}
      <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
        <WorkerStatus status={status.data} />
        <div className="grid gap-4">
          <EvidenceCard title="任務佇列" data={report.data?.tool_tasks ?? []} />
          <EvidenceCard title="執行中工具" data={status.data?.latest_next_tool ?? "閒置"} />
          <EvidenceCard title="工具輸出" data={report.data?.tool_results ?? []} />
          <EvidenceCard title="決策輸出" data={report.data?.decision_scores ?? []} />
          <EvidenceCard title="學習更新" data={report.data?.learning_feedback ?? []} />
          <EvidenceCard title={`紀錄串流（${realtime.status}）`} data={realtime.messages.length ? realtime.messages : (report.data?.auto_loop_decisions ?? [])} />
        </div>
      </div>
    </div>
  );
}
