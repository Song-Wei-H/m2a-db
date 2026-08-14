import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardCheck } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import { ApprovalDialog } from "../components/ApprovalDialog";
import { EmptyState, ErrorState, Loading } from "../components/Status";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "../components/ui/table";
import { useToast } from "../components/ToastProvider";

export function ApprovalCenter() {
  const queryClient = useQueryClient();
  const { notify } = useToast();
  const [dialog, setDialog] = useState<{ taskId: number | null; action: "approve" | "reject" | null }>({ taskId: null, action: null });
  const pending = useQuery({ queryKey: ["pending-approvals"], queryFn: api.pendingApprovals, refetchInterval: 15_000 });
  const approve = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason?: string }) => api.approveTask(id, reason),
    onSuccess: () => {
      notify({ title: "任務已核准", tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["pending-approvals"] });
    }
  });
  const reject = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason?: string }) => api.rejectTask(id, reason),
    onSuccess: () => {
      notify({ title: "任務已拒絕", tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["pending-approvals"] });
    }
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><ClipboardCheck className="h-4 w-4 text-primary" />核准中心</CardTitle></CardHeader>
        <CardContent>
          {pending.isLoading ? <Loading /> : null}
          {pending.isError ? <ErrorState message={pending.error.message} /> : null}
          {pending.data?.length ? (
            <Table>
              <THead><TR><TH>任務 ID</TH><TH>狀態</TH><TH>內容</TH><TH>理由</TH><TH>操作</TH></TR></THead>
              <TBody>
                {pending.data.map((task) => (
                  <TR key={task.task_id}>
                    <TD className="font-mono">{task.task_id}</TD>
                    <TD>等待核准</TD>
                    <TD><div>{task.tool_name}</div><div className="text-xs text-muted-foreground">{task.target} · {task.scope || "scope pending"}</div></TD>
                    <TD className="text-muted-foreground"><div>{task.proposal_reason || "未記錄提案理由"}</div><div className="text-xs">治理門檻：{task.approval_reason || "未記錄核准門檻理由"}</div></TD>
                    <TD className="space-x-2 text-right">
                      <Button size="sm" onClick={() => setDialog({ taskId: task.task_id, action: "approve" })}>核准</Button>
                      <Button size="sm" variant="destructive" onClick={() => setDialog({ taskId: task.task_id, action: "reject" })}>拒絕</Button>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          ) : (
            <EmptyState title="沒有待核准任務" message="後端回傳的核准佇列目前為空。" />
          )}
        </CardContent>
      </Card>
      <ApprovalDialog
        taskId={dialog.taskId}
        action={dialog.action}
        onClose={() => setDialog({ taskId: null, action: null })}
        onSubmit={(reason) => {
          if (!dialog.taskId || !dialog.action) return;
          if (dialog.action === "approve") approve.mutate({ id: dialog.taskId, reason });
          else reject.mutate({ id: dialog.taskId, reason });
          setDialog({ taskId: null, action: null });
        }}
      />
    </div>
  );
}
