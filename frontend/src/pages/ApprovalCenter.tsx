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
      notify({ title: "Task approved", tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["pending-approvals"] });
    }
  });
  const reject = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason?: string }) => api.rejectTask(id, reason),
    onSuccess: () => {
      notify({ title: "Task rejected", tone: "success" });
      queryClient.invalidateQueries({ queryKey: ["pending-approvals"] });
    }
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><ClipboardCheck className="h-4 w-4 text-primary" />Approval Center</CardTitle></CardHeader>
        <CardContent>
          {pending.isLoading ? <Loading /> : null}
          {pending.isError ? <ErrorState message={pending.error.message} /> : null}
          {pending.data?.length ? (
            <Table>
              <THead><TR><TH>Task ID</TH><TH>Status</TH><TH>Reason</TH><TH>History</TH><TH /></TR></THead>
              <TBody>
                {pending.data.map((id) => (
                  <TR key={id}>
                    <TD className="font-mono">{id}</TD>
                    <TD>pending approval</TD>
                    <TD className="text-muted-foreground">Disabled: endpoint returns task IDs only.</TD>
                    <TD className="text-muted-foreground">Disabled: history endpoint not exposed.</TD>
                    <TD className="space-x-2 text-right">
                      <Button size="sm" onClick={() => setDialog({ taskId: id, action: "approve" })}>Approve</Button>
                      <Button size="sm" variant="destructive" onClick={() => setDialog({ taskId: id, action: "reject" })}>Reject</Button>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          ) : (
            <EmptyState title="No pending approvals" message="The backend returned an empty approval queue." />
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
