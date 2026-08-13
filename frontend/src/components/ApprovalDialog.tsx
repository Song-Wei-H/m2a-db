import { useState } from "react";
import { Dialog } from "./ui/dialog";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

export function ApprovalDialog({
  taskId,
  action,
  onClose,
  onSubmit
}: {
  taskId: number | null;
  action: "approve" | "reject" | null;
  onClose: () => void;
  onSubmit: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  return (
    <Dialog open={taskId !== null && action !== null} title={`${action === "reject" ? "Reject" : "Approve"} task`} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">Task ID {taskId}</p>
        <Input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Reason" />
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={!reason.trim()} variant={action === "reject" ? "destructive" : "default"} onClick={() => onSubmit(reason.trim())}>
            Confirm
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
