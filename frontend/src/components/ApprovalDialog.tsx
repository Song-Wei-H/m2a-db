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
    <Dialog open={taskId !== null && action !== null} title={action === "reject" ? "拒絕任務" : "核准任務"} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">任務 ID {taskId}</p>
        <Input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="請填寫理由" />
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          <Button disabled={!reason.trim()} variant={action === "reject" ? "destructive" : "default"} onClick={() => onSubmit(reason.trim())}>
            確認
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
