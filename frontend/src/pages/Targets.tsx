import { useMutation, useQueries, useQueryClient } from "@tanstack/react-query";
import { ArrowDownUp, Plus, Search, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { RunStatus, TargetCreatePayload, TargetSummary } from "../api/types";
import { RiskBadge } from "../components/Badges";
import { EmptyState, ErrorState, Loading } from "../components/Status";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Select } from "../components/ui/select";
import { Table, TBody, TD, TH, THead, TR } from "../components/ui/table";
import { useKnownTargets } from "../hooks/useKnownTargets";
import { useToast } from "../components/ToastProvider";

export function TargetsPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const knownTargets = useKnownTargets();
  const { notify } = useToast();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [sort, setSort] = useState<"risk" | "target" | "round">("risk");
  const [lookupId, setLookupId] = useState("");
  const [newTarget, setNewTarget] = useState<TargetCreatePayload>({ target: "", target_type: "ip", scope: "internal" });

  const queries = useQueries({
    queries: knownTargets.ids.map((id) => ({
      queryKey: ["target-summary", id],
      queryFn: () => api.targetSummary(id)
    }))
  });
  const statusQueries = useQueries({
    queries: knownTargets.ids.map((id) => ({
      queryKey: ["target-run-status", id],
      queryFn: () => api.targetRunStatus(id),
      refetchInterval: 10_000
    }))
  });
  const targets = queries.flatMap((query) => (query.data ? [query.data] : []));
  const statusesByTarget = new Map(
    statusQueries.flatMap((query) => (query.data ? [[query.data.target_id, query.data] as const] : []))
  );
  const isLoading = queries.some((query) => query.isLoading);
  const firstError = queries.find((query) => query.isError)?.error;

  const createTarget = useMutation({
    mutationFn: api.createTarget,
    onSuccess: (result) => {
      knownTargets.add(result.target_id);
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      notify({ title: "目標已建立", message: `目標 ${result.target_id} 已排入測試佇列。`, tone: "success" });
      navigate(`/targets/${result.target_id}`);
    }
  });

  const filtered = useMemo(() => {
    return targets
      .filter((target) => {
        const haystack = `${target.target} ${target.scope} ${target.status}`.toLowerCase();
        return haystack.includes(search.toLowerCase()) && (status === "all" || target.status === status);
      })
      .sort((a, b) => {
        if (sort === "target") return String(a.target).localeCompare(String(b.target));
        if (sort === "round") return (b.current_round ?? 0) - (a.current_round ?? 0);
        return (b.highest_risk_score ?? 0) - (a.highest_risk_score ?? 0);
      });
  }, [targets, search, status, sort]);

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <Card>
          <CardHeader>
            <CardTitle>測試目標</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-3 md:grid-cols-[1fr_160px_160px]">
              <div className="relative">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜尋目標" />
              </div>
              <Select value={status} onChange={(event) => setStatus(event.target.value)}>
                <option value="all">全部狀態</option>
                <option value="pending">等待中</option>
                <option value="running">執行中</option>
                <option value="completed">已完成</option>
                <option value="failed">失敗</option>
              </Select>
              <Button variant="outline" onClick={() => setSort(sort === "risk" ? "target" : sort === "target" ? "round" : "risk")}>
                <ArrowDownUp className="h-4 w-4" />
                排序：{sort === "risk" ? "風險" : sort === "target" ? "目標" : "輪次"}
              </Button>
            </div>
            {isLoading ? <Loading /> : null}
            {firstError ? <ErrorState message={firstError.message} /> : null}
            {filtered.length ? (
              <Table>
                <THead>
                  <TR>
                    <TH>目標</TH>
                    <TH>範圍</TH>
                    <TH>狀態</TH>
                    <TH>目前輪次</TH>
                    <TH>風險</TH>
                    <TH>目前工具</TH>
                    <TH>建立時間</TH>
                    <TH />
                  </TR>
                </THead>
                <TBody>
                  {filtered.map((target) => (
                    <TargetRow
                      key={target.target_id}
                      target={target}
                      runStatus={target.target_id ? statusesByTarget.get(target.target_id) : undefined}
                      onOpen={() => navigate(`/targets/${target.target_id}`)}
                      onRemove={() => knownTargets.remove(target.target_id ?? 0)}
                    />
                  ))}
                </TBody>
              </Table>
            ) : (
              <EmptyState title="尚未載入目標" message="使用目標 ID 開啟既有目標，或建立新目標。" />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>目標操作</CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="space-y-2">
              <div className="section-title">開啟既有目標</div>
              <div className="flex gap-2">
                <Input value={lookupId} onChange={(event) => setLookupId(event.target.value)} placeholder="目標 ID" />
                <Button
                  onClick={() => {
                    const id = Number(lookupId);
                    if (Number.isInteger(id) && id > 0) {
                      knownTargets.add(id);
                      navigate(`/targets/${id}`);
                    }
                  }}
                >
                  開啟
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <div className="section-title">建立目標</div>
              <Input value={newTarget.target} onChange={(event) => setNewTarget({ ...newTarget, target: event.target.value })} placeholder="192.0.2.10" />
              <div className="grid grid-cols-2 gap-2">
                <Select value={newTarget.target_type} onChange={(event) => setNewTarget({ ...newTarget, target_type: event.target.value as "ip" | "domain" | "cidr" })}>
                  <option value="ip">IP</option>
                  <option value="domain">網域</option>
                  <option value="cidr">CIDR</option>
                </Select>
                <Select value={newTarget.scope} onChange={(event) => setNewTarget({ ...newTarget, scope: event.target.value as "internal" | "external" })}>
                  <option value="internal">內部</option>
                  <option value="external">外部</option>
                </Select>
              </div>
              <Button className="w-full" disabled={!newTarget.target || createTarget.isPending} onClick={() => createTarget.mutate(newTarget)}>
                <Plus className="h-4 w-4" />
                建立
              </Button>
              {createTarget.isError ? <p className="text-sm text-red-300">{createTarget.error.message}</p> : null}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function TargetRow({
  target,
  runStatus,
  onOpen,
  onRemove
}: {
  target: TargetSummary;
  runStatus?: RunStatus;
  onOpen: () => void;
  onRemove: () => void;
}) {
  return (
    <TR onDoubleClick={onOpen}>
      <TD>
        <Link className="font-medium text-primary hover:underline" to={`/targets/${target.target_id}`}>
          {target.target || `Target ${target.target_id}`}
        </Link>
      </TD>
      <TD>{formatScope(target.scope)}</TD>
      <TD>{formatStatus(target.status)}</TD>
      <TD>{target.current_round ?? "n/a"}</TD>
      <TD>
        <RiskBadge score={target.highest_risk_score} severity={target.highest_severity} />
      </TD>
      <TD>{runStatus?.latest_next_tool || runStatus?.latest_next_action || "閒置"}</TD>
      <TD className="text-muted-foreground">後端未提供建立時間</TD>
      <TD>
        <Button variant="ghost" size="icon" onClick={onRemove} aria-label="從本機清單移除目標">
          <Trash2 className="h-4 w-4" />
        </Button>
      </TD>
    </TR>
  );
}

function formatStatus(status?: string | null) {
  return ({ pending: "等待中", running: "執行中", completed: "已完成", failed: "失敗" } as Record<string, string>)[String(status)] || status || "無資料";
}

function formatScope(scope?: string | null) {
  return ({ internal: "內部", external: "外部" } as Record<string, string>)[String(scope)] || scope || "無資料";
}
