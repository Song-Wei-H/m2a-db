import { useMutation, useQueries } from "@tanstack/react-query";
import { Download, ExternalLink, FileJson, FileText, Package, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../api/client";
import { ReportViewer } from "../components/ReportViewer";
import { EmptyState, ErrorState } from "../components/Status";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Select } from "../components/ui/select";
import { useKnownTargets } from "../hooks/useKnownTargets";
import { useToast } from "../components/ToastProvider";

export function ReportCenter() {
  const { ids } = useKnownTargets();
  const { notify } = useToast();
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState(ids[0] ?? 0);
  const reports = useQueries({
    queries: ids.map((id) => ({ queryKey: ["target-report", id], queryFn: () => api.targetReport(id) }))
  });
  const firstError = reports.find((query) => query.isError)?.error;
  const exportReport = useMutation({
    mutationFn: ({ targetId, format }: { targetId: number; format: "html" | "pdf" | "json" | "all" }) => api.exportReport(targetId, format),
    onSuccess: (result) => notify({ title: "Report exported", message: `${Object.keys(result.artifacts).length} verified artifact(s) ready.`, tone: "success" }),
    onError: (error) => notify({ title: "Export failed", message: error.message, tone: "error" })
  });
  const loadedReports = reports.flatMap((query) => (query.data ? [query.data] : []));
  const filtered = useMemo(
    () => loadedReports.filter((report) => `${report.target_summary.target} ${report.target_summary.status}`.toLowerCase().includes(search.toLowerCase())),
    [loadedReports, search]
  );
  const selected = loadedReports.find((report) => report.target_summary.target_id === selectedId) ?? filtered[0];
  const selectedTargetId = selected?.target_summary.target_id;

  if (!ids.length) return <EmptyState title="No reports loaded" message="Reports are exposed through /targets/{id}/report, so open a target first." />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><FileText className="h-4 w-4 text-primary" />Report Center</CardTitle></CardHeader>
        <CardContent className="grid gap-3 lg:grid-cols-[1fr_180px_repeat(4,auto)]">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search reports" />
          </div>
          <Select value={String(selectedTargetId ?? selectedId)} onChange={(event) => setSelectedId(Number(event.target.value))}>
            {filtered.map((report) => <option key={report.target_summary.target_id} value={report.target_summary.target_id ?? 0}>{report.target_summary.target}</option>)}
          </Select>
          <Button disabled={!selectedTargetId} onClick={() => selectedTargetId && exportReport.mutate({ targetId: selectedTargetId, format: "html" })}>
            <Download className="h-4 w-4" />HTML
          </Button>
          <Button variant="outline" disabled={!selectedTargetId} onClick={() => selectedTargetId && exportReport.mutate({ targetId: selectedTargetId, format: "pdf" })}>
            <Download className="h-4 w-4" />PDF
          </Button>
          <Button variant="outline" disabled={!selectedTargetId} onClick={() => selectedTargetId && exportReport.mutate({ targetId: selectedTargetId, format: "json" })}>
            <FileJson className="h-4 w-4" />JSON
          </Button>
          <Button variant="outline" disabled={!selectedTargetId} onClick={() => selectedTargetId && exportReport.mutate({ targetId: selectedTargetId, format: "all" })}>
            <Package className="h-4 w-4" />All
          </Button>
        </CardContent>
      </Card>
      {firstError ? <ErrorState message={firstError.message} /> : null}
      {exportReport.data && selectedTargetId ? (
        <Card>
          <CardHeader><CardTitle>Generated artifacts</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {Object.entries(exportReport.data.artifacts).map(([format, artifact]) => (
              <div className="grid gap-2 rounded-md border border-border bg-muted/20 p-3 text-sm md:grid-cols-[80px_100px_1fr_auto] md:items-center" key={format}>
                <strong className="uppercase">{format}</strong>
                <span>{formatBytes(artifact.size)}</span>
                <code className="truncate text-xs text-muted-foreground" title={artifact.sha256}>SHA-256 {artifact.sha256}</code>
                <Button asChild size="sm" variant="outline">
                  <a href={api.reportDownloadUrl(selectedTargetId, format as "html" | "pdf" | "json")}>
                    <Download className="h-4 w-4" />Download
                  </a>
                </Button>
              </div>
            ))}
            <Button asChild variant="ghost">
              <a href={api.latestReportUrl(selectedTargetId)} rel="noreferrer" target="_blank">
                <ExternalLink className="h-4 w-4" />Open latest HTML report
              </a>
            </Button>
          </CardContent>
        </Card>
      ) : null}
      {selected ? <ReportViewer report={selected} /> : <EmptyState title="No matching reports" message="Adjust search or open another target." />}
    </div>
  );
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}
