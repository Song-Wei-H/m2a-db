import type { TargetReport } from "../api/types";
import { MITREBadge, RiskBadge, SeverityBadge } from "./Badges";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Table, TBody, TD, TH, THead, TR } from "./ui/table";
import { EvidenceCard } from "./EvidenceCard";

export function ReportViewer({ report }: { report: TargetReport }) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>執行摘要</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-3">
          <div>
            <div className="section-title">目標</div>
            <div className="mt-1 font-medium">{report.target_summary.target || "n/a"}</div>
          </div>
          <div>
            <div className="section-title">風險排名</div>
            <div className="mt-1">
              <RiskBadge
                score={report.risk_ranking.highest_risk_score}
                severity={report.risk_ranking.highest_severity}
              />
            </div>
          </div>
          <div>
            <div className="section-title">建議</div>
            <div className="mt-1 text-sm text-muted-foreground">
              {report.remediation_guidance[0] || String(report.remediation[0]?.recommendation || "尚無建議。")}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>開放連接埠</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <THead>
              <TR>
                <TH>Port</TH>
                <TH>Service</TH>
                <TH>Product</TH>
                <TH>State</TH>
              </TR>
            </THead>
            <TBody>
              {report.open_ports.map((port, index) => (
                <TR key={index}>
                  <TD>{port.port}/{port.protocol}</TD>
                  <TD>{port.service || "n/a"}</TD>
                  <TD>{[port.product, port.version].filter(Boolean).join(" ") || "n/a"}</TD>
                  <TD>{port.state || "n/a"}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <EvidenceCard title="工具結果" data={report.tool_results} />
        <EvidenceCard title="證據" data={report.evidence_confidence} />
        <EvidenceCard title="正規化結果" data={report.normalized_results} />
        <EvidenceCard title="學習回饋" data={report.learning_feedback} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>MITRE ATT&CK</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {report.mitre_mapping.length ? (
            report.mitre_mapping.map((item, index) => (
              <MITREBadge key={index} phase={item.mitre_phase} technique={item.mitre_technique} />
            ))
          ) : (
            <span className="text-sm text-muted-foreground">尚無 MITRE 對應。</span>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>CVE 候選與證據引用</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {report.cve_candidate_summary ? (
            <div className="mb-3 grid gap-2 rounded-md border border-border bg-muted/20 p-3 text-xs sm:grid-cols-3">
              <span>完整候選：{String(report.cve_candidate_summary.total_candidates ?? 0)}</span>
              <span>報告顯示：{String(report.cve_candidate_summary.selected_candidates ?? 0)}</span>
              <span>摘要收斂：{String(report.cve_candidate_summary.summarized_candidates ?? 0)}</span>
              <span>KEV：{String(report.cve_candidate_summary.kev_candidates ?? 0)}</span>
              <span>精確版本：{String(report.cve_candidate_summary.exact_version_candidates ?? 0)}</span>
              <span>僅產品匹配：{String(report.cve_candidate_summary.product_only_candidates ?? 0)}</span>
            </div>
          ) : null}
          {report.matched_cves.length ? (
            report.matched_cves.map((cve, index) => (
              <div className="rounded-md border border-border bg-muted/25 p-3" key={index}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-sm">{String(cve.cve || cve.cve_id || "CVE pending")}</span>
                  <SeverityBadge severity={String(cve.severity || "unknown")} />
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  CVSS {String(cve.cvss_score || cve.cvss || "n/a")} - EPSS {String(cve.epss || "n/a")}
                </div>
                <div className="mt-2 text-xs">
                  <span className="font-medium">證據層級：</span>{String(cve.evidence_level || "SOURCE_CLAIM")} · {String(cve.finding_status || "候選")}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{String(cve.evidence_notice || "尚未完成目標版本驗證。")}</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {Array.isArray(cve.evidence_references) ? cve.evidence_references.map((reference, referenceIndex) => {
                    const item = reference as Record<string, unknown>;
                    return <a className="text-xs text-primary hover:underline" href={String(item.url)} target="_blank" rel="noreferrer" key={referenceIndex}>{String(item.authority)}</a>;
                  }) : null}
                </div>
              </div>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">尚無 CVE 比對結果。</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
