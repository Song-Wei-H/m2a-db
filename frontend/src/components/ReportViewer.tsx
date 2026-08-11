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
          <CardTitle>Executive Summary</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-3">
          <div>
            <div className="section-title">Target</div>
            <div className="mt-1 font-medium">{report.target_summary.target || "n/a"}</div>
          </div>
          <div>
            <div className="section-title">Risk Ranking</div>
            <div className="mt-1">
              <RiskBadge
                score={report.risk_ranking.highest_risk_score}
                severity={report.risk_ranking.highest_severity}
              />
            </div>
          </div>
          <div>
            <div className="section-title">Recommendation</div>
            <div className="mt-1 text-sm text-muted-foreground">
              {report.remediation_guidance[0] || String(report.remediation[0]?.recommendation || "No recommendation returned.")}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Open Ports</CardTitle>
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
        <EvidenceCard title="Tool Results" data={report.tool_results} />
        <EvidenceCard title="Evidence" data={report.evidence_confidence} />
        <EvidenceCard title="Normalized Results" data={report.normalized_results} />
        <EvidenceCard title="Learning Feedback" data={report.learning_feedback} />
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
            <span className="text-sm text-muted-foreground">No MITRE mapping returned.</span>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>CVE Matches</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
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
              </div>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">No CVE matches returned.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
