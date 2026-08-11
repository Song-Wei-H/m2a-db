import { useQueries } from "@tanstack/react-query";
import { BrainCircuit } from "lucide-react";
import { api } from "../api/client";
import { DecisionCard } from "../components/DecisionCard";
import { EvidenceCard } from "../components/EvidenceCard";
import { EmptyState, ErrorState } from "../components/Status";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { useKnownTargets } from "../hooks/useKnownTargets";

export function DecisionCenter() {
  const { ids } = useKnownTargets();
  const reports = useQueries({
    queries: ids.map((id) => ({ queryKey: ["target-report", id], queryFn: () => api.targetReport(id) }))
  });
  const firstError = reports.find((query) => query.isError)?.error;
  const decisionGroups = reports.flatMap((query) =>
    query.data
      ? query.data.decision_scores.map((decision, index) => ({
          decision,
          index,
          report: query.data
        }))
      : []
  );

  if (!ids.length) return <EmptyState title="No decisions loaded" message="Open target IDs to hydrate Decision Center from existing target report APIs." />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><BrainCircuit className="h-4 w-4 text-primary" />Decision Center</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Each flow is rendered from decision score fields exposed by the backend. Extended governance fields are shown when present in report extensions.
        </CardContent>
      </Card>
      {firstError ? <ErrorState message={firstError.message} /> : null}
      {decisionGroups.length ? (
        decisionGroups.map(({ decision, index, report }) => (
          <div className="space-y-3" key={`${report.target_summary.target_id}-${index}`}>
            <DecisionCard decision={decision} index={index} />
            <div className="grid gap-3 xl:grid-cols-3">
              <EvidenceCard title="Decision Trace" data={decision} />
              <EvidenceCard title="Learning Prior" data={report.learning_ranking_summary ?? report.learning_feedback_summary} />
              <EvidenceCard title="UCB Score / Governance Result" data={report.round_value_summary ?? report.auto_loop_decisions} />
            </div>
          </div>
        ))
      ) : (
        <EmptyState title="No decision records" message="The loaded reports do not contain decision_scores yet." />
      )}
    </div>
  );
}
