import { Link, useNavigate } from "react-router-dom";
import type { TargetSummary } from "../api/types";
import { RiskBadge } from "./Badges";
import { Card, CardContent } from "./ui/card";
import { ContextMenu } from "./ContextMenu";

export function TargetCard({ target }: { target: TargetSummary }) {
  const navigate = useNavigate();
  return (
    <ContextMenu
      label="target"
      onCopy={() => navigator.clipboard?.writeText(String(target.target_id))}
      onOpen={() => navigate(`/targets/${target.target_id}`)}
    >
      <Link to={`/targets/${target.target_id}`} className="block">
        <Card className="transition-colors hover:border-primary/50">
          <CardContent className="pt-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate font-medium">{target.target || `Target ${target.target_id}`}</div>
                <div className="mt-1 text-xs uppercase text-muted-foreground">{target.scope || "scope pending"}</div>
              </div>
              <RiskBadge score={target.highest_risk_score} severity={target.highest_severity} />
            </div>
            <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs text-muted-foreground">
              <span>{target.open_port_count} ports</span>
              <span>{target.tool_result_count} results</span>
              <span>{target.decision_count} decisions</span>
            </div>
          </CardContent>
        </Card>
      </Link>
    </ContextMenu>
  );
}
