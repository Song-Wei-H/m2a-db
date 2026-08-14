import { Link, useLocation } from "react-router-dom";
import { ChevronRight, Home } from "lucide-react";

export function Breadcrumbs() {
  const location = useLocation();
  const parts = location.pathname.split("/").filter(Boolean);
  return (
    <nav className="flex min-w-0 items-center gap-1 text-xs text-muted-foreground">
      <Link to="/" className="flex items-center gap-1 hover:text-foreground">
        <Home className="h-3.5 w-3.5" />
        首頁
      </Link>
      {parts.map((part, index) => {
        const href = `/${parts.slice(0, index + 1).join("/")}`;
        const labels: Record<string, string> = {
          targets: "測試目標",
          console: "即時主控台",
          decisions: "決策中心",
          reports: "報告中心",
          approvals: "核准中心",
          settings: "設定"
        };
        const label = labels[part] || part.replace(/-/g, " ");
        return (
          <span className="flex min-w-0 items-center gap-1" key={href}>
            <ChevronRight className="h-3.5 w-3.5" />
            <Link className="truncate capitalize hover:text-foreground" to={href}>
              {label}
            </Link>
          </span>
        );
      })}
    </nav>
  );
}
