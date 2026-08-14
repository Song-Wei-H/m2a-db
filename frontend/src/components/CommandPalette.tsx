import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Command, Search } from "lucide-react";
import { Dialog } from "./ui/dialog";
import { Input } from "./ui/input";

const actions = [
  { label: "儀表板", path: "/" },
  { label: "測試目標", path: "/targets" },
  { label: "即時主控台", path: "/console" },
  { label: "決策中心", path: "/decisions" },
  { label: "報告中心", path: "/reports" },
  { label: "核准中心", path: "/approvals" },
  { label: "設定", path: "/settings" }
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((value) => !value);
      }
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const matches = useMemo(
    () => actions.filter((action) => action.label.toLowerCase().includes(query.toLowerCase())),
    [query]
  );

  return (
    <Dialog open={open} title="Command Palette" onClose={() => setOpen(false)}>
      <div className="space-y-3">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input autoFocus className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜尋頁面與操作" />
        </div>
        <div className="grid gap-1">
          {matches.map((action) => (
            <button
              className="flex items-center gap-3 rounded-md px-3 py-2 text-left text-sm hover:bg-accent"
              key={action.path}
              onClick={() => {
                navigate(action.path);
                setOpen(false);
                setQuery("");
              }}
            >
              <Command className="h-4 w-4 text-primary" />
              {action.label}
            </button>
          ))}
        </div>
      </div>
    </Dialog>
  );
}
