import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity,
  BarChart3,
  ClipboardCheck,
  FileText,
  LayoutDashboard,
  Menu,
  MonitorDot,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Settings,
  Shield,
  Sun,
  Target
} from "lucide-react";
import { useMemo, useState } from "react";
import { cn } from "../lib/utils";
import { Breadcrumbs } from "./Breadcrumbs";
import { CommandPalette } from "./CommandPalette";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { useTheme } from "./ThemeProvider";

const navItems = [
  { to: "/", label: "儀表板", icon: LayoutDashboard },
  { to: "/targets", label: "測試目標", icon: Target },
  { to: "/console", label: "即時主控台", icon: MonitorDot },
  { to: "/decisions", label: "決策中心", icon: Activity },
  { to: "/reports", label: "報告中心", icon: FileText },
  { to: "/approvals", label: "核准中心", icon: ClipboardCheck },
  { to: "/settings", label: "設定", icon: Settings }
];

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [search, setSearch] = useState("");
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();
  const filteredNav = useMemo(
    () => navItems.filter((item) => item.label.toLowerCase().includes(search.toLowerCase())),
    [search]
  );

  return (
    <div className="min-h-screen bg-background">
      <aside className={cn("fixed inset-y-0 left-0 z-40 hidden border-r border-border bg-card/95 transition-all lg:block", collapsed ? "w-20" : "w-64")}>
        <div className="flex h-16 items-center gap-3 border-b border-border px-4">
          <div className="rounded-md bg-primary/10 p-2 text-primary">
            <Shield className="h-5 w-5" />
          </div>
          <div className={cn("min-w-0", collapsed && "hidden")}>
            <div className="font-semibold">M2A</div>
            <div className="text-xs text-muted-foreground">受治理決策引擎</div>
          </div>
        </div>
        <div className={cn("p-3", collapsed && "hidden")}>
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜尋導覽" />
          </div>
        </div>
        <nav className="space-y-1 p-3">
          {filteredNav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground",
                  collapsed && "justify-center px-2",
                  isActive && "bg-accent text-accent-foreground"
                )
              }
              title={item.label}
            >
              <item.icon className="h-4 w-4" />
              <span className={cn(collapsed && "hidden")}>{item.label}</span>
            </NavLink>
          ))}
        </nav>
      </aside>
      <div
        className={cn(
          "fixed inset-0 z-40 bg-black/70 transition-opacity lg:hidden",
          mobileOpen ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"
        )}
        onClick={() => setMobileOpen(false)}
      />
      <aside className={cn("fixed inset-y-0 left-0 z-50 w-72 border-r border-border bg-card transition-transform lg:hidden", mobileOpen ? "translate-x-0" : "-translate-x-full")}>
        <div className="flex h-16 items-center gap-3 border-b border-border px-4">
          <Shield className="h-5 w-5 text-primary" />
          <span className="font-semibold">M2A</span>
        </div>
        <nav className="space-y-1 p-3">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                cn("flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground", isActive && "bg-accent text-accent-foreground")
              }
              onClick={() => setMobileOpen(false)}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className={cn("transition-all", collapsed ? "lg:pl-20" : "lg:pl-64")}>
        <header className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur">
          <div className="flex min-h-16 flex-wrap items-center justify-between gap-3 px-4 py-3 lg:px-6">
            <div className="flex min-w-0 items-center gap-3">
              <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileOpen(true)} aria-label="開啟導覽列">
                <Menu className="h-5 w-5" />
              </Button>
              <Button variant="ghost" size="icon" className="hidden lg:inline-flex" onClick={() => setCollapsed((value) => !value)} aria-label="收合側邊欄">
                {collapsed ? <PanelLeftOpen className="h-5 w-5" /> : <PanelLeftClose className="h-5 w-5" />}
              </Button>
              <div className="min-w-0">
                <Breadcrumbs />
                <div className="truncate font-semibold">M2A 自動化滲透測試作業</div>
              </div>
            </div>
            <div className="flex w-full items-center gap-2 sm:w-auto">
              <div className="relative min-w-0 flex-1 sm:w-72">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  className="pl-9"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && filteredNav[0]) navigate(filteredNav[0].to);
                  }}
                  placeholder="搜尋全部內容"
                />
              </div>
              <Button variant="outline" size="sm" className="hidden sm:inline-flex" onClick={() => window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true }))}>
                Ctrl+K
              </Button>
              <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label="切換佈景主題">
                {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </Button>
              <div className="hidden items-center gap-2 text-xs text-muted-foreground xl:flex">
                <BarChart3 className="h-4 w-4 text-primary" />
                已啟用自動更新
              </div>
            </div>
          </div>
        </header>
        <main className="p-3 sm:p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
      <CommandPalette />
    </div>
  );
}
