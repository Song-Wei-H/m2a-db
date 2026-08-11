import { createBrowserRouter } from "react-router-dom";
import { lazy, Suspense } from "react";
import type { ReactNode } from "react";
import { AppShell } from "./components/AppShell";
import { Skeleton } from "./components/Status";

const Dashboard = lazy(() => import("./pages/Dashboard").then((module) => ({ default: module.Dashboard })));
const TargetsPage = lazy(() => import("./pages/Targets").then((module) => ({ default: module.TargetsPage })));
const TargetDetail = lazy(() => import("./pages/TargetDetail").then((module) => ({ default: module.TargetDetail })));
const LiveConsole = lazy(() => import("./pages/LiveConsole").then((module) => ({ default: module.LiveConsole })));
const DecisionCenter = lazy(() => import("./pages/DecisionCenter").then((module) => ({ default: module.DecisionCenter })));
const ReportCenter = lazy(() => import("./pages/ReportCenter").then((module) => ({ default: module.ReportCenter })));
const ApprovalCenter = lazy(() => import("./pages/ApprovalCenter").then((module) => ({ default: module.ApprovalCenter })));
const SettingsPage = lazy(() => import("./pages/Settings").then((module) => ({ default: module.SettingsPage })));

function LazyPage({ children }: { children: ReactNode }) {
  return <Suspense fallback={<Skeleton className="h-[70vh] w-full" />}>{children}</Suspense>;
}

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppShell />,
    children: [
      { index: true, element: <LazyPage><Dashboard /></LazyPage> },
      { path: "targets", element: <LazyPage><TargetsPage /></LazyPage> },
      { path: "targets/:targetId", element: <LazyPage><TargetDetail /></LazyPage> },
      { path: "console", element: <LazyPage><LiveConsole /></LazyPage> },
      { path: "decisions", element: <LazyPage><DecisionCenter /></LazyPage> },
      { path: "reports", element: <LazyPage><ReportCenter /></LazyPage> },
      { path: "approvals", element: <LazyPage><ApprovalCenter /></LazyPage> },
      { path: "settings", element: <LazyPage><SettingsPage /></LazyPage> }
    ]
  }
]);
