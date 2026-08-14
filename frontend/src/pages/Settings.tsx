import { Save } from "lucide-react";
import type { ReactNode } from "react";
import { useState } from "react";
import { getApiBase, setApiBase } from "../api/client";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Select } from "../components/ui/select";
import { useTheme } from "../components/ThemeProvider";
import { useToast } from "../components/ToastProvider";

export function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const { notify } = useToast();
  const [apiBase, updateApiBase] = useState(getApiBase());
  const [refresh, setRefresh] = useState(localStorage.getItem("m2a.refreshInterval") || "15000");
  const [user, setUser] = useState(localStorage.getItem("m2a.user") || "analyst");
  const [wsEndpoint, setWsEndpoint] = useState(localStorage.getItem("m2a.wsEndpoint") || "");

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHeader><CardTitle>API 設定</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <Field label="API 端點">
            <Input value={apiBase} onChange={(event) => updateApiBase(event.target.value)} placeholder="http://127.0.0.1:8000" />
          </Field>
          <Field label="更新間隔">
            <Select value={refresh} onChange={(event) => setRefresh(event.target.value)}>
              <option value="5000">5 秒</option>
              <option value="15000">15 秒</option>
              <option value="30000">30 秒</option>
            </Select>
          </Field>
          <Button
            onClick={() => {
              setApiBase(apiBase);
              localStorage.setItem("m2a.refreshInterval", refresh);
              localStorage.setItem("m2a.user", user);
              localStorage.setItem("m2a.wsEndpoint", wsEndpoint);
              notify({ title: "設定已儲存", tone: "success" });
            }}
          >
            <Save className="h-4 w-4" />儲存
          </Button>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>主控台偏好設定</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <Field label="佈景主題">
            <Select value={theme} onChange={(event) => setTheme(event.target.value as "dark" | "light")}>
              <option value="dark">深色 SOC</option>
              <option value="light">淺色分析師</option>
            </Select>
          </Field>
          <Field label="使用者">
            <Input value={user} onChange={(event) => setUser(event.target.value)} />
          </Field>
          <Field label="Worker 狀態">
            <Input value="由 /targets/{id}/run-status 取得" disabled />
          </Field>
          <Field label="WebSocket 端點">
            <Input value={wsEndpoint} onChange={(event) => setWsEndpoint(event.target.value)} placeholder="ws://127.0.0.1:8000/ws/targets/{targetId}" />
          </Field>
        </CardContent>
      </Card>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-2">
      <span className="section-title">{label}</span>
      {children}
    </label>
  );
}
