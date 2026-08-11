import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { CheckCircle2, Info, X } from "lucide-react";
import { Button } from "./ui/button";
import { cn } from "../lib/utils";

type Toast = {
  id: number;
  title: string;
  message?: string;
  tone?: "default" | "success" | "error";
};

const ToastContext = createContext<{ notify: (toast: Omit<Toast, "id">) => void } | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const notify = useCallback(
    (toast: Omit<Toast, "id">) => {
      const id = Date.now();
      setToasts((current) => [...current, { ...toast, id }].slice(-4));
      window.setTimeout(() => remove(id), 4200);
    },
    [remove]
  );

  const value = useMemo(() => ({ notify }), [notify]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed bottom-4 right-4 z-[60] grid w-[min(380px,calc(100vw-2rem))] gap-2">
        {toasts.map((toast) => {
          const Icon = toast.tone === "success" ? CheckCircle2 : Info;
          return (
            <div
              className={cn(
                "rounded-lg border border-border bg-card p-3 shadow-lg shadow-black/30",
                toast.tone === "error" && "border-red-500/40",
                toast.tone === "success" && "border-green-500/40"
              )}
              key={toast.id}
            >
              <div className="flex items-start gap-3">
                <Icon className="mt-0.5 h-4 w-4 text-primary" />
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium">{toast.title}</div>
                  {toast.message ? <div className="mt-1 text-sm text-muted-foreground">{toast.message}</div> : null}
                </div>
                <Button variant="ghost" size="icon" onClick={() => remove(toast.id)} aria-label="Dismiss notification">
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}
