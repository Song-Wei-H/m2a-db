import { useEffect, useState, type ReactNode } from "react";
import { Copy, ExternalLink } from "lucide-react";
import { cn } from "../lib/utils";

export function ContextMenu({
  children,
  label,
  onOpen,
  onCopy
}: {
  children: ReactNode;
  label: string;
  onOpen?: () => void;
  onCopy?: () => void;
}) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const close = () => setOpen(false);
    window.addEventListener("click", close);
    window.addEventListener("keydown", close);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("keydown", close);
    };
  }, []);

  return (
    <div
      onContextMenu={(event) => {
        event.preventDefault();
        setOpen(true);
      }}
    >
      {children}
      {open ? (
        <div className={cn("fixed right-4 top-20 z-50 w-48 rounded-md border border-border bg-card p-1 shadow-lg shadow-black/30")}>
          <button className="flex w-full items-center gap-2 rounded px-2 py-2 text-left text-sm hover:bg-accent" onClick={onOpen}>
            <ExternalLink className="h-4 w-4 text-primary" />
            Open {label}
          </button>
          <button className="flex w-full items-center gap-2 rounded px-2 py-2 text-left text-sm hover:bg-accent" onClick={onCopy}>
            <Copy className="h-4 w-4 text-primary" />
            Copy reference
          </button>
        </div>
      ) : null}
    </div>
  );
}
