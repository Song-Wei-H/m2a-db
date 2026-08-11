import { AlertTriangle, Loader2, SearchX } from "lucide-react";
import { Card, CardContent } from "./ui/card";

export function Loading({ label = "Loading live M2A data" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <Loader2 className="h-4 w-4 animate-spin text-primary" />
      {label}
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-muted ${className}`} />;
}

export function TableSkeleton({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, row) => (
        <div className="flex gap-2" key={row}>
          {Array.from({ length: columns }).map((__, column) => (
            <Skeleton className="h-9 flex-1" key={column} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <Card>
      <CardContent className="flex items-start gap-3 pt-4 text-sm text-red-200">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
        <span>{message}</span>
      </CardContent>
    </Card>
  );
}

export function EmptyState({ title, message }: { title: string; message: string }) {
  return (
    <Card>
      <CardContent className="flex items-start gap-3 pt-4 text-sm text-muted-foreground">
        <SearchX className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
        <div>
          <div className="font-medium text-foreground">{title}</div>
          <div>{message}</div>
        </div>
      </CardContent>
    </Card>
  );
}
