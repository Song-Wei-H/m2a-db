import { Circle } from "lucide-react";
import { formatDate } from "../lib/utils";

export function Timeline({
  items
}: {
  items: Array<{ title: string; time?: string | null; detail?: string | null }>;
}) {
  if (!items.length) return <p className="text-sm text-muted-foreground">No timeline events returned by the API.</p>;
  return (
    <ol className="space-y-3">
      {items.map((item, index) => (
        <li className="flex gap-3" key={`${item.title}-${index}`}>
          <Circle className="mt-1 h-3 w-3 fill-primary text-primary" />
          <div className="min-w-0">
            <div className="text-sm font-medium">{item.title}</div>
            <div className="text-xs text-muted-foreground">{formatDate(item.time)}</div>
            {item.detail ? <div className="mt-1 text-sm text-muted-foreground">{item.detail}</div> : null}
          </div>
        </li>
      ))}
    </ol>
  );
}
