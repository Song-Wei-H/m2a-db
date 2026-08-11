import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { compactText } from "../lib/utils";

export function EvidenceCard({ title, data }: { title: string; data: unknown }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <pre className="max-h-80 overflow-auto rounded-md bg-black/30 p-3 text-xs text-slate-200">
          {compactText(data)}
        </pre>
      </CardContent>
    </Card>
  );
}
