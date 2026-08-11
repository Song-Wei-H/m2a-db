import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";

export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("M2A UI error boundary", error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="p-4">
        <Card>
          <CardContent className="space-y-4 pt-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-1 h-5 w-5 text-red-400" />
              <div>
                <div className="font-semibold">The UI hit an unexpected error.</div>
                <div className="mt-1 text-sm text-muted-foreground">{this.state.error.message}</div>
              </div>
            </div>
            <Button onClick={() => this.setState({ error: null })}>Recover</Button>
          </CardContent>
        </Card>
      </div>
    );
  }
}
