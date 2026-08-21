import { AlertTriangle, CheckCircle2, FileQuestion } from "lucide-react";
import type { JSX } from "react";
import type { PolicyStatus } from "../../lib/types";
import { Button } from "../../components/ui";

export function PolicyStatusView(props: {
  policy: PolicyStatus;
  running: boolean;
  onRunWithoutPolicy(): void;
}): JSX.Element {
  const { policy, running, onRunWithoutPolicy } = props;

  if (policy.status === "valid") {
    return (
      <div className="flex items-start gap-2 border border-success-border bg-success-subtle px-3 py-2 text-[12px] text-text-secondary">
        <CheckCircle2 size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-success" />
        <div className="min-w-0">
          <p className="font-medium text-text-primary">Project policy active</p>
          <p className="mt-0.5 font-mono text-[11px] text-text-muted">{policy.hash.slice(0, 12)}</p>
        </div>
      </div>
    );
  }

  if (policy.status === "invalid") {
    return (
      <div role="alert" className="border border-error-border bg-error-subtle px-3 py-2.5">
        <div className="flex items-start gap-2">
          <AlertTriangle size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-error" />
          <div className="min-w-0 flex-1">
            <p className="text-[12px] font-medium text-text-primary">Project policy needs attention</p>
            <p className="mt-1 text-[11px] leading-relaxed text-text-secondary">{policy.message}</p>
            <Button
              type="button"
              onClick={onRunWithoutPolicy}
              disabled={running}
              variant="warning"
              size="sm"
              className="mt-2"
            >
              Scan without project policy
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-start gap-2 border border-border bg-surface-primary px-3 py-2 text-[12px] text-text-secondary">
      <FileQuestion size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-text-muted" />
      <div>
        <p className="font-medium text-text-primary">No project policy</p>
        <p className="mt-0.5 text-[11px] text-text-muted">Local reviews and defaults will be used.</p>
      </div>
    </div>
  );
}
