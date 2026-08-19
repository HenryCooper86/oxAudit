import { useEffect, useRef, useState } from "react";
import { ShieldAlert } from "lucide-react";

/**
 * HITL permission approval modal (y-agent hitl.rs): a tool call is waiting for
 * the user's Approve / Deny. Auto-denies after 120s (mirrors the Rust timeout).
 */
export function ApprovalModal({
  tool,
  argumentsPreview,
  onDecide,
  onRestoreFocus,
}: {
  tool: string;
  argumentsPreview: string;
  onDecide: (approve: boolean) => void;
  onRestoreFocus: () => void;
}) {
  const [remaining, setRemaining] = useState(120);
  const dialogRef = useRef<HTMLDivElement>(null);
  const denyRef = useRef<HTMLButtonElement>(null);
  const onRestoreFocusRef = useRef(onRestoreFocus);
  onRestoreFocusRef.current = onRestoreFocus;

  useEffect(() => {
    const timer = setInterval(
      () => setRemaining((value) => Math.max(0, value - 1)),
      1000,
    );
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (remaining === 0) onDecide(false);
    // The decision handler unmounts this prompt after the timeout.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [remaining]);

  useEffect(() => {
    const returnFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const focusFrame = requestAnimationFrame(() => denyRef.current?.focus());

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) {
        event.preventDefault();
        dialog.focus();
      } else if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", onKeyDown);
      requestAnimationFrame(() => {
        if (returnFocus?.isConnected && returnFocus !== document.body) {
          returnFocus.focus();
          if (document.activeElement === returnFocus) return;
        }
        onRestoreFocusRef.current();
      });
    };
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6">
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="approval-dialog-title"
        aria-describedby="approval-dialog-description"
        className="w-full max-w-md rounded-md border border-warning-border bg-surface-secondary p-5 shadow-lg"
      >
        <div className="flex items-center gap-2">
          <ShieldAlert size={17} aria-hidden="true" className="text-warning" />
          <h3 id="approval-dialog-title" className="text-[14px] font-semibold text-text-primary">
            Tool permission required
          </h3>
        </div>
        <p id="approval-dialog-description" className="mt-2 text-[13px] leading-relaxed text-text-secondary">
          The AI wants to call{" "}
          <span className="rounded-sm bg-surface-tertiary px-1.5 py-0.5 font-mono text-[12px] text-accent">
            {tool}
          </span>
          . Approve to let it run, or deny to skip it.
        </p>
        {argumentsPreview && (
          <pre className="selectable mt-3 max-h-40 overflow-y-auto whitespace-pre-wrap break-all rounded-sm border border-border bg-surface-primary px-3 py-2 font-mono text-[12px] leading-relaxed text-text-secondary">
            {argumentsPreview}
          </pre>
        )}
        <div className="mt-2 text-right text-[11px] tabular-nums text-text-muted">
          Auto-denies in {remaining}s
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2">
          <button
            ref={denyRef}
            type="button"
            onClick={() => onDecide(false)}
            className="rounded-sm border border-error-border bg-transparent px-3 py-2 text-[12px] font-semibold text-error hover:bg-error-subtle"
          >
            Deny
          </button>
          <button
            type="button"
            onClick={() => onDecide(true)}
            className="rounded-sm border border-success-border bg-transparent px-3 py-2 text-[12px] font-semibold text-success hover:bg-success-subtle"
          >
            Approve
          </button>
        </div>
      </div>
    </div>
  );
}
