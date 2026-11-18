import { useEffect, useEffectEvent, useRef, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { Button } from "../ui";
import {
  DIALOG_CARD_CLASS,
  DIALOG_CODE_CHIP_CLASS,
  DIALOG_OVERLAY_CLASS,
  DIALOG_TITLE_CLASS,
} from "./dialogRecipe";

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

  // An effect event, so a parent re-render that hands over a new onDecide
  // cannot fire a second deny while the prompt is still mounted at zero.
  const denyOnTimeout = useEffectEvent(() => onDecide(false));
  useEffect(() => {
    if (remaining === 0) denyOnTimeout();
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
    <div className={DIALOG_OVERLAY_CLASS}>
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="approval-dialog-title"
        aria-describedby="approval-dialog-description"
        className={`${DIALOG_CARD_CLASS} max-w-[480px]`}
      >
        <div className="flex items-center gap-2">
          <ShieldAlert size={18} aria-hidden="true" className="shrink-0 text-warning" />
          <h3 id="approval-dialog-title" className={DIALOG_TITLE_CLASS}>
            Tool permission required
          </h3>
          <span className="ml-auto shrink-0 text-[11px] font-medium tabular-nums text-warning">
            Auto-denies in {remaining}s
          </span>
        </div>
        <p id="approval-dialog-description" className="mt-3 text-[12px] leading-relaxed text-text-secondary">
          The AI wants to call <code className={DIALOG_CODE_CHIP_CLASS}>{tool}</code>. Approve to
          let it run, or deny to skip it.
        </p>
        {argumentsPreview && (
          <pre className="selectable mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap break-all rounded-md border border-border bg-surface-code px-3 py-2 font-mono text-[12px] leading-relaxed text-text-secondary">
            {argumentsPreview}
          </pre>
        )}
        <div className="mt-4 flex items-center justify-end gap-2">
          <Button ref={denyRef} variant="outline" size="md" onClick={() => onDecide(false)}>
            Deny
          </Button>
          <Button variant="primary" size="md" onClick={() => onDecide(true)}>
            Approve
          </Button>
        </div>
      </div>
    </div>
  );
}
