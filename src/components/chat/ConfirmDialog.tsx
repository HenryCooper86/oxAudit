import { useEffect, useRef, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

/**
 * Modal confirmation for destructive actions, following ApprovalModal's
 * focus handling: the safe choice (Cancel) takes focus, Tab stays inside the
 * dialog, Escape cancels, and focus returns to the opener on close.
 */
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  onConfirm,
  onCancel,
  onRestoreFocus,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  onRestoreFocus?: () => void;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const onCancelRef = useRef(onCancel);
  onCancelRef.current = onCancel;
  const onRestoreFocusRef = useRef(onRestoreFocus);
  onRestoreFocusRef.current = onRestoreFocus;

  useEffect(() => {
    const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusFrame = requestAnimationFrame(() => cancelRef.current?.focus());

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancelRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>('button:not([disabled]), [href], [tabindex]:not([tabindex="-1"])'),
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
        onRestoreFocusRef.current?.();
      });
    };
  }, []);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 sm:p-6"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-description"
        className="w-full max-w-md rounded-md border border-warning-border bg-surface-secondary p-5 shadow-lg"
      >
        <div className="flex items-center gap-2">
          <AlertTriangle size={17} aria-hidden="true" className="text-warning" />
          <h3 id="confirm-dialog-title" className="text-[14px] font-semibold text-text-primary">
            {title}
          </h3>
        </div>
        <div id="confirm-dialog-description" className="mt-2 space-y-2 text-[13px] leading-relaxed text-text-secondary">
          {children}
        </div>
        <div className="mt-4 grid grid-cols-2 gap-2">
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            className="rounded-sm border border-border bg-transparent px-3 py-2 text-[12px] font-semibold text-text-secondary hover:bg-surface-hover hover:text-text-primary"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="rounded-sm border border-error-border bg-transparent px-3 py-2 text-[12px] font-semibold text-error hover:bg-error-subtle"
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
