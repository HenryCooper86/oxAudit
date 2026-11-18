import { useEffect, useRef, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "../ui";
import { DIALOG_CARD_CLASS, DIALOG_OVERLAY_CLASS, DIALOG_TITLE_CLASS } from "./dialogRecipe";

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
    // The backdrop is a pointer-only dismiss target; Escape is the keyboard path.
    <div
      role="presentation"
      className={DIALOG_OVERLAY_CLASS}
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
        className={`${DIALOG_CARD_CLASS} max-w-[440px]`}
      >
        <div className="flex items-center gap-2">
          <AlertTriangle size={18} aria-hidden="true" className="shrink-0 text-warning" />
          <h3 id="confirm-dialog-title" className={DIALOG_TITLE_CLASS}>
            {title}
          </h3>
        </div>
        <div id="confirm-dialog-description" className="mt-3 space-y-2 text-[12px] leading-relaxed text-text-secondary">
          {children}
        </div>
        <div className="mt-4 flex items-center justify-end gap-2">
          <Button ref={cancelRef} variant="outline" size="md" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="danger" size="md" onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
