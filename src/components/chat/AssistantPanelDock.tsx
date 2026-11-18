import { useEffect, useRef, type JSX, type ReactNode } from "react";

/**
 * Where the Assistant's Conversations or Activity panel opens, after oxFuzz's
 * `PanelShell`: 320px on the secondary surface behind a left hairline, fading
 * in on the right of the conversation.
 *
 * As a `drawer` (narrow windows) it overlays the conversation instead of
 * squeezing it: a blurred backdrop closes it on click, Escape closes it, focus
 * moves into it and returns to where it was when it closes.
 */
export function AssistantPanelDock({
  drawer,
  onClose,
  children,
}: {
  drawer: boolean;
  onClose: () => void;
  children: ReactNode;
}): JSX.Element {
  const panelRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!drawer) return;
    const panel = panelRef.current;
    const returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const frame = requestAnimationFrame(() => {
      const first = panel?.querySelector<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
      );
      (first ?? panel)?.focus();
    });
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || document.querySelector('[aria-modal="true"]')) return;
      event.preventDefault();
      onCloseRef.current();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener("keydown", onKeyDown);
      const focused = document.activeElement;
      const focusWasInPanel =
        !focused || focused === document.body || !focused.isConnected || panel?.contains(focused);
      if (focusWasInPanel && returnFocus?.isConnected) returnFocus.focus();
    };
  }, [drawer]);

  if (!drawer) {
    return (
      <div
        data-assistant-panel="docked"
        className="flex w-[320px] shrink-0 animate-fade-in flex-col border-l border-border bg-surface-secondary"
      >
        {children}
      </div>
    );
  }

  return (
    <>
      {/* A pointer-only dismiss target; Escape is the keyboard path. */}
      <div
        role="presentation"
        data-assistant-panel-backdrop
        className="absolute inset-0 z-30 animate-fade-in bg-black/40 backdrop-blur-[2px]"
        onMouseDown={onClose}
      />
      <div
        ref={panelRef}
        tabIndex={-1}
        data-assistant-panel="drawer"
        className="absolute inset-y-0 right-0 z-40 flex w-[320px] max-w-[calc(100%-48px)] animate-fade-in flex-col border-l border-border bg-surface-secondary shadow-lg"
      >
        {children}
      </div>
    </>
  );
}
