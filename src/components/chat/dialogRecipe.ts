/**
 * oxFuzz's dialog recipe (`providers/ConfirmContext.tsx`, `ApprovalPrompt.tsx`)
 * for the Assistant's dialogs: a 40% black overlay blurred by 2px, then a
 * `surface-card` lifted to `shadow-lg` that scales in with `animate-dialog-in`.
 * The same recipe the readiness wizard and the command palette use.
 */
export const DIALOG_OVERLAY_CLASS =
  "fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 backdrop-blur-[2px] sm:p-6";

export const DIALOG_CARD_CLASS = "surface-card w-full animate-dialog-in p-5 shadow-lg";

/** Title row: icon, the 14px title, and a right-aligned note (countdown, risk). */
export const DIALOG_TITLE_CLASS = "text-[14px] font-semibold text-text-primary";

/** The action under review, oxFuzz's code chip. */
export const DIALOG_CODE_CHIP_CLASS =
  "rounded-sm border border-border bg-surface-secondary px-1.5 py-0.5 font-mono text-[12px] text-text-primary [overflow-wrap:anywhere]";
