/**
 * A result row as oxFuzz draws its triage queue: a bordered card-button on the
 * 8px radius. The selected row keeps the card shape and moves to the focus
 * border on the active surface; other rows lift on hover.
 */
export function listRowClassName(selected: boolean): string {
  return `rounded-md border transition-colors duration-150 ${
    selected
      ? "border-border-focus bg-surface-active"
      : "border-border bg-surface-primary hover:bg-surface-hover"
  }`;
}
