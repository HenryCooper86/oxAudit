import type { JSX } from "react";

/**
 * oxFuzz's 36x20 switch: a bordered pill, accent when on, with a 14px knob.
 * The control is a native checkbox with `role="switch"` so the label, keyboard
 * and checked state come from the platform; the pill is its visual.
 */
export function Switch(props: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
  /** Keep `label` as the accessible name only, for a switch whose row already shows the title. */
  hideLabel?: boolean;
}): JSX.Element {
  const { checked, onChange, label, disabled = false, hideLabel = false } = props;

  return (
    <label
      className={`inline-flex items-center gap-2 text-[12px] text-text-secondary ${ disabled ? "cursor-not-allowed opacity-55" : "cursor-pointer" }`}
    >
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        disabled={disabled}
        className="peer sr-only"
      />
      <span className="relative h-5 w-9 shrink-0 rounded-full border border-border bg-surface-tertiary transition-colors duration-200 peer-checked:border-transparent peer-checked:bg-accent peer-focus-visible:shadow-[0_0_0_2px_var(--surface-primary),0_0_0_4px_var(--accent)]">
        <span
          className={`absolute top-[2px] h-3.5 w-3.5 rounded-full transition-[left] duration-200 ${ checked ? "left-[18px] bg-accent-contrast" : "left-[2px] bg-text-secondary" }`}
        />
      </span>
      <span className={hideLabel ? "sr-only" : undefined}>{label}</span>
    </label>
  );
}
