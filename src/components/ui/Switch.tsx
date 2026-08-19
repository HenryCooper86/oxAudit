import type { JSX } from "react";

export function Switch(props: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}): JSX.Element {
  const { checked, onChange, label, disabled = false } = props;

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
      <span className="relative h-4 w-7 shrink-0 rounded-full bg-surface-active transition-colors peer-checked:bg-accent peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-accent">
        <span
          className={`absolute top-0.5 h-3 w-3 rounded-full transition-[left] ${ checked ? "left-3.5 bg-accent-contrast" : "left-0.5 bg-text-secondary" }`}
        />
      </span>
      <span>{label}</span>
    </label>
  );
}
