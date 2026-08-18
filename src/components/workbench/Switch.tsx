import type { JSX } from "react";

export function Switch(props: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}): JSX.Element {
  const { checked, onChange, label, disabled = false } = props;

  return (
    <label className={`inline-flex items-center gap-2 text-[12px] text-stone-300 ${disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`}>
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        disabled={disabled}
        className="peer sr-only"
      />
      <span className="relative h-4 w-7 shrink-0 rounded-full bg-ink-600 transition-colors peer-checked:bg-accent-500 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-accent-400">
        <span className={`absolute top-0.5 h-3 w-3 rounded-full bg-stone-100 transition-[left] ${checked ? "left-3.5" : "left-0.5"}`} />
      </span>
      <span>{label}</span>
    </label>
  );
}
