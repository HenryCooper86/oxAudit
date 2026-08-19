import type { JSX } from "react";

export function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}): JSX.Element {
  const hintId = `${htmlFor}-hint`;
  const errorId = `${htmlFor}-error`;

  return (
    <div>
      <label htmlFor={htmlFor} className="mb-1 block text-[12px] font-medium text-text-secondary">
        {label}
      </label>
      {children}
      {hint && (
        <p id={hintId} className="mt-1 text-[11px] leading-relaxed text-text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} role="alert" className="mt-1 text-[11px] leading-relaxed text-error">
          {error}
        </p>
      )}
    </div>
  );
}
