import { Children, cloneElement, isValidElement, type AriaAttributes, type JSX } from "react";

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
  const controls = Children.map(children, (child) => {
    if (!isValidElement<{ id?: string } & AriaAttributes>(child) || child.props.id !== htmlFor) return child;
    const descriptions = new Set((child.props["aria-describedby"] ?? "").split(/\s+/).filter(Boolean));
    if (hint) descriptions.add(hintId);
    if (error) descriptions.add(errorId);
    return cloneElement(child, {
      "aria-describedby": [...descriptions].join(" ") || undefined,
      "aria-invalid": error ? true : child.props["aria-invalid"],
    });
  });

  return (
    <div>
      <label htmlFor={htmlFor} className="mb-1 block text-[12px] font-medium text-text-secondary">
        {label}
      </label>
      {controls}
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
