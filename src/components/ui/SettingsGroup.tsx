import { Children, cloneElement, isValidElement, useId, type AriaAttributes, type JSX, type ReactNode } from "react";

/**
 * oxFuzz's settings layout: an uppercase group title (and optional
 * description) above a bordered card whose rows are `SettingsItem`s,
 * separated by hairlines. The group is a labelled region.
 */
export function SettingsGroup({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}): JSX.Element {
  const id = useId();
  return (
    <section aria-labelledby={`${id}-title`} className="mb-6 last:mb-0">
      <div className="px-1 pb-2">
        <h2 id={`${id}-title`} className="text-[11px] font-semibold uppercase tracking-[0.06em] text-text-muted">
          {title}
        </h2>
        {description && <p className="mt-1 text-[12px] leading-normal text-text-secondary">{description}</p>}
      </div>
      <div className="divide-y divide-border overflow-hidden rounded-md border border-border bg-surface-secondary">
        {children}
      </div>
    </section>
  );
}

/**
 * One 44px settings row: label and description on the left, the control on
 * the right. `stacked` drops the control to a full-width row beneath the label,
 * for textareas and wide inputs. Pass `htmlFor` to label a control by id: the
 * description then also describes the control (`aria-describedby`), and an
 * `error` is announced as an alert and marks the control `aria-invalid`, the
 * same association `Field` makes.
 */
export function SettingsItem({
  title,
  description,
  htmlFor,
  stacked = false,
  error,
  children,
}: {
  title: string;
  description?: string;
  htmlFor?: string;
  stacked?: boolean;
  error?: string;
  children?: ReactNode;
}): JSX.Element {
  const Label = htmlFor ? "label" : "div";
  const hintId = htmlFor && description ? `${htmlFor}-hint` : undefined;
  const errorId = htmlFor && error ? `${htmlFor}-error` : undefined;
  const controls = Children.map(children, (child) => {
    if (!htmlFor || !isValidElement<{ id?: string } & AriaAttributes>(child) || child.props.id !== htmlFor) return child;
    const described = new Set((child.props["aria-describedby"] ?? "").split(/\s+/).filter(Boolean));
    if (hintId) described.add(hintId);
    if (errorId) described.add(errorId);
    return cloneElement(child, {
      "aria-describedby": [...described].join(" ") || undefined,
      "aria-invalid": error ? true : child.props["aria-invalid"],
    });
  });
  return (
    <div
      className={`flex min-h-11 px-3.5 py-2.5 ${stacked ? "flex-col items-stretch gap-2" : "items-center gap-4"}`}
    >
      <div className="min-w-0 flex-1">
        <Label htmlFor={htmlFor} className="block text-[13px] font-medium text-text-primary">
          {title}
        </Label>
        {description && (
          <p id={hintId} className="mt-0.5 text-[12px] leading-snug text-text-secondary">
            {description}
          </p>
        )}
        {error && (
          <p id={errorId} role="alert" className="mt-0.5 text-[12px] leading-snug text-error">
            {error}
          </p>
        )}
      </div>
      {children != null && <div className={stacked ? "w-full" : "shrink-0"}>{controls}</div>}
    </div>
  );
}
