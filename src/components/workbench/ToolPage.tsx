import type { JSX, ReactNode } from "react";

/**
 * Page anatomy, after oxFuzz's views: 24px page padding (16px below 768px),
 * an 18px semibold `h1` with a secondary one-line description, actions on the
 * right, then the page's cards on a 16px rhythm. The page fades in on entry.
 * The `h1` is the page's only top-level heading; the shell header shows the
 * same title as plain text.
 */
export function ToolPage(props: {
  title: string;
  description: string;
  context?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}): JSX.Element {
  const { title, description, context, actions, children } = props;

  return (
    <div className="w-full animate-fade-in px-4 pb-10 pt-4 md:px-6 md:pt-6">
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
        <div className="min-w-0 [overflow-wrap:anywhere]">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-[18px] font-semibold leading-tight text-text-primary">{title}</h1>
            {context}
          </div>
          <p className="mt-1 text-[13px] text-text-secondary">{description}</p>
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </header>

      <div className="mt-4 space-y-4">{children}</div>
    </div>
  );
}
