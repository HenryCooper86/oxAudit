import type { JSX, ReactNode } from "react";

export function ToolPage(props: {
  title: string;
  description: string;
  context?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}): JSX.Element {
  const { title, description, context, actions, children } = props;

  return (
    <div className="mx-auto max-w-6xl px-5 py-5 sm:px-6 sm:py-6">
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-[15px] font-semibold tracking-tight text-slate-100">{title}</h1>
            {context}
          </div>
          <p className="mt-1 text-[13px] text-slate-400">{description}</p>
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </header>

      <div className="mt-5 space-y-5">{children}</div>
    </div>
  );
}
