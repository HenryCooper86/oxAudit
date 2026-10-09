import type { JSX } from "react";

/** Saved caveats stay attached to the receipt, including clean-looking results. */
export function CoverageWarnings({ warnings }: { warnings?: readonly string[] }): JSX.Element | null {
  if (!warnings?.length) return null;
  return (
    <section aria-label="Scan coverage warnings" className="rounded-sm border border-warning/40 bg-surface-secondary p-3 text-[12px]">
      <h2 className="font-medium text-warning">Scan coverage is limited</h2>
      <p className="mt-1 text-text-muted">Absence of findings does not establish that excluded or unreadable files are safe.</p>
      <ul className="mt-2 list-disc space-y-1 pl-4 text-text-secondary">
        {warnings.map((warning, index) => <li key={index}>{warning}</li>)}
      </ul>
    </section>
  );
}
