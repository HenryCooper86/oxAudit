import { useEffect, useState, type JSX } from "react";
import { api } from "../../lib/api";
import { errorMessage } from "../../lib/commandError";
import type { InstalledSignaturePack, SignaturePackKind } from "../../lib/types";

/** Installed packs of one kind; `packs` is null until the first answer. */
export function useSignaturePacks(kind: SignaturePackKind) {
  const [packs, setPacks] = useState<InstalledSignaturePack[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let disposed = false;
    void api.listSignaturePacks().then(
      all => { if (!disposed) { setPacks(all.filter(pack => pack.kind === kind && pack.enabled)); setError(null); } },
      cause => { if (!disposed) setError(errorMessage(cause)); },
    );
    return () => { disposed = true; };
  }, [kind]);
  return { packs, error };
}

/** Packs apply by default; unticking one excludes it from this run only. */
export function packIdsFor(packs: readonly InstalledSignaturePack[], excluded: readonly string[]): string[] | undefined {
  return excluded.length === 0 ? undefined : packs.filter(pack => !excluded.includes(pack.id)).map(pack => pack.id);
}

export function PackSelector({ packs, excluded, onChange, disabled, unit }: {
  packs: readonly InstalledSignaturePack[]; excluded: readonly string[]; onChange(next: string[]): void; disabled?: boolean; unit: "rules" | "templates";
}): JSX.Element {
  const selected = packs.filter(pack => !excluded.includes(pack.id)).length;
  return <fieldset disabled={disabled} className="min-w-0">
    <legend className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">Packs ({selected} of {packs.length} selected)</legend>
    <ul className="flex flex-wrap gap-x-4 gap-y-1.5">
      {packs.map(pack => (
        <li key={pack.id}>
          <label className="inline-flex cursor-pointer items-center gap-2 text-[12px] text-text-secondary">
            <input type="checkbox" checked={!excluded.includes(pack.id)} className="accent-[var(--accent)]"
              onChange={event => onChange(event.target.checked ? excluded.filter(id => id !== pack.id) : [...excluded, pack.id])} />
            <span>{pack.name} <span className="text-text-muted">· {pack.ruleCount.toLocaleString()} {unit}</span></span>
          </label>
        </li>
      ))}
    </ul>
    {selected === 0 && <p role="alert" className="mt-1.5 text-[12px] text-error">Select at least one pack.</p>}
  </fieldset>;
}
