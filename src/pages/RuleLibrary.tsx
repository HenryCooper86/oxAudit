import { CheckCircle2, FileCheck2, PackagePlus, Search, ShieldCheck, Trash2, TriangleAlert } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { useEffect, useMemo, useState, type JSX } from "react";
import { Button, Switch } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { useToastStore } from "../lib/stores";
import type { InstalledRulePack, RuleLibraryPackStatus, RulePackValidationPreview } from "../lib/types";

export function RuleLibraryPage(): JSX.Element {
  const push = useToastStore((state) => state.push);
  const [packs, setPacks] = useState<RuleLibraryPackStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [externalPreview, setExternalPreview] = useState<RulePackValidationPreview | null>(null);
  const [externalPath, setExternalPath] = useState<string | null>(null);
  const [externalError, setExternalError] = useState<string | null>(null);
  const [validating, setValidating] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [installed, setInstalled] = useState<InstalledRulePack[] | null>(null);
  const [installedError, setInstalledError] = useState<string | null>(null);

  useEffect(() => {
    let disposed = false;
    void api
      .ruleLibraryStatus()
      .then((result) => {
        if (!disposed) setPacks(result);
      })
      .catch((cause) => {
        if (!disposed) setError(String(cause));
      });
    return () => {
      disposed = true;
    };
  }, []);

  const refreshInstalled = async () => {
    try {
      setInstalled(await api.listInstalledRulePacks());
      setInstalledError(null);
    } catch (cause) {
      setInstalledError(String(cause));
    }
  };

  useEffect(() => {
    void refreshInstalled();
  }, []);

  const installValidatedPack = async () => {
    if (!externalPath || installing) return;
    setInstalling(true);
    try {
      const pack = await api.installRulePack(externalPath);
      push("success", `Installed ${pack.name} — its enabled rules apply to every source scan.`);
      await refreshInstalled();
    } catch (cause) {
      push("error", "The pack could not be installed.");
      setInstalledError(String(cause));
    } finally {
      setInstalling(false);
    }
  };

  const togglePack = async (pack: InstalledRulePack, enabled: boolean) => {
    try {
      await api.setRulePackEnabled(pack.id, enabled);
      await refreshInstalled();
    } catch (cause) {
      push("error", "The pack state could not be changed.");
      setInstalledError(String(cause));
    }
  };

  const removePack = async (pack: InstalledRulePack) => {
    try {
      await api.removeRulePack(pack.id);
      push("success", `Removed ${pack.name}. Past runs keep the findings they already recorded.`);
      await refreshInstalled();
    } catch (cause) {
      push("error", "The pack could not be removed.");
      setInstalledError(String(cause));
    }
  };

  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return packs ?? [];
    return (packs ?? [])
      .map((pack) => ({
        ...pack,
        rules: pack.rules.filter((rule) =>
          `${rule.id} ${rule.title} ${rule.severity} ${rule.scope.join(" ")} ${rule.provenance}`
            .toLowerCase()
            .includes(normalized),
        ),
      }))
      .filter(
        (pack) =>
          pack.rules.length > 0 ||
          `${pack.id} ${pack.name} ${pack.engine}`.toLowerCase().includes(normalized),
      );
  }, [packs, query]);

  const validateExternalPack = async () => {
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Declarative rule pack", extensions: ["toml"] }],
    });
    if (!selected || Array.isArray(selected)) return;
    setValidating(true);
    setExternalError(null);
    setExternalPreview(null);
    setExternalPath(null);
    try {
      setExternalPreview(await api.validateRulePack(selected));
      setExternalPath(selected);
    } catch (cause) {
      setExternalError(String(cause));
    } finally {
      setValidating(false);
    }
  };

  return (
    <ToolPage
      title="Rule Library"
      description="Inspect the deterministic rules included in oxAudit, where they came from, and which fixture claims are actually verified."
    >
      <section className="rounded-sm border border-border bg-surface-secondary p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="max-w-2xl">
            <h2 className="text-[13px] font-semibold text-text-primary">Install a public pack</h2>
            <p className="mt-1 text-[12px] leading-relaxed text-text-muted">Inspect an oxAudit declarative TOML pack locally. Validation checks provenance, immutable hashes, bounded regexes, fixture hashes, and path containment — nothing executes. A validated pack can be installed; every enabled pack's text-engine rules then run beside the built-ins in each source scan, with findings prefixed by the pack id.</p>
          </div>
          <Button type="button" variant="outline" size="md" onClick={() => void validateExternalPack()} disabled={validating}>
            <FileCheck2 size={13} aria-hidden="true" />{validating ? "Validating…" : "Choose pack…"}
          </Button>
        </div>
        {externalError && <div className="mt-3"><InlineState compact tone="error" title="Pack validation failed" description={externalError} /></div>}
        {externalPreview && (
          <div className="mt-3 rounded-sm border border-success-subtle bg-surface-primary p-3">
            <p className="inline-flex items-center gap-1 text-[12px] font-medium text-success"><CheckCircle2 size={13} aria-hidden="true" />Safe declarative pack verified</p>
            <p className="mt-1 text-[13px] text-text-primary">{externalPreview.name} <span className="font-mono text-[10px] text-text-muted">{externalPreview.id} · v{externalPreview.version}</span></p>
            <p className="mt-1 text-[11px] text-text-secondary">{externalPreview.ruleCount} rules · {externalPreview.fixtureCount} fixtures · {externalPreview.engines.join(", ")} · {externalPreview.license}</p>
            <p className="mt-1 text-[11px] text-text-muted">{externalPreview.validation}. Source: {externalPreview.source}</p>
            <p className="mt-1 break-all font-mono text-[10px] text-text-muted">Snapshot: {externalPreview.contentSha256}</p>
            <div className="mt-2">
              <Button type="button" variant="primary" size="md" onClick={() => void installValidatedPack()} disabled={installing}>
                <PackagePlus size={13} aria-hidden="true" />{installing ? "Installing…" : "Install pack"}
              </Button>
            </div>
          </div>
        )}
      </section>

      <section aria-labelledby="installed-packs-title" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
        <div className="border-b border-border px-4 py-3">
          <h2 id="installed-packs-title" className="text-[13px] font-semibold text-text-primary">Installed packs</h2>
          <p className="mt-1 text-[12px] text-text-muted">
            Enabled packs apply to every source scan: their rules run beside the built-ins under the same budgets and redaction, and their findings carry a <span className="font-mono">pack/rule</span> id. Only the text engines (source_regex, secret_regex) apply today; dependency, binary, and semantic engine rules validate but do not yet run. A pack whose stored snapshot no longer validates is skipped with its reason instead of failing the scan.
          </p>
        </div>
        {installedError && <div className="px-4 py-3"><InlineState compact tone="error" title="The pack store is unavailable" description={installedError} /></div>}
        {installed && installed.length === 0 && (
          <p className="px-4 py-4 text-[12px] text-text-muted">No packs installed. Validate a pack above to install it.</p>
        )}
        {installed && installed.length > 0 && (
          <ul className="divide-y divide-border">
            {installed.map((pack) => (
              <li key={pack.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                <div className="min-w-0">
                  <p className="text-[13px] font-medium text-text-primary">
                    {pack.name} <span className="font-mono text-[10px] text-text-muted">v{pack.version}</span>
                  </p>
                  <p className="mt-0.5 text-[11px] text-text-muted">
                    {pack.ruleCount} rules · {pack.engines.join(", ")} · <span className="font-mono">{pack.id}</span>
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <Switch
                    checked={pack.enabled}
                    onChange={(enabled) => void togglePack(pack, enabled)}
                    label={pack.enabled ? "Applies to scans" : "Disabled"}
                  />
                  <Button type="button" variant="outline" size="md" onClick={() => void removePack(pack)}>
                    <Trash2 size={13} aria-hidden="true" />Remove
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {!packs && !error && <InlineState tone="running" title="Validating built-in rule packs" />}
      {error && <InlineState tone="error" title="Rule metadata is unavailable" description={error} />}
      {packs && (
        <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <ResultsToolbar
            countLabel={`${packs.length} packs · ${packs.reduce((total, pack) => total + pack.rules.length, 0)} rules`}
            search={
              <label className="relative min-w-0">
                <span className="sr-only">Search rules</span>
                <Search size={13} aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search rule, scope, or engine…"
                  className="w-64 rounded-sm border border-border bg-surface-primary py-1.5 pl-8 pr-2 text-[12px] text-text-primary placeholder:text-text-muted"
                />
              </label>
            }
          />
          {visible.length === 0 ? (
            <InlineState tone="empty" compact title="No rules match this search" />
          ) : (
            <div className="divide-y divide-border">
              {visible.map((pack) => (
                <article key={pack.id} className="p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h2 className="text-[15px] font-semibold text-text-primary">{pack.name}</h2>
                        <span className="rounded-full border border-border bg-surface-primary px-2 py-0.5 font-mono text-[10px] text-text-muted">{pack.engine}</span>
                        <span className="inline-flex items-center gap-1 text-[11px] text-success">
                          <ShieldCheck size={12} aria-hidden="true" /> Enabled
                        </span>
                      </div>
                      <p className="mt-1 font-mono text-[11px] text-text-muted">{pack.id} · v{pack.version}</p>
                    </div>
                    <span className="inline-flex items-center gap-1 text-[11px] text-success">
                      <CheckCircle2 size={13} aria-hidden="true" /> {pack.validation}
                    </span>
                  </div>
                  <dl className="mt-3 grid gap-3 text-[12px] min-[700px]:grid-cols-3">
                    <Metadata label="Provenance" value={`${pack.creationMethod} · ${pack.source}`} />
                    <Metadata label="Licence" value={pack.license} />
                    <Metadata label="Fixture health" value={pack.fixtureSummary} />
                  </dl>
                  <details className="mt-4 rounded-sm border border-border bg-surface-primary">
                    <summary className="cursor-pointer px-3 py-2 text-[12px] font-medium text-text-primary">
                      {pack.rules.length} rules in this view
                    </summary>
                    <div className="max-h-80 overflow-auto border-t border-border">
                      <table className="w-full min-w-[42rem] text-left text-[12px]">
                        <thead className="sticky top-0 bg-surface-secondary text-text-muted">
                          <tr><th className="px-3 py-2">Rule</th><th className="px-3 py-2">Severity</th><th className="px-3 py-2">Scope</th><th className="px-3 py-2">Fixtures</th></tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {pack.rules.map((rule) => (
                            <tr key={rule.id}>
                              <td className="px-3 py-2"><span className="block text-text-primary">{rule.title}</span><span className="font-mono text-[10px] text-text-muted">{rule.id}</span></td>
                              <td className="px-3 py-2 capitalize text-text-secondary">{rule.severity}</td>
                              <td className="px-3 py-2 text-text-secondary"><span className="block">{rule.scope.join(", ")}</span><span className="mt-0.5 block text-[10px] text-text-muted">{rule.provenance}</span></td>
                              <td className="px-3 py-2">
                                <span className={`inline-flex items-center gap-1 ${rule.fixtureHealth === "coverageNeeded" ? "text-warning" : "text-success"}`}>
                                  {rule.fixtureHealth === "coverageNeeded" && <TriangleAlert size={12} aria-hidden="true" />}
                                  {rule.fixtureHealth === "verified" ? "Verified" : rule.fixtureHealth === "unitTested" ? "Unit tested" : "Coverage needed"}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </details>
                  <p className="mt-2 break-all font-mono text-[10px] text-text-muted">Snapshot: {pack.contentSha256}</p>
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </ToolPage>
  );
}

function Metadata({ label, value }: { label: string; value: string }): JSX.Element {
  return <div><dt className="font-semibold uppercase tracking-[0.1em] text-text-muted">{label}</dt><dd className="mt-1 leading-relaxed text-text-secondary">{value}</dd></div>;
}
