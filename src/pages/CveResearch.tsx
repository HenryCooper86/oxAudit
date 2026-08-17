import { useCallback, useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  ArrowLeft,
  Bot,
  Bug,
  Calendar,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Loader2,
  PackageSearch,
  Search,
} from "lucide-react";
import { EmptyState } from "../components/EmptyState";
import { SeverityBadge } from "../components/SeverityBadge";
import { TopBar } from "../components/TopBar";
import { api } from "../lib/api";
import { fmtDate, fmtDateTime } from "../lib/format";
import { useAppStore, useToastStore } from "../lib/stores";
import type { CveDetail, CveItem, CveSearchResult } from "../lib/types";
import Markdown from "react-markdown";

const PER_PAGE = 20;
const ECOSYSTEMS = ["npm", "crates.io", "Go", "PyPI", "RubyGems", "Packagist", "Maven"];

export function CveResearchPage() {
  const aiReady = useAppStore((s) => s.aiReady);
  const push = useToastStore((s) => s.push);

  const [query, setQuery] = useState("");
  const [recent, setRecent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CveSearchResult | null>(null);
  const [start, setStart] = useState(0);

  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [pkgEco, setPkgEco] = useState("npm");
  const [pkgName, setPkgName] = useState("");
  const [pkgLoading, setPkgLoading] = useState(false);
  const [pkgResult, setPkgResult] = useState<unknown[] | null>(null);

  const search = useCallback(
    async (q: string, startIndex: number, useRecent: boolean) => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.searchCves(
          q,
          startIndex,
          PER_PAGE,
          useRecent ? 7 : null,
        );
        setResult(res);
        setStart(startIndex);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    search("", 0, false);
  }, [search]);

  const openDetail = async (id: string) => {
    setDetailLoading(true);
    setError(null);
    try {
      const d = await api.cveDetail(id);
      setDetail(d);
    } catch (e) {
      setError(String(e));
    } finally {
      setDetailLoading(false);
    }
  };

  const lookupPackage = async () => {
    if (!pkgName.trim()) return;
    setPkgLoading(true);
    setError(null);
    try {
      const res = await api.osvPackageVulns(pkgEco, pkgName.trim());
      setPkgResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setPkgLoading(false);
    }
  };

  if (detail) {
    return (
      <CveDetailView
        detail={detail}
        loading={detailLoading}
        aiReady={!!aiReady}
        onBack={() => setDetail(null)}
        onAi={async () => {
          try {
            const res = await api.researchCve(detail.item, detail.osv);
            push("success", "AI briefing ready");
            return res;
          } catch (e) {
            push("error", String(e));
            return null;
          }
        }}
      />
    );
  }

  const total = result?.total ?? 0;
  const hasPrev = start > 0;
  const hasNext = start + PER_PAGE < total;

  return (
    <div className="mx-auto max-w-6xl px-6 py-6">
      <TopBar
        title="CVE Research"
        subtitle="Search the NVD database and query OSV for package advisories"
      />

      <div className="mt-5 rounded-xl border border-ink-700 bg-ink-850 p-4">
        <div className="flex items-center gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search(query, 0, recent)}
            placeholder="Search CVEs — e.g. 'apache log4j rce', 'nginx', 'CVE-2024-…'"
            className="selectable flex-1 rounded-lg border border-ink-600 bg-ink-900 px-3 py-2 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
          />
          <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={recent}
              onChange={(e) => setRecent(e.target.checked)}
              className="accent-teal-500"
            />
            Modified last 7 days
          </label>
          <button
            onClick={() => search(query, 0, recent)}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 px-4 py-2 text-xs font-bold text-ink-950 shadow-lg shadow-teal-900/30 hover:opacity-90 disabled:opacity-40"
          >
            {loading ? <Loader2 size={13} className="animate-spin" /> : <Search size={13} />}
            Search
          </button>
        </div>

        {/* OSV package lookup */}
        <div className="mt-3 flex items-center gap-2 border-t border-ink-800 pt-3">
          <PackageSearch size={14} className="text-sky-400" />
          <span className="text-xs text-slate-400">Package lookup (OSV):</span>
          <select
            value={pkgEco}
            onChange={(e) => setPkgEco(e.target.value)}
            className="rounded-lg border border-ink-600 bg-ink-900 px-2 py-1.5 text-xs text-slate-300 outline-none"
          >
            {ECOSYSTEMS.map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
          </select>
          <input
            value={pkgName}
            onChange={(e) => setPkgName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && lookupPackage()}
            placeholder="package name, e.g. lodash"
            className="selectable flex-1 rounded-lg border border-ink-600 bg-ink-900 px-3 py-1.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
          />
          <button
            onClick={lookupPackage}
            disabled={pkgLoading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-750 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-ink-500"
          >
            {pkgLoading ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
            Look up
          </button>
        </div>
      </div>

      {error && (
        <div className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
          {error}
        </div>
      )}

      {pkgResult && (
        <div className="mt-4 rounded-xl border border-ink-700 bg-ink-850 p-4">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-500">
            OSV advisories for {pkgName} ({pkgEco}) — {pkgResult.length}
          </h3>
          {pkgResult.length === 0 ? (
            <p className="mt-2 text-xs text-slate-500">No known advisories for this package.</p>
          ) : (
            <div className="mt-2 space-y-1.5">
              {pkgResult.slice(0, 15).map((v: any, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      openUrl(`https://osv.dev/vulnerability/${v.id}`);
                    }}
                    className="font-mono text-sky-300 hover:underline"
                  >
                    {v.id}
                  </a>
                  <span className="truncate text-slate-400">
                    {v.summary || (v.details || "").slice(0, 120)}
                  </span>
                  <span className="ml-auto shrink-0 text-[10px] text-slate-600">
                    {fmtDate(v.published)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {result && (
        <div className="mt-6">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>
              {total.toLocaleString()} results
              {query ? ` for “${query}”` : recent ? " (recent)" : ""}
            </span>
            <span className="tabular-nums">
              {start + 1}–{Math.min(start + PER_PAGE, total)} of {total.toLocaleString()}
            </span>
          </div>
          <div className="mt-2 space-y-2">
            {result.items.length === 0 && (
              <EmptyState
                icon={<Bug size={32} />}
                title="No CVEs found"
                description="Try a broader keyword, or use the package lookup for OSV advisories."
              />
            )}
            {result.items.map((c) => (
              <CveRow key={c.id} cve={c} onOpen={() => openDetail(c.id)} />
            ))}
          </div>
          <div className="mt-4 flex items-center justify-center gap-3">
            <button
              onClick={() => search(query, Math.max(0, start - PER_PAGE), recent)}
              disabled={!hasPrev || loading}
              className="inline-flex items-center gap-1 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-xs text-slate-300 disabled:opacity-40"
            >
              <ChevronLeft size={13} /> Prev
            </button>
            <button
              onClick={() => search(query, start + PER_PAGE, recent)}
              disabled={!hasNext || loading}
              className="inline-flex items-center gap-1 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-xs text-slate-300 disabled:opacity-40"
            >
              Next <ChevronRight size={13} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function CveRow({ cve, onOpen }: { cve: CveItem; onOpen: () => void }) {
  return (
    <button
      onClick={onOpen}
      className="w-full rounded-xl border border-ink-700 bg-ink-850 px-4 py-3 text-left transition-colors hover:border-teal-500/40 hover:bg-ink-800"
    >
      <div className="flex items-center gap-2.5">
        <span className="font-mono text-[13px] font-bold text-sky-300">{cve.id}</span>
        <SeverityBadge severity={cve.severity} />
        {cve.cvssScore !== null && (
          <span className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
            CVSS {cve.cvssScore.toFixed(1)}
          </span>
        )}
        {cve.cwes.slice(0, 3).map((c) => (
          <span key={c} className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
            {c}
          </span>
        ))}
        <span className="ml-auto shrink-0 text-[11px] text-slate-600">{fmtDate(cve.published)}</span>
      </div>
      <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-slate-400">{cve.description}</p>
      {cve.affectedProducts.length > 0 && (
        <p className="mt-1 truncate font-mono text-[10px] text-slate-600">
          {cve.affectedProducts.join(" · ")}
        </p>
      )}
    </button>
  );
}

function CveDetailView({
  detail,
  loading,
  aiReady,
  onBack,
  onAi,
}: {
  detail: CveDetail;
  loading: boolean;
  aiReady: boolean;
  onBack: () => void;
  onAi: () => Promise<unknown>;
}) {
  const { item } = detail;
  const [briefing, setBriefing] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [showOsv, setShowOsv] = useState(false);

  const runAi = async () => {
    if (!aiReady) return;
    setAiLoading(true);
    try {
      const res = (await onAi()) as { content: string } | null;
      if (res) setBriefing(res.content);
    } finally {
      setAiLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl px-6 py-6">
      <button
        onClick={onBack}
        className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200"
      >
        <ArrowLeft size={14} /> Back to results
      </button>

      {loading ? (
        <div className="mt-8 flex items-center justify-center gap-2 text-sm text-slate-500">
          <Loader2 size={16} className="animate-spin" /> Loading CVE details…
        </div>
      ) : (
        <>
          <div className="mt-4 rounded-xl border border-ink-700 bg-ink-850 p-5">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="font-mono text-lg font-bold text-slate-100">{item.id}</h1>
              <SeverityBadge severity={item.severity} />
              {item.cvssScore !== null && (
                <span className="rounded border border-ink-600 bg-ink-900 px-2 py-0.5 font-mono text-xs text-slate-300">
                  CVSS {item.cvssScore.toFixed(1)}
                </span>
              )}
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-500">
              <span className="inline-flex items-center gap-1">
                <Calendar size={11} /> Published {fmtDateTime(item.published)}
              </span>
              <span className="inline-flex items-center gap-1">
                <Calendar size={11} /> Modified {fmtDateTime(item.modified)}
              </span>
            </div>

            {item.cwes.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {item.cwes.map((c) => (
                  <span key={c} className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-sky-300">
                    {c}
                  </span>
                ))}
              </div>
            )}

            <p className="selectable mt-4 text-[13px] leading-relaxed text-slate-300">{item.description}</p>

            {item.affectedProducts.length > 0 && (
              <div className="mt-4">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Affected products
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {item.affectedProducts.map((p) => (
                    <span key={p} className="rounded border border-ink-600 bg-ink-900 px-2 py-0.5 font-mono text-[10px] text-slate-400">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {item.references.length > 0 && (
              <div className="mt-4">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  References
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {item.references.slice(0, 8).map((r) => (
                    <button
                      key={r}
                      onClick={() => openUrl(r)}
                      className="inline-flex max-w-[300px] items-center gap-1 truncate rounded border border-ink-600 bg-ink-900 px-2 py-1 text-[11px] text-sky-300 hover:border-sky-500/50"
                    >
                      <ExternalLink size={10} />
                      <span className="truncate">{r.replace(/^https?:\/\//, "")}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="mt-4 flex items-center gap-2">
            <button
              onClick={runAi}
              disabled={!aiReady || aiLoading}
              className="inline-flex items-center gap-1.5 rounded-lg border border-teal-500/40 bg-teal-500/10 px-3.5 py-2 text-xs font-medium text-teal-300 hover:bg-teal-500/20 disabled:opacity-40"
            >
              {aiLoading ? <Loader2 size={13} className="animate-spin" /> : <Bot size={13} />}
              {aiLoading ? "Generating research briefing…" : briefing ? "Regenerate AI briefing" : "Generate AI research briefing"}
            </button>
            {detail.osv ? (
              <button
                onClick={() => setShowOsv(!showOsv)}
                className="rounded-lg border border-ink-600 bg-ink-850 px-3 py-2 text-xs text-slate-400 hover:text-slate-200"
              >
                {showOsv ? "Hide" : "Show"} OSV record
              </button>
            ) : null}
            <button
              onClick={() => openUrl(`https://nvd.nist.gov/vuln/detail/${item.id}`)}
              className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-850 px-3 py-2 text-xs text-slate-400 hover:text-slate-200"
            >
              <ExternalLink size={12} /> NVD page
            </button>
          </div>

          {aiLoading && (
            <div className="mt-3 animate-pulse rounded-lg border border-ink-700 bg-ink-900 px-4 py-3 text-xs text-slate-500">
              Consulting the model… this can take 20–90s.
            </div>
          )}
          {briefing && (
            <div className="md-body selectable mt-3 max-h-[480px] overflow-y-auto rounded-xl border border-ink-700 bg-ink-900 px-5 py-4 text-xs">
              <Markdown>{briefing}</Markdown>
            </div>
          )}

          {showOsv && detail.osv && (
            <div className="selectable mt-3 overflow-x-auto rounded-xl border border-ink-700 bg-ink-950 p-4">
              <pre className="font-mono text-[10px] leading-relaxed text-slate-400">
                {JSON.stringify(detail.osv, null, 2)}
              </pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
