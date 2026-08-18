import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { ChevronLeft, ChevronRight, PackageSearch, Search } from "lucide-react";
import { CveDossier } from "../components/CveDossier";
import { SeverityBadge } from "../components/SeverityBadge";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { TargetBar } from "../components/workbench/TargetBar";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { fmtDate } from "../lib/format";
import { useAppStore, useToastStore } from "../lib/stores";
import type { CveDetail, CveItem, CveSearchResult } from "../lib/types";

const PER_PAGE = 20;
const ECOSYSTEMS = [
  "npm",
  "crates.io",
  "Go",
  "PyPI",
  "RubyGems",
  "Packagist",
  "Maven",
];
type SearchParameters = {
  query: string;
  recent: boolean;
  startIndex: number;
};
type PackageLookupResult = {
  ecosystem: string;
  packageName: string;
  advisories: unknown[];
};

export function CveResearchPage(): JSX.Element {
  const aiReady = useAppStore((state) => state.aiReady);
  const setPageStatus = useAppStore((state) => state.setPageStatus);
  const clearPageStatus = useAppStore((state) => state.clearPageStatus);
  const push = useToastStore((state) => state.push);
  const [query, setQuery] = useState("");
  const [recent, setRecent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [failedSearch, setFailedSearch] = useState<SearchParameters | null>(
    null,
  );
  const [result, setResult] = useState<CveSearchResult | null>(null);
  const [completedSearch, setCompletedSearch] =
    useState<SearchParameters | null>(null);
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [pkgEco, setPkgEco] = useState("npm");
  const [pkgName, setPkgName] = useState("");
  const [pkgLoading, setPkgLoading] = useState(false);
  const [pkgResult, setPkgResult] = useState<PackageLookupResult | null>(null);
  const [pkgError, setPkgError] = useState<string | null>(null);
  const searchRequestRef = useRef(false);
  const detailRequestRef = useRef(0);
  const packageRequestRef = useRef(0);

  const search = useCallback(
    async (parameters: SearchParameters) => {
      if (searchRequestRef.current) return;
      searchRequestRef.current = true;
      setLoading(true);
      setSearchError(null);
      setFailedSearch(null);
      setPageStatus("cve-research", {
        label: "Searching NVD",
        tone: "running",
      });
      try {
        const res = await api.searchCves(
          parameters.query,
          parameters.startIndex,
          PER_PAGE,
          parameters.recent ? 7 : null,
        );
        setResult(res);
        setCompletedSearch(parameters);
        detailRequestRef.current += 1;
        setSelectedCveId(null);
        setDetail(null);
        setDetailLoading(false);
        setDetailError(null);
        setPageStatus("cve-research", {
          label: "Research ready",
          tone: "success",
          detail: `${res.total} results`,
        });
      } catch (error) {
        setSearchError(String(error));
        setFailedSearch(parameters);
        setPageStatus("cve-research", {
          label: "Research unavailable",
          tone: "error",
        });
      } finally {
        setLoading(false);
        searchRequestRef.current = false;
      }
    },
    [setPageStatus],
  );

  useEffect(() => () => clearPageStatus("cve-research"), [clearPageStatus]);

  const openDetail = async (id: string) => {
    if (detailLoading || (id === selectedCveId && detail)) return;
    const requestId = ++detailRequestRef.current;
    setSelectedCveId(id);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    try {
      const response = await api.cveDetail(id);
      if (requestId === detailRequestRef.current) setDetail(response);
    } catch (error) {
      if (requestId === detailRequestRef.current) setDetailError(String(error));
    } finally {
      if (requestId === detailRequestRef.current) setDetailLoading(false);
    }
  };

  const lookupPackage = async () => {
    const packageName = pkgName.trim();
    if (!packageName || pkgLoading) return;
    const requestId = ++packageRequestRef.current;
    const parameters = { ecosystem: pkgEco, packageName };
    setPkgLoading(true);
    setPkgError(null);
    try {
      const advisories = await api.osvPackageVulns(
        parameters.ecosystem,
        parameters.packageName,
      );
      if (requestId === packageRequestRef.current) {
        setPkgResult({ ...parameters, advisories });
      }
    } catch (error) {
      if (requestId === packageRequestRef.current) setPkgError(String(error));
    } finally {
      if (requestId === packageRequestRef.current) setPkgLoading(false);
    }
  };

  const selectedItem =
    result?.items.find((item) => item.id === selectedCveId) ??
    result?.items[0] ??
    null;
  const total = result?.total ?? 0;
  const start = completedSearch?.startIndex ?? 0;
  const hasPrev = start > 0;
  const hasNext = start + PER_PAGE < total;

  return (
    <ToolPage
      title="CVE Research"
      description="Search NVD CVEs, inspect source records, and query OSV package advisories."
      context={
        <span className="rounded-full border border-ink-600 bg-ink-850 px-2 py-0.5 text-[11px] text-stone-400">
          No project required
        </span>
      }
    >
      <TargetBar
        primary={
          <button
            type="button"
            onClick={() => void search({ query, recent, startIndex: 0 })}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-md bg-accent-500 px-3.5 py-2 text-[12px] font-semibold text-ink-950 hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Search size={13} aria-hidden="true" />
            {loading ? "Searching…" : "Search NVD"}
          </button>
        }
        secondary={
          <PackageLookup
            ecosystem={pkgEco}
            packageName={pkgName}
            loading={pkgLoading}
            error={pkgError}
            result={pkgResult}
            onEcosystem={setPkgEco}
            onPackage={setPkgName}
            onLookup={lookupPackage}
          />
        }
      >
        <label
          htmlFor="cve-query"
          className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.12em] text-stone-400"
        >
          CVE ID or keyword
        </label>
        <div className="flex flex-wrap items-center gap-2">
          <input
            id="cve-query"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                void search({ query, recent, startIndex: 0 });
              }
            }}
            placeholder="apache log4j rce, nginx, CVE-2024-…"
            className="min-w-[min(100%,18rem)] flex-1 rounded-md border border-ink-600 bg-ink-900 px-3 py-2 text-[13px] text-stone-200 placeholder:text-stone-400"
          />
          <label className="flex cursor-pointer items-center gap-2 text-[12px] text-stone-400">
            <input
              type="checkbox"
              checked={recent}
              onChange={(event) => setRecent(event.target.checked)}
              className="accent-accent-500"
            />
            Modified last 7 days
          </label>
        </div>
      </TargetBar>

      {searchError && (
        <InlineState
          tone="error"
          title="CVE search unavailable"
          description={searchError}
          action={
            <button
              type="button"
              onClick={() =>
                void search(
                  failedSearch ??
                    completedSearch ?? { query, recent, startIndex: 0 },
                )
              }
              className="rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[12px] font-medium text-stone-200 hover:bg-ink-700"
            >
              Retry search
            </button>
          }
        />
      )}
      {loading && (
        <InlineState
          tone="running"
          compact
          title="Searching NVD"
          description={
            result
              ? "Previous completed results remain available below."
              : "Looking for matching CVE records."
          }
        />
      )}

      {result && completedSearch && result.items.length > 0 && (
        <section
          aria-label="CVE search results"
          className="overflow-hidden rounded-lg border border-ink-700 bg-ink-850"
        >
          <ResultsToolbar
            countLabel={`${total.toLocaleString()} results${completedSearch.query ? ` for “${completedSearch.query}”` : completedSearch.recent ? " (recent)" : ""} · ${start + 1}–${Math.min(start + PER_PAGE, total)}`}
            actions={
              <Pagination
                hasPrev={hasPrev}
                hasNext={hasNext}
                loading={loading}
                onPrevious={() =>
                  void search({
                    ...completedSearch,
                    startIndex: Math.max(0, start - PER_PAGE),
                  })
                }
                onNext={() =>
                  void search({
                    ...completedSearch,
                    startIndex: start + PER_PAGE,
                  })
                }
              />
            }
          />
          <SplitWorkspace
            listLabel="CVE results"
            detailLabel="CVE dossier"
            hasSelection={selectedCveId !== null}
            onBackToList={() => setSelectedCveId(null)}
            list={
              <CveList
                items={result.items}
                selectedId={selectedCveId}
                onSelect={openDetail}
              />
            }
            detail={
              <>
                {detailError && (
                  <div className="p-3">
                    <InlineState
                      tone="error"
                      compact
                      title="CVE detail unavailable"
                      description={detailError}
                      action={
                        selectedItem ? (
                          <button
                            type="button"
                            onClick={() => void openDetail(selectedItem.id)}
                            className="rounded-md border border-ink-600 bg-ink-750 px-2.5 py-1.5 text-[12px] font-medium text-stone-200 hover:bg-ink-700"
                          >
                            Retry details
                          </button>
                        ) : undefined
                      }
                    />
                  </div>
                )}
                <CveDossier
                  detail={detail}
                  loading={detailLoading}
                  aiReady={!!aiReady}
                  onGenerateBriefing={async () => {
                    if (!detail) return null;
                    try {
                      const response = await api.researchCve(
                        detail.item,
                        detail.osv,
                      );
                      push("success", "AI briefing ready");
                      return response.content;
                    } catch (error) {
                      push("error", "AI briefing failed");
                      throw error;
                    }
                  }}
                />
              </>
            }
          />
        </section>
      )}
      {result && result.items.length === 0 && (
        <InlineState
          tone="empty"
          title="No CVEs found"
          description="Try a broader keyword, or use Package lookup for OSV advisories."
        />
      )}
      {!result && !loading && !searchError && (
        <InlineState
          tone="idle"
          title="Start CVE research"
          description="Search by CVE ID or keyword to begin reviewing NVD records."
        />
      )}
    </ToolPage>
  );
}

function PackageLookup({
  ecosystem,
  packageName,
  loading,
  error,
  result,
  onEcosystem,
  onPackage,
  onLookup,
}: {
  ecosystem: string;
  packageName: string;
  loading: boolean;
  error: string | null;
  result: PackageLookupResult | null;
  onEcosystem: (value: string) => void;
  onPackage: (value: string) => void;
  onLookup: () => void;
}): JSX.Element {
  return (
    <details>
      <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[12px] font-medium text-stone-300">
        <PackageSearch size={13} aria-hidden="true" />
        Package lookup <span className="text-stone-400">(OSV)</span>
      </summary>
      <div className="mt-3 flex flex-wrap items-end gap-2">
        <label className="text-[11px] text-stone-400">
          Ecosystem
          <select
            value={ecosystem}
            onChange={(event) => onEcosystem(event.target.value)}
            className="mt-1 block rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-[12px] text-stone-200"
          >
            {ECOSYSTEMS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label className="min-w-[min(100%,16rem)] flex-1 text-[11px] text-stone-400">
          Package name
          <input
            value={packageName}
            onChange={(event) => onPackage(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void onLookup();
            }}
            placeholder="lodash"
            className="mt-1 block w-full rounded-md border border-ink-600 bg-ink-900 px-3 py-1.5 text-[13px] text-stone-200 placeholder:text-stone-400"
          />
        </label>
        <button
          type="button"
          onClick={() => void onLookup()}
          disabled={loading || !packageName.trim()}
          className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-750 px-3 py-1.5 text-[12px] font-medium text-stone-200 hover:bg-ink-700 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Search size={12} aria-hidden="true" />
          {loading ? "Looking up…" : "Look up"}
        </button>
      </div>
      {error && (
        <p role="alert" className="mt-2 text-[12px] text-red-300">
          OSV package lookup unavailable: {error}
        </p>
      )}
      {result && (
        <PackageResults
          ecosystem={result.ecosystem}
          packageName={result.packageName}
          result={result.advisories}
        />
      )}
    </details>
  );
}

function PackageResults({
  ecosystem,
  packageName,
  result,
}: {
  ecosystem: string;
  packageName: string;
  result: unknown[];
}): JSX.Element {
  const advisories = result as Array<{
    id?: string;
    summary?: string;
    details?: string;
    published?: string;
  }>;
  return (
    <div className="mt-3 border-t border-ink-800 pt-3">
      <p className="text-[12px] text-stone-300">
        OSV advisories for {packageName} ({ecosystem}) — {advisories.length}
      </p>
      {advisories.length === 0 ? (
        <p className="mt-1 text-[12px] text-stone-400">
          No known advisories for this package.
        </p>
      ) : (
        <ul className="mt-2 space-y-1.5">
          {advisories.slice(0, 15).map((advisory, index) => (
            <li
              key={`${advisory.id ?? "advisory"}-${index}`}
              className="flex items-start gap-1.5 text-[12px] text-stone-400"
            >
              <button
                type="button"
                disabled={!advisory.id}
                onClick={() =>
                  advisory.id &&
                  openUrl(`https://osv.dev/vulnerability/${advisory.id}`)
                }
                className="shrink-0 font-mono text-sky-300 hover:underline disabled:cursor-not-allowed disabled:text-stone-500"
              >
                {advisory.id ?? "OSV advisory"}
              </button>
              {advisory.summary || advisory.details ? (
                <span>
                  — {advisory.summary || advisory.details?.slice(0, 120)}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function CveList({
  items,
  selectedId,
  onSelect,
}: {
  items: CveItem[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}): JSX.Element {
  return (
    <ul className="max-h-[39rem] overflow-auto" aria-label="CVE results">
      {items.map((item) => {
        const selected = item.id === selectedId;
        return (
          <li key={item.id}>
            <button
              type="button"
              aria-current={selected ? "true" : undefined}
              onClick={() => void onSelect(item.id)}
              className={`block w-full border-l-2 border-b border-ink-800 px-3 py-3 text-left transition-colors ${selected ? "border-l-accent-500 bg-accent-500/5" : "border-l-transparent hover:bg-ink-800"}`}
            >
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-[13px] font-semibold text-sky-300">
                  {item.id}
                </span>
                <SeverityBadge severity={item.severity} />
                {item.cvssScore !== null && (
                  <span className="rounded bg-ink-900 px-1.5 py-0.5 font-mono text-[11px] text-stone-400">
                    CVSS {item.cvssScore.toFixed(1)}
                  </span>
                )}
                <span className="ml-auto text-[11px] text-stone-400">
                  {fmtDate(item.published)}
                </span>
              </div>
              <p className="mt-1.5 line-clamp-2 text-[13px] leading-relaxed text-stone-300">
                {item.description}
              </p>
              <p className="mt-1 truncate font-mono text-[11px] text-stone-400">
                {item.affectedProducts.join(" · ")}
              </p>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function Pagination({
  hasPrev,
  hasNext,
  loading,
  onPrevious,
  onNext,
}: {
  hasPrev: boolean;
  hasNext: boolean;
  loading: boolean;
  onPrevious: () => void;
  onNext: () => void;
}): JSX.Element {
  return (
    <div className="flex items-center gap-1">
      <button
        type="button"
        onClick={onPrevious}
        disabled={!hasPrev || loading}
        className="inline-flex items-center gap-1 rounded-md border border-ink-600 bg-ink-750 px-2 py-1.5 text-[11px] text-stone-300 hover:bg-ink-700 disabled:cursor-not-allowed disabled:opacity-40"
      >
        <ChevronLeft size={12} aria-hidden="true" />
        Prev
      </button>
      <button
        type="button"
        onClick={onNext}
        disabled={!hasNext || loading}
        className="inline-flex items-center gap-1 rounded-md border border-ink-600 bg-ink-750 px-2 py-1.5 text-[11px] text-stone-300 hover:bg-ink-700 disabled:cursor-not-allowed disabled:opacity-40"
      >
        Next
        <ChevronRight size={12} aria-hidden="true" />
      </button>
    </div>
  );
}
