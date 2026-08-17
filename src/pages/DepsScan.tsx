import { useEffect, useRef, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Boxes, ChevronDown, ExternalLink, Play, Search } from "lucide-react";
import { EmptyState } from "../components/EmptyState";
import { FolderPicker } from "../components/FolderPicker";
import { ProgressBar } from "../components/ProgressBar";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatCard } from "../components/StatCard";
import { TopBar } from "../components/TopBar";
import { api } from "../lib/api";
import { fmtDate } from "../lib/format";
import { useAppStore, useToastStore } from "../lib/stores";
import type { DependencyScanResult, LockfileInfo } from "../lib/types";

export function DepsScanPage() {
  const addRecentScan = useAppStore((s) => s.addRecentScan);
  const setActiveProjectStore = useAppStore((s) => s.setActiveProject);
  const push = useToastStore((s) => s.push);

  const [path, setPath] = useState("");
  const [running, setRunning] = useState(false);
  const [preview, setPreview] = useState<LockfileInfo[] | null>(null);
  const [result, setResult] = useState<DependencyScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const unlistenRef = useRef<UnlistenFn | null>(null);
  useEffect(() => {
    let disposed = false;
    listen<{ phase: string; done?: number; total?: number }>("deps://progress", (e) => {
      if (!disposed) {
        setPhase(e.payload.phase);
        setProgress({ done: e.payload.done ?? 0, total: e.payload.total ?? 0 });
      }
    }).then((fn) => {
      if (disposed) fn();
      else unlistenRef.current = fn;
    });
    return () => {
      disposed = true;
      unlistenRef.current?.();
    };
  }, []);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);

  const findLockfiles = async () => {
    if (!path) return;
    try {
      const res = await api.findLockfiles(path);
      setPreview(res);
    } catch (e) {
      setError(String(e));
    }
  };

  const run = async () => {
    if (!path || running) return;
    setRunning(true);
    setError(null);
    setResult(null);
    setProgress({ done: 0, total: 0 });
    try {
      const res = await api.scanDependencies(path);
      setResult(res);
      setPreview(
        res.summary.lockfilesFound.map((p) => {
          const kind = p.split(/[\\/]/).pop() ?? "?";
          return { path: p, kind, packages: 0 };
        }),
      );
      addRecentScan({
        id: `deps-${Date.now()}`,
        kind: "deps",
        path,
        at: new Date().toISOString(),
        findings: res.summary.vulnerabilitiesFound,
        critical: res.vulnerabilities.filter((v) => v.severity === "critical").length,
        high: res.vulnerabilities.filter((v) => v.severity === "high").length,
      });
      push(
        "success",
        `Dependency scan complete — ${res.summary.vulnerabilitiesFound} vulnerabilities across ${res.summary.packagesQueried} packages`,
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
      setProgress(null);
      setPhase(null);
    }
  };

  const vulns = result?.vulnerabilities ?? [];
  const filteredVulns = vulns.filter((v) => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return `${v.id} ${v.packageName} ${v.summary} ${v.aliases.join(" ")}`.toLowerCase().includes(q);
  });

  const critical = vulns.filter((v) => v.severity === "critical").length;
  const high = vulns.filter((v) => v.severity === "high").length;

  return (
    <div className="mx-auto max-w-6xl px-6 py-6">
      <TopBar
        title="Dependency Scanner"
        subtitle="Parse lockfiles and check every package against the OSV vulnerability database"
      />

      <div className="mt-5 rounded-xl border border-ink-700 bg-ink-850 p-4">
        <FolderPicker
          value={path}
          onChange={(p) => {
            setPath(p);
            api.setActiveProject(p).catch(() => undefined);
            setActiveProjectStore(p);
          }}
        />
        <div className="mt-3 flex items-center gap-2">
          <button
            onClick={findLockfiles}
            disabled={!path}
            className="inline-flex items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-750 px-3.5 py-2 text-xs font-medium text-slate-200 hover:border-ink-500"
          >
            <Search size={13} /> Find lockfiles
          </button>
          <button
            onClick={run}
            disabled={!path || running}
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 px-4 py-2 text-xs font-bold text-ink-950 shadow-lg shadow-teal-900/30 hover:opacity-90 disabled:opacity-40"
          >
            <Play size={13} />
            {running ? "Scanning…" : "Scan dependencies"}
          </button>
        </div>

        {running && (
          <div className="mt-4">
            <ProgressBar
              indeterminate={!progress?.total}
              value={progress?.done ?? 0}
              max={progress?.total ?? 0}
              label={
                phase === "parsing"
                  ? "Parsing lockfiles…"
                  : phase === "querying-osv"
                    ? "Querying OSV vulnerability database…"
                    : "Working…"
              }
            />
          </div>
        )}
        {error && (
          <div className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        {preview && preview.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            {preview.map((l, i) => (
              <span
                key={i}
                className="inline-flex items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-900 px-2.5 py-1 font-mono text-[11px] text-slate-400"
              >
                <Boxes size={11} className="text-sky-400" />
                {l.path.split(/[\\/]/).pop()}
                <span className="text-slate-600">({l.packages} pkgs)</span>
              </span>
            ))}
          </div>
        )}
      </div>

      {result && (
        <>
          <div className="mt-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatCard label="Lockfiles" value={result.summary.lockfilesFound.length} />
            <StatCard label="Packages queried" value={result.summary.packagesQueried.toLocaleString()} />
            <StatCard label="Vulnerabilities" value={vulns.length} tone="danger" />
            <StatCard
              label="Critical / High"
              value={`${critical} / ${high}`}
              tone="warning"
            />
          </div>

          <div className="mt-6">
            <div className="flex items-center gap-2">
              <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                Vulnerable packages ({filteredVulns.length})
              </h2>
              <div className="ml-auto">
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter by package, CVE, advisory…"
                  className="w-72 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
                />
              </div>
            </div>

            <div className="mt-2 space-y-2">
              {filteredVulns.length === 0 && (
                <EmptyState
                  icon={<Boxes size={32} />}
                  title="No known vulnerabilities found"
                  description="All queried packages appear clean according to OSV. Remember: OSV only knows published advisories."
                />
              )}
              {filteredVulns.map((v) => {
                const key = `${v.id}:${v.packageName}:${v.installedVersion}`;
                const open = expanded === key;
                return (
                  <div key={key} className="overflow-hidden rounded-xl border border-ink-700 bg-ink-850">
                    <button
                      onClick={() => setExpanded(open ? null : key)}
                      className="flex w-full items-center gap-3 px-4 py-3 text-left"
                    >
                      <SeverityBadge severity={v.severity} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-[13px] font-semibold text-slate-100">
                            {v.packageName}
                          </span>
                          <span className="font-mono text-[11px] text-slate-500">
                            {v.installedVersion}
                          </span>
                          {v.aliases.slice(0, 3).map((a) => (
                            <span key={a} className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[10px] text-sky-300">
                              {a}
                            </span>
                          ))}
                        </div>
                        <div className="mt-0.5 truncate text-[11px] text-slate-500">
                          {v.id} · {v.summary || "no summary"}
                        </div>
                      </div>
                      {v.cvssScore !== null && (
                        <span className="font-mono text-xs font-bold text-slate-300">
                          {v.cvssScore.toFixed(1)}
                        </span>
                      )}
                      <ChevronDown size={15} className={`text-slate-500 transition-transform ${open ? "rotate-180" : ""}`} />
                    </button>
                    {open && (
                      <div className="border-t border-ink-800 px-4 pb-4 pt-3">
                        <p className="text-xs leading-relaxed text-slate-400">{v.details || v.summary}</p>
                        {v.affectedRange && (
                          <div className="mt-2 text-xs text-slate-500">
                            Affected: <span className="font-mono text-slate-300">{v.affectedRange}</span>
                          </div>
                        )}
                        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                          {v.fixedVersions.length > 0 ? (
                            <span className="rounded-lg border border-emerald-900/50 bg-emerald-950/20 px-2.5 py-1 text-emerald-300">
                              Fixed in: {v.fixedVersions.join(", ")}
                            </span>
                          ) : (
                            <span className="rounded-lg border border-amber-900/50 bg-amber-950/20 px-2.5 py-1 text-amber-300">
                              No fixed version published yet
                            </span>
                          )}
                          <span className="text-slate-600">Published {fmtDate(v.published)}</span>
                        </div>
                        {v.references.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {v.references.slice(0, 6).map((r) => (
                              <button
                                key={r}
                                onClick={() => openUrl(r)}
                                className="inline-flex max-w-[260px] items-center gap-1 truncate rounded border border-ink-600 bg-ink-800 px-2 py-1 text-[11px] text-sky-300 hover:border-sky-500/50"
                              >
                                <ExternalLink size={10} />
                                <span className="truncate">{r.replace(/^https?:\/\//, "")}</span>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {!result && !running && (
        <div className="mt-6">
          <EmptyState
            icon={<Boxes size={36} />}
            title="Scan your application's dependencies"
            description="Point VulnCompanion at a project. It finds package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, go.sum, Pipfile.lock, Gemfile.lock, composer.lock, pom.xml and requirements.txt, then queries OSV for every pinned package version."
          />
        </div>
      )}
    </div>
  );
}
