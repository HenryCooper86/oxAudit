import { useEffect, useMemo, useRef, useState } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { Ban, Clipboard, Download, Play, ScanLine, X } from "lucide-react";
import { EmptyState } from "../components/EmptyState";
import { FindingCard } from "../components/FindingCard";
import { FolderPicker } from "../components/FolderPicker";
import { ProgressBar } from "../components/ProgressBar";
import { StatCard } from "../components/StatCard";
import { TopBar } from "../components/TopBar";
import { api } from "../lib/api";
import { fmtBytes, fmtDuration } from "../lib/format";
import { useAppStore, useToastStore } from "../lib/stores";
import type { ScanProgress, ScanResult, Severity } from "../lib/types";

const SEVERITIES: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];

export function SourceScanPage() {
  const addRecentScan = useAppStore((s) => s.addRecentScan);
  const setActiveProjectStore = useAppStore((s) => s.setActiveProject);
  const push = useToastStore((s) => s.push);

  const [path, setPath] = useState("");
  const [scanSecrets, setScanSecrets] = useState(true);
  const [scanVulns, setScanVulns] = useState(true);
  const [includeGit, setIncludeGit] = useState(false);
  const [followSymlinks, setFollowSymlinks] = useState(false);
  const [maxSizeKb, setMaxSizeKb] = useState(1024);

  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exportOpen, setExportOpen] = useState(false);

  const [tab, setTab] = useState<"all" | "secret" | "vulnerability">("all");
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [langFilter, setLangFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const unlistenRef = useRef<UnlistenFn | null>(null);

  useEffect(() => {
    let disposed = false;
    listen<ScanProgress>("scan://progress", (e) => {
      if (!disposed) setProgress(e.payload);
    }).then((fn) => {
      if (disposed) fn();
      else unlistenRef.current = fn;
    });
    listen<ScanProgress>("scan://done", (e) => {
      if (!disposed) setProgress((p) => ({ ...p, ...e.payload }));
    }).then((fn) => {
      if (disposed) fn();
      else unlistenRef.current = fn;
    });
    return () => {
      disposed = true;
      unlistenRef.current?.();
    };
  }, []);

  const run = async () => {
    if (!path || running) return;
    setRunning(true);
    setError(null);
    setResult(null);
    setProgress({ phase: "walking" });
    try {
      const res = await api.scanProject({
        path,
        includeGit,
        followSymlinks,
        maxFileSizeKb: maxSizeKb,
        scanSecrets,
        scanVulnerabilities: scanVulns,
        extraIgnoredDirs: [],
      });
      setResult(res);
      addRecentScan({
        id: `${Date.now()}`,
        kind: "source",
        path,
        at: new Date().toISOString(),
        findings: res.summary.totalFindings,
        critical: res.summary.critical,
        high: res.summary.high,
      });
      push("success", `Scan complete — ${res.summary.totalFindings} findings in ${fmtDuration(res.summary.durationMs)}`);
    } catch (e) {
      setError(String(e));
      push("error", String(e));
    } finally {
      setRunning(false);
      setProgress(null);
    }
  };

  const cancel = async () => {
    try {
      await api.cancelScan();
      push("info", "Cancelling scan…");
    } catch {
      /* ignore */
    }
  };

  const filtered = useMemo(() => {
    if (!result) return [];
    const q = search.trim().toLowerCase();
    return result.findings.filter((f) => {
      if (tab !== "all" && f.category !== tab) return false;
      if (sevFilter !== "all" && f.severity !== sevFilter) return false;
      if (langFilter !== "all" && f.language !== langFilter) return false;
      if (q && !`${f.ruleName} ${f.filePath} ${f.matchText}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [result, tab, sevFilter, langFilter, search]);

  const languages = useMemo(() => {
    if (!result) return [];
    const set = new Set<string>();
    for (const f of result.findings) if (f.language) set.add(f.language);
    return ["all", ...Array.from(set).sort()];
  }, [result]);

  const grouped = useMemo(() => {
    const map = new Map<string, typeof filtered>();
    for (const f of filtered) {
      const key = `${f.filePath}:${f.line}`;
      const arr = map.get(key) ?? [];
      arr.push(f);
      map.set(key, arr);
    }
    return Array.from(map.entries());
  }, [filtered]);

  const exportJson = () => {
    if (!result) return;
    const blob = {
      tool: "VulnCompanion",
      version: "0.1.0",
      exportedAt: new Date().toISOString(),
      summary: result.summary,
      findings: result.findings,
    };
    const text = JSON.stringify(blob, null, 2);
    navigator.clipboard?.writeText(text).then(
      () => push("success", "Scan report copied to clipboard (JSON)"),
      () => push("error", "Clipboard unavailable"),
    );
    setExportOpen(false);
  };

  return (
    <div className="mx-auto max-w-6xl px-6 py-6">
      <TopBar
        title="Source Code Scanner"
        subtitle="Pattern-based vulnerability detection + secret leakage scanning"
      />

      {/* config panel */}
      <div className="mt-5 rounded-xl border border-ink-700 bg-ink-850 p-4">
        <FolderPicker
          value={path}
          onChange={(p) => {
            setPath(p);
            api.setActiveProject(p).catch(() => undefined);
            setActiveProjectStore(p);
          }}
        />
        <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2">
          <Toggle label="Secrets" checked={scanSecrets} onChange={setScanSecrets} />
          <Toggle label="Vulnerabilities" checked={scanVulns} onChange={setScanVulns} />
          <Toggle label="Include .git" checked={includeGit} onChange={setIncludeGit} />
          <Toggle label="Follow symlinks" checked={followSymlinks} onChange={setFollowSymlinks} />
          <label className="flex items-center gap-2 text-xs text-slate-400">
            Max file size
            <input
              type="number"
              value={maxSizeKb}
              min={1}
              max={10240}
              onChange={(e) => setMaxSizeKb(Number(e.target.value) || 1024)}
              className="w-20 rounded border border-ink-600 bg-ink-900 px-2 py-1 font-mono text-xs text-slate-200 outline-none focus:border-teal-500/60"
            />
            KB
          </label>
          <div className="ml-auto flex gap-2">
            {running && (
              <button
                onClick={cancel}
                className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2 text-xs font-medium text-red-300 hover:bg-red-500/20"
              >
                <Ban size={13} /> Cancel
              </button>
            )}
            <button
              onClick={run}
              disabled={!path || running}
              className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 px-4 py-2 text-xs font-bold text-ink-950 shadow-lg shadow-teal-900/30 transition-opacity hover:opacity-90 disabled:opacity-40"
            >
              <Play size={13} />
              {running ? "Scanning…" : "Run scan"}
            </button>
          </div>
        </div>
        {running && progress && (
          <div className="mt-4">
            <ProgressBar
              indeterminate={!progress.total}
              value={progress.done ?? 0}
              max={progress.total ?? 0}
              label={progress.phase === "walking" ? "Walking directory tree…" : "Scanning files for secrets & vulnerable patterns"}
            />
          </div>
        )}
        {error && (
          <div className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}
      </div>

      {/* summary */}
      {result && (
        <div className="mt-5 grid grid-cols-2 gap-3 lg:grid-cols-5">
          <StatCard label="Files" value={result.summary.filesScanned.toLocaleString()} />
          <StatCard label="Secrets" value={result.summary.secretsFound} tone="accent" />
          <StatCard label="Vuln patterns" value={result.summary.vulnerabilitiesFound} tone="warning" />
          <StatCard
            label="Critical / High"
            value={`${result.summary.critical} / ${result.summary.high}`}
            tone="danger"
          />
          <StatCard label="Duration" value={fmtDuration(result.summary.durationMs)} />
        </div>
      )}

      {/* results */}
      {result && (
        <div className="mt-6">
          <div className="flex flex-wrap items-center gap-2">
            {(
              [
                ["all", `All (${result.findings.length})`],
                ["secret", `Secrets (${result.summary.secretsFound})`],
                ["vulnerability", `Vulnerabilities (${result.summary.vulnerabilitiesFound})`],
              ] as const
            ).map(([k, label]) => (
              <button
                key={k}
                onClick={() => setTab(k)}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                  tab === k
                    ? "border-teal-500/50 bg-teal-500/10 text-teal-300"
                    : "border-ink-600 bg-ink-850 text-slate-400 hover:text-slate-200"
                }`}
              >
                {label}
              </button>
            ))}

            <div className="ml-auto flex items-center gap-2">
              <select
                value={sevFilter}
                onChange={(e) => setSevFilter(e.target.value)}
                className="rounded-lg border border-ink-600 bg-ink-850 px-2 py-1.5 text-xs text-slate-300 outline-none focus:border-teal-500/60"
              >
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s === "all" ? "All severities" : s}
                  </option>
                ))}
              </select>
              <select
                value={langFilter}
                onChange={(e) => setLangFilter(e.target.value)}
                className="rounded-lg border border-ink-600 bg-ink-850 px-2 py-1.5 text-xs text-slate-300 outline-none focus:border-teal-500/60"
              >
                {languages.map((l) => (
                  <option key={l} value={l}>
                    {l === "all" ? "All languages" : l}
                  </option>
                ))}
              </select>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search findings…"
                className="w-44 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
              />
              <button
                onClick={() => setExportOpen(true)}
                title="Export JSON report"
                className="rounded-lg border border-ink-600 bg-ink-850 p-1.5 text-slate-400 hover:text-slate-200"
              >
                <Download size={14} />
              </button>
            </div>
          </div>

          <div className="mt-3 space-y-2">
            {grouped.length === 0 && (
              <EmptyState
                title="No findings match the current filters"
                description="Try widening the severity or category filters, or clear the search box."
              />
            )}
            {grouped.map(([key, fs]) => {
              const f = fs[0];
              const idx = result.findings.indexOf(f);
              return <FindingCard key={key} finding={f} fileIndex={idx >= 0 ? idx + 1 : undefined} />;
            })}
          </div>
        </div>
      )}

      {!result && !running && (
        <div className="mt-6">
          <EmptyState
            icon={<ScanLine size={36} />}
            title="Nothing scanned yet"
            description="Choose a project folder above and hit Run scan. VulnCompanion will scan text files for 30+ secret patterns (API keys, tokens, private keys…) and 50+ dangerous code patterns (eval, exec, SQL injection, unsafe deserialization…) across 10+ languages."
          />
        </div>
      )}

      {exportOpen && result && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-6" onClick={() => setExportOpen(false)}>
          <div className="w-full max-w-lg rounded-xl border border-ink-600 bg-ink-850 p-5" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-100">Export scan report</h3>
              <button onClick={() => setExportOpen(false)} className="text-slate-500 hover:text-slate-300">
                <X size={16} />
              </button>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Copies the full report ({result.summary.totalFindings} findings, {fmtBytes(result.summary.bytesScanned)} scanned) as JSON to the clipboard.
            </p>
            <button
              onClick={exportJson}
              className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 px-4 py-2 text-xs font-bold text-ink-950 hover:opacity-90"
            >
              <Clipboard size={14} /> Copy JSON to clipboard
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-300">
      <button
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative h-4 w-7 rounded-full transition-colors ${checked ? "bg-teal-500" : "bg-ink-600"}`}
      >
        <span
          className={`absolute top-0.5 h-3 w-3 rounded-full bg-white transition-all ${checked ? "left-3.5" : "left-0.5"}`}
        />
      </button>
      {label}
    </label>
  );
}
