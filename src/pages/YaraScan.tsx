import { CircleX, ScanSearch } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type JSX } from "react";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, Select } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultPagination } from "../components/workbench/ResultPagination";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { ServerPageState } from "../components/workbench/ServerPageState";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { TargetBar } from "../components/workbench/TargetBar";
import { TargetInput } from "../components/workbench/TargetInput";
import { ToolPage } from "../components/workbench/ToolPage";
import { acquireScan, cancelActiveScan, detachScan, refreshScanWork, releaseScan, scanOperationId, useScanWorkStore } from "../features/project-home/coordinator";
import { EvidenceSummary, yaraEvidence } from "../features/runs/EvidenceSummary";
import { RunTimeline } from "../features/runs/RunTimeline";
import { readSavedScanReceipt } from "../features/runs/savedScanReceipt";
import { useToolProgress } from "../features/runs/useToolProgress";
import { PackSelector, packIdsFor, useSignaturePacks } from "../features/signature-packs/PackSelector";
import { api } from "../lib/api";
import { errorMessage, normalizeCommandError } from "../lib/commandError";
import { offsetLabel, printableAscii, spacedHex } from "../lib/matchFormat";
import { usePagination } from "../lib/pagination";
import { useCanonicalPage } from "../lib/serverPagination";
import { useAppStore, useToastStore } from "../lib/stores";
import type { CanonicalRun, Severity, YaraMatchRow, YaraScanResult, YaraSkippedFile } from "../lib/types";

const SEVERITIES: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low", "info"];
const DEFAULT_MAX_FILE_MB = "64";
/** usePagination restarts whenever its input identity changes, so absent lists must be one stable value. */
const NONE: never[] = [];

function parseMaxFileMb(raw: string): { value: number | null; error?: string } {
  const text = raw.trim();
  if (!text) return { value: null };
  const value = /^\d+$/.test(text) ? Number(text) : Number.NaN;
  return Number.isSafeInteger(value) && value >= 1 && value <= 1024 ? { value } : { value: null, error: "Enter a whole number of MiB between 1 and 1,024." };
}

export function YaraScanPage(): JSX.Element {
  const push = useToastStore(state => state.push);
  const openExport = useAppStore(state => state.openExport);
  const setPage = useAppStore(state => state.setPage);
  const setPageStatus = useAppStore(state => state.setPageStatus);
  const clearPageStatus = useAppStore(state => state.clearPageStatus);
  const activeWork = useScanWorkStore(state => state.active);
  const recoveryRevision = useScanWorkStore(state => state.recoveryRevision);
  const { packs, error: packsError } = useSignaturePacks("yara");
  const { progress, reset: resetProgress, error: progressError } = useToolProgress("yara", "yara://progress");

  const [target, setTarget] = useState(() => useScanWorkStore.getState().lastTargets.yara ?? "");
  const [excluded, setExcluded] = useState<string[]>([]);
  const [maxFileMb, setMaxFileMb] = useState(DEFAULT_MAX_FILE_MB);
  const [localBusy, setBusy] = useState(false);
  const busy = localBusy || activeWork?.owner === "yara";
  const [result, setResult] = useState<YaraScanResult | null>(null);
  const [receipt, setReceipt] = useState<CanonicalRun | null>(null);
  const [attempt, setAttempt] = useState<CanonicalRun | null>(null);
  const [matchTotal, setMatchTotal] = useState(0);
  const [skippedTotal, setSkippedTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const mounted = useRef(true);
  const inFlight = useRef<number | null>(null);
  const receiptRequest = useRef(0);
  const targetEdited = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      receiptRequest.current += 1;
      if (inFlight.current !== null) detachScan(inFlight.current);
      clearPageStatus("yara-scan");
    };
  }, [clearPageStatus]);

  useEffect(() => {
    const generation = ++receiptRequest.current;
    if (activeWork?.owner === "yara" && !target.trim()) { setTarget(activeWork.path); return; }
    if (busy || (!target.trim() && targetEdited.current)) return;
    const recent = useScanWorkStore.getState().backend.recent.find(work => work.kind === "yara" && work.target === target.trim());
    void readSavedScanReceipt<YaraScanResult>("yara", target.trim(), recent?.runId).then(saved => {
      if (!mounted.current || generation !== receiptRequest.current) return;
      setAttempt(saved.attempt);
      if (saved.loadError && !saved.data) setError(`Saved YARA results could not be loaded: ${saved.loadError}`);
      if (saved.data) {
        setError(null);
        setResult(saved.data);
        setReceipt(saved.receipt);
        setMatchTotal(saved.sections.matches ?? 0);
        setSkippedTotal(saved.sections.skipped ?? 0);
        setSelectedId(null);
        if (!target.trim()) setTarget(saved.target);
        setPageStatus("yara-scan", { label: `Saved YARA results · ${saved.data.state} · ${(saved.sections.matches ?? 0).toLocaleString()} matches`, tone: saved.data.state === "completed" ? "success" : "neutral" });
      }
    }).catch(cause => {
      if (mounted.current && generation === receiptRequest.current) setError(`Saved YARA results could not be loaded: ${errorMessage(cause)}`);
    });
    return () => { receiptRequest.current += 1; };
  }, [activeWork?.owner, activeWork?.path, busy, recoveryRevision, setPageStatus, target]);

  const fileSize = parseMaxFileMb(maxFileMb);
  const packIds = packs ? packIdsFor(packs, excluded) : undefined;
  const noPacks = packs !== null && packs.length === 0;
  const nothingSelected = packs !== null && packs.length > 0 && packIds !== undefined && packIds.length === 0;
  const canRun = Boolean(target.trim()) && !noPacks && !nothingSelected && !fileSize.error && packs !== null && !busy && !activeWork;

  const run = async () => {
    if (!canRun || inFlight.current !== null) return;
    const ownership = acquireScan("yara", target.trim(), "YARA scan");
    if (ownership === null) return;
    inFlight.current = ownership;
    receiptRequest.current += 1;
    setBusy(true);
    setError(null);
    resetProgress();
    setPageStatus("yara-scan", { label: "YARA scan running", detail: target.trim(), tone: "running" });
    try {
      const next = await api.scanYara({
        path: target.trim(),
        ...(packIds ? { packIds } : {}),
        ...(fileSize.value !== null ? { maxFileSizeMb: fileSize.value } : {}),
        operationId: scanOperationId(ownership),
      });
      const active = useScanWorkStore.getState().active;
      if (!mounted.current || active?.id !== ownership) return;
      if (active.cancelling || active.terminalStatus === "cancelled") {
        setError("YARA scan cancelled; previous saved results remain available.");
        setPageStatus("yara-scan", { label: "YARA scan cancelled", tone: "neutral" });
        return;
      }
      setResult(next);
      setReceipt(null);
      setAttempt(null);
      setMatchTotal(next.matches.length);
      setSkippedTotal(next.skipped.length);
      setSelectedId(null);
      const complete = next.state === "completed" && active.terminalStatus !== "failed" && active.terminalStatus !== "incomplete";
      setPageStatus("yara-scan", { label: `YARA scan ${complete ? "completed" : "incomplete"} · ${next.matches.length.toLocaleString()} matches`, tone: complete ? "success" : "neutral" });
      push(complete ? "success" : "info", `YARA scan ${complete ? "completed" : "incomplete"}: ${next.matches.length.toLocaleString()} matches`);
    } catch (cause) {
      if (mounted.current && useScanWorkStore.getState().active?.id === ownership) {
        const message = normalizeCommandError(cause).message;
        const cancelled = message.toLowerCase().includes("cancelled") || Boolean(useScanWorkStore.getState().active?.cancelling);
        setError(message);
        setPageStatus("yara-scan", { label: cancelled ? "YARA scan cancelled" : "YARA scan failed", tone: "neutral" });
      }
    } finally {
      inFlight.current = null;
      releaseScan(ownership);
      if (mounted.current) setBusy(false);
      void refreshScanWork(true);
    }
  };

  const query = useMemo(() => ({ ...(search.trim() ? { search: search.trim() } : {}), ...(severity !== "all" ? { severity } : {}) }), [search, severity]);
  const liveMatches = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (result?.matches ?? []).filter(row => (severity === "all" || row.severity === severity)
      && (!needle || [row.rule, row.pack, row.path, row.namespace, row.tags.join(" ")].join(" ").toLowerCase().includes(needle)));
  }, [result, search, severity]);
  const localMatches = usePagination(liveMatches);
  const savedMatches = useCanonicalPage<YaraMatchRow>(receipt?.id ?? null, "matches", query, matchTotal);
  const matches = receipt ? savedMatches : localMatches;
  const liveSkipped = usePagination<YaraSkippedFile>(result?.skipped ?? NONE);
  const savedSkipped = useCanonicalPage<YaraSkippedFile>(receipt?.id ?? null, "skipped", {}, skippedTotal);
  const skipped = receipt ? savedSkipped : liveSkipped;
  const ruleSkips = usePagination(result?.rulesSkipped ?? NONE, 25);
  const selected = matches.items.find(row => row.id === selectedId) ?? null;

  const incomplete = result !== null && result.state !== "completed";
  const missingPacks = noPacks;
  const running = busy;
  const progressLabel = progress && activeWork && progress.operationId === activeWork.operationId ? progress : null;

  return (
    <ToolPage title="YARA Scan" description="Apply imported YARA rules to every file under a path. Rules come from Rule Library; nothing runs without them.">
      <div className="space-y-4">
        <TargetBar primary={<>
          <Button variant="primary" disabled={!canRun} onClick={() => void run()}>
            <ScanSearch size={13} aria-hidden="true" />Run YARA scan
          </Button>
          {running && <Button variant="danger" disabled={activeWork?.cancelling} onClick={() => void cancelActiveScan()}>
            <CircleX size={13} aria-hidden="true" />{activeWork?.cancelling ? "Cancelling…" : "Cancel"}
          </Button>}
        </>} secondary={<div className="flex min-w-0 flex-wrap items-start gap-x-6 gap-y-3">
          {packs && packs.length > 0 && <PackSelector packs={packs} excluded={excluded} onChange={setExcluded} disabled={running} unit="rules" />}
          <div>
            <label htmlFor="yara-max-file" className="mb-1.5 block text-[11px] font-semibold uppercase tracking-[0.12em] text-text-muted">Max file size (MiB)</label>
            <input id="yara-max-file" inputMode="numeric" value={maxFileMb} disabled={running} aria-invalid={fileSize.error ? true : undefined}
              onChange={event => setMaxFileMb(event.target.value)}
              className="w-28 rounded-sm border border-border bg-surface-secondary px-3 py-2 text-xs text-text-primary disabled:cursor-not-allowed disabled:opacity-50" />
            <p className="mt-1.5 max-w-xs text-[11px] text-text-muted">Larger files are listed as not scanned. Default 64.</p>
            {fileSize.error && <p role="alert" className="mt-1 text-[12px] text-error">{fileSize.error}</p>}
          </div>
        </div>}>
          <TargetInput
            label="Scan target" inputLabel="YARA target" value={target} disabled={running || Boolean(activeWork)}
            pickers={["file", "folder"]} pickerLabels={{ file: "Choose file…", folder: "Choose folder…" }}
            placeholder="Path to a file or folder"
            hint="Every file under the path is read, including ignored folders; symlinks are not followed."
            onChange={value => { targetEdited.current = true; receiptRequest.current += 1; setTarget(value); setResult(null); setReceipt(null); setAttempt(null); setSelectedId(null); setError(null); resetProgress(); }}
          />
        </TargetBar>

        {missingPacks && <InlineState tone="empty" title="No YARA rules are enabled"
          description="YARA Scan runs rules you import. Import a rule file, folder or .zip in Rule Library and keep its pack enabled, then return here."
          action={<Button variant="outline" onClick={() => setPage("rule-library")}>Open Rule Library</Button>} />}
        {packsError && <InlineState tone="error" title="Installed packs could not be listed" description={packsError} />}

        <RunTimeline kind="yara" running={running} hasCompletedResult={Boolean(result)} title="Scanning files with YARA rules"
          progress={progressLabel ? { operationId: progressLabel.operationId, label: progressLabel.message } : null}
          detail={progressLabel?.bytesScanned !== undefined ? `${progressLabel.bytesScanned.toLocaleString()} bytes read` : undefined}
          unavailable={progressError !== null} />

        {error && <InlineState tone={error.toLowerCase().includes("cancelled") ? "unavailable" : "error"}
          title={error.toLowerCase().includes("cancelled") ? "YARA scan cancelled" : "YARA scan unavailable"} description={error} />}
        {attempt && !result && attempt.state !== "completed" && (
          <p role="status" className="text-[12px] text-warning">Latest saved attempt: {attempt.state}. Saved results could not be loaded.</p>
        )}
        {incomplete && <InlineState tone="unavailable" title="This run is incomplete"
          description={`Files that were not scanned were not evaluated, so the matches below may be partial.${result.notes.length ? ` ${result.notes.join(" ")}` : ""}`} />}

        {result && <EvidenceSummary label="YARA" evidence={yaraEvidence(result, receipt, { matches: matchTotal, skipped: skippedTotal })} running={running} cancelling={activeWork?.cancelling} attempt={attempt}
          operation={error ? error.toLowerCase().includes("cancelled") ? "Latest operation cancelled" : "Latest operation failed or results unavailable" : null}
          action={<Button size="sm" variant="outline" onClick={() => openExport(result.runId)}>Open Export Center</Button>}>
          <p>Target: <span className="break-all font-mono">{result.target}</span></p>
          {result.packs.map(pack => <p key={pack.id}>Pack {pack.name} · {pack.license} · {pack.ruleCount.toLocaleString()} rules · <span className="break-all font-mono">{pack.contentSha256}</span></p>)}
        </EvidenceSummary>}

        {result && matchTotal === 0 && !running && (
          <InlineState tone="empty" title="No rule matched in the files that were scanned."
            description={`${result.filesScanned.toLocaleString()} files were scanned with ${result.rulesCompiled.toLocaleString()} compiled rules.${skippedTotal ? ` ${skippedTotal.toLocaleString()} files were not scanned.` : ""}`} />
        )}

        {result && matchTotal > 0 && (
          <section aria-label="YARA results" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
            <ResultsToolbar
              countLabel={receipt && savedMatches.loading ? `Loading this view · ${matchTotal.toLocaleString()} matches` : receipt && savedMatches.error ? `This view is unavailable · ${matchTotal.toLocaleString()} matches` : `${matches.total.toLocaleString()} shown · ${matchTotal.toLocaleString()} ${matchTotal === 1 ? "match" : "matches"}`}
              filters={<Select aria-label="Match severity" variant="compact" value={severity} onChange={event => { setSeverity(event.target.value as Severity | "all"); setSelectedId(null); }}>
                {SEVERITIES.map(item => <option key={item} value={item}>{item === "all" ? "All severities" : item}</option>)}
              </Select>}
              search={<label className="relative min-w-0"><span className="sr-only">Search matches</span>
                <input value={search} onChange={event => { setSearch(event.target.value); setSelectedId(null); }} placeholder="Search rule, pack, path…"
                  className="w-52 rounded-sm border border-border bg-surface-primary px-2 py-1.5 text-[12px] text-text-primary placeholder:text-text-muted" /></label>}
            />
            {receipt && <ServerPageState page={savedMatches} />}
            <SplitWorkspace panelId="yara-matches" listLabel="Rule matches"
              list={<>
                <ul aria-label="YARA matches">
                  {matches.items.map(row => {
                    const active = selected?.id === row.id;
                    return <li key={row.id}>
                      <button type="button" data-detail-trigger aria-current={active ? "true" : undefined} onClick={() => setSelectedId(row.id)}
                        className={`block w-full border-b border-border px-3 py-2.5 text-left transition-colors ${active ? "bg-accent-subtle" : "hover:bg-surface-hover"}`}>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <SeverityBadge severity={row.severity} />
                          <span className="font-mono text-[12px] text-text-primary">{row.rule}</span>
                          <span className="text-[11px] text-text-muted">{row.pack}</span>
                        </div>
                        <p className="mt-1 truncate font-mono text-[12px] text-text-secondary">{row.path}</p>
                        {row.tags.length > 0 && <p className="mt-0.5 truncate text-[11px] text-text-muted">{row.tags.join(", ")}</p>}
                      </button>
                    </li>;
                  })}
                </ul>
                <ResultPagination pagination={matches} label="YARA matches" onPageChange={matches.setPage} />
              </>}
              detailLabel="Match detail" hasSelection={selected !== null} onBackToList={() => setSelectedId(null)}
              detail={selected ? <MatchDetail row={selected} /> : <InlineState tone="idle" title="Select a match" description="Choose a match to see its metadata and the strings that matched." />}
            />
            {result.matchesDropped > 0 && <p className="border-t border-border px-4 py-2 text-[11px] text-text-muted">{result.matchesDropped.toLocaleString()} further matches were counted but not stored.</p>}
          </section>
        )}

        {result && skippedTotal > 0 && (
          <section aria-label="Not scanned" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
            <div className="border-b border-border px-4 py-3">
              <h2 className="text-[13px] font-semibold text-text-primary">Not scanned ({skippedTotal.toLocaleString()})</h2>
              <p className="mt-1 text-[12px] text-text-muted">These files were not evaluated. Nothing is known about them from this run.{result.skippedDropped > 0 ? ` ${result.skippedDropped.toLocaleString()} more were not listed.` : ""}</p>
            </div>
            {receipt && <ServerPageState page={savedSkipped} />}
            <ul aria-label="Files that were not scanned" className="divide-y divide-border">
              {skipped.items.map(file => <li key={`${file.path}:${file.reason}`} className="px-4 py-2 text-[12px]">
                <span className="break-all font-mono text-text-primary">{file.path}</span><span className="mt-0.5 block text-text-muted">{file.reason}</span>
              </li>)}
            </ul>
            <ResultPagination pagination={skipped} label="files not scanned" onPageChange={skipped.setPage} />
          </section>
        )}

        {result && result.rulesSkipped.length > 0 && (
          <section aria-label="Rule files that were not applied" className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
            <div className="border-b border-border px-4 py-3">
              <h2 className="text-[13px] font-semibold text-text-primary">Rule files that were not applied ({result.rulesSkippedTotal.toLocaleString()})</h2>
              <p className="mt-1 text-[12px] text-text-muted">These rule files did not compile. What they would have matched is unknown.</p>
            </div>
            <ul aria-label="Rule files not applied" className="divide-y divide-border">
              {ruleSkips.items.map((skip, index) => <li key={`${ruleSkips.start + index}`} className="px-4 py-2 text-[12px]">
                <span className="break-all font-mono text-text-primary">{skip.pack}/{skip.file}{skip.line ? `:${skip.line}` : ""}</span><span className="mt-0.5 block text-text-muted">{skip.message}</span>
              </li>)}
            </ul>
            {ruleSkips.pageCount > 1 && <ResultPagination pagination={ruleSkips} label="rule files not applied" onPageChange={ruleSkips.setPage} />}
          </section>
        )}

        {result && result.notes.length > 0 && (
          <section aria-label="Run notes" className="rounded-sm border border-border bg-surface-secondary px-4 py-3">
            <h2 className="text-[13px] font-semibold text-text-primary">Run notes</h2>
            <ul className="mt-1 list-disc space-y-1 pl-4 text-[12px] text-text-secondary">{result.notes.map(note => <li key={note}>{note}</li>)}</ul>
          </section>
        )}
      </div>
    </ToolPage>
  );
}

function MatchDetail({ row }: { row: YaraMatchRow }): JSX.Element {
  const strings = usePagination(row.strings, 25);
  return <div className="space-y-4 p-4 text-[13px] text-text-secondary">
    <div className="flex flex-wrap items-center gap-2">
      <SeverityBadge severity={row.severity} />
      <span className="font-mono text-[14px] font-semibold text-text-primary">{row.rule}</span>
    </div>
    <dl className="grid gap-2 text-[12px]">
      <div><dt className="font-semibold text-text-muted">File</dt><dd className="break-all font-mono">{row.path}</dd></div>
      <div><dt className="font-semibold text-text-muted">File SHA-256</dt><dd className="break-all font-mono">{row.sha256}</dd></div>
      <div><dt className="font-semibold text-text-muted">Pack</dt><dd>{row.pack} · <span className="break-all font-mono">{row.namespace}</span></dd></div>
      {row.tags.length > 0 && <div><dt className="font-semibold text-text-muted">Tags</dt><dd>{row.tags.join(", ")}</dd></div>}
    </dl>
    {row.meta.length > 0 && <div>
      <h3 className="text-[12px] font-semibold uppercase tracking-wide text-text-muted">Rule metadata</h3>
      <table aria-label="Rule metadata" className="mt-1 w-full text-left text-[12px]"><tbody className="divide-y divide-border">
        {row.meta.map(([key, value], index) => <tr key={`${key}:${index}`}><th scope="row" className="w-1/3 py-1 pr-3 align-top font-medium text-text-muted">{key}</th><td className="break-words py-1 text-text-secondary">{String(value)}</td></tr>)}
      </tbody></table>
    </div>}
    <div>
      <h3 className="text-[12px] font-semibold uppercase tracking-wide text-text-muted">Strings that matched</h3>
      {row.strings.length === 0 ? <p className="mt-1 text-[12px] text-text-muted">This rule matched without reporting string offsets.</p> : <>
        <div className="mt-1 overflow-x-auto"><table aria-label="Matched strings" className="w-full min-w-[34rem] text-left text-[12px]">
          <thead className="text-text-muted"><tr><th className="py-1 pr-3">String</th><th className="py-1 pr-3">Offset</th><th className="py-1 pr-3">Length</th><th className="py-1">Excerpt</th></tr></thead>
          <tbody className="divide-y divide-border">
            {strings.items.map((match, index) => <tr key={`${match.identifier}:${match.offset}:${index}`} className="align-top">
              <td className="py-1.5 pr-3 font-mono text-text-primary">{match.identifier}</td>
              <td className="py-1.5 pr-3 font-mono">{offsetLabel(match.offset)}</td>
              <td className="py-1.5 pr-3 font-mono">{match.length.toLocaleString()} bytes</td>
              <td className="py-1.5"><code className="block break-all rounded-sm border border-border bg-surface-code px-2 py-1 font-mono text-[11px] text-text-primary">{spacedHex(match.excerptHex)}</code>
                <code className="mt-1 block break-all font-mono text-[11px] text-text-muted" aria-label="Printable rendering">{printableAscii(match.excerptHex)}</code>
                {match.excerptMasked && <span className="mt-0.5 block text-[11px] text-text-muted">Masked: this rule reports secrets, so only the first bytes (if any) and the length are kept.</span>}
                {!match.excerptMasked && match.length > spacedHex(match.excerptHex).split(" ").filter(Boolean).length && <span className="mt-0.5 block text-[11px] text-text-muted">Excerpt shows the first {spacedHex(match.excerptHex).split(" ").filter(Boolean).length} of {match.length.toLocaleString()} bytes.</span>}
              </td>
            </tr>)}
          </tbody>
        </table></div>
        {strings.pageCount > 1 && <ResultPagination pagination={strings} label="matched strings" onPageChange={strings.setPage} />}
      </>}
      {row.stringsTruncated > 0 && <p className="mt-1 text-[12px] text-text-muted">{row.stringsTruncated.toLocaleString()} more string matches were counted but not stored.</p>}
    </div>
  </div>;
}
