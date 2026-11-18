import { CircleX, Crosshair } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type JSX, type ReactNode } from "react";
import { MarkdownLink } from "../components/MarkdownLink";
import { SeverityBadge } from "../components/SeverityBadge";
import { Button, Checkbox, Input, SearchField, Switch, Textarea } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultPagination } from "../components/workbench/ResultPagination";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { ServerPageState } from "../components/workbench/ServerPageState";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { TargetBar } from "../components/workbench/TargetBar";
import { TargetInput } from "../components/workbench/TargetInput";
import { ToolPage } from "../components/workbench/ToolPage";
import { acquireScan, cancelActiveScan, detachScan, refreshScanWork, releaseScan, scanOperationId, useScanWorkStore } from "../features/project-home/coordinator";
import { EvidenceSummary, templateEvidence } from "../features/runs/EvidenceSummary";
import { RunTimeline } from "../features/runs/RunTimeline";
import { readSavedScanReceipt } from "../features/runs/savedScanReceipt";
import { useToolProgress } from "../features/runs/useToolProgress";
import { PackSelector, packIdsFor, useSignaturePacks } from "../features/signature-packs/PackSelector";
import { api } from "../lib/api";
import { errorMessage, normalizeCommandError } from "../lib/commandError";
import { usePagination } from "../lib/pagination";
import { useCanonicalPage } from "../lib/serverPagination";
import { useAppStore, useToastStore } from "../lib/stores";
import { liveTargetsAllowed } from "../lib/transport";
import type { CanonicalRun, TemplateMatchRow, TemplateNotEvaluatedRow, TemplateScanRequest, TemplateScanResult } from "../lib/types";

type Mode = "path" | "targets";
type Sev = NonNullable<TemplateScanRequest["severities"]>[number];
const SEVERITY_CHOICES: Sev[] = ["critical", "high", "medium", "low", "info"];
export const MAX_LIVE_TARGETS_HINT = "One per line: a URL, host, host:port, IP address, or a CIDR range of up to 256 addresses.";

/** Client-side hygiene only: trim, drop blanks, drop exact repeats. The backend validates targets. */
export function parseTargets(raw: string): string[] {
  return [...new Set(raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean))];
}
function parseList(raw: string): string[] {
  return [...new Set(raw.split(",").map(item => item.trim()).filter(Boolean))];
}

export function TemplateScanPage(): JSX.Element {
  const push = useToastStore(state => state.push);
  const openExport = useAppStore(state => state.openExport);
  const setPage = useAppStore(state => state.setPage);
  const openSettings = useAppStore(state => state.openSettings);
  const setPageStatus = useAppStore(state => state.setPageStatus);
  const clearPageStatus = useAppStore(state => state.clearPageStatus);
  const activeWork = useScanWorkStore(state => state.active);
  const recoveryRevision = useScanWorkStore(state => state.recoveryRevision);
  const { packs, error: packsError } = useSignaturePacks("nuclei");
  const { progress, reset: resetProgress, error: progressError } = useToolProgress("template", "template://progress");

  const [mode, setMode] = useState<Mode>("path");
  const [target, setTarget] = useState(() => useScanWorkStore.getState().lastTargets.template ?? "");
  const [targetsText, setTargetsText] = useState("");
  const [excluded, setExcluded] = useState<string[]>([]);
  const [tagsText, setTagsText] = useState("");
  const [excludeTagsText, setExcludeTagsText] = useState("");
  const [severities, setSeverities] = useState<Sev[]>([]);
  const [intrusive, setIntrusive] = useState(false);
  // Per run, never stored: not in settings, not in browser storage.
  const [authorized, setAuthorized] = useState(false);
  const [statement, setStatement] = useState("");
  const [localBusy, setBusy] = useState(false);
  const busy = localBusy || activeWork?.owner === "template";
  const [result, setResult] = useState<TemplateScanResult | null>(null);
  const [receipt, setReceipt] = useState<CanonicalRun | null>(null);
  const [attempt, setAttempt] = useState<CanonicalRun | null>(null);
  const [matchTotal, setMatchTotal] = useState(0);
  const [notEvaluatedTotal, setNotEvaluatedTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [notEvaluatedSearch, setNotEvaluatedSearch] = useState("");
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
      clearPageStatus("template-scan");
    };
  }, [clearPageStatus]);

  const liveAllowed = liveTargetsAllowed;
  const live = mode === "targets" && liveAllowed;

  // Saved results are for local paths; live targets are never reopened by typing.
  useEffect(() => {
    const generation = ++receiptRequest.current;
    if (activeWork?.owner === "template" && !target.trim() && mode === "path") { setTarget(activeWork.path); return; }
    if (busy || mode !== "path" || (!target.trim() && targetEdited.current)) return;
    const recent = useScanWorkStore.getState().backend.recent.find(work => work.kind === "template" && work.target === target.trim());
    void readSavedScanReceipt<TemplateScanResult>("template", target.trim(), recent?.runId).then(saved => {
      if (!mounted.current || generation !== receiptRequest.current) return;
      setAttempt(saved.attempt);
      if (saved.loadError && !saved.data) setError(`Saved template results could not be loaded: ${saved.loadError}`);
      if (saved.data) {
        setError(null);
        setResult(saved.data);
        setReceipt(saved.receipt);
        setMatchTotal(saved.sections.matches ?? 0);
        setNotEvaluatedTotal(saved.sections.notEvaluated ?? 0);
        setSelectedId(null);
        if (!target.trim()) setTarget(saved.target);
        setPageStatus("template-scan", { label: `Saved template results · ${saved.data.state} · ${(saved.sections.matches ?? 0).toLocaleString()} matches`, tone: saved.data.state === "completed" ? "success" : "neutral" });
      }
    }).catch(cause => {
      if (mounted.current && generation === receiptRequest.current) setError(`Saved template results could not be loaded: ${errorMessage(cause)}`);
    });
    return () => { receiptRequest.current += 1; };
  }, [activeWork?.owner, activeWork?.path, busy, mode, recoveryRevision, setPageStatus, target]);

  const targets = useMemo(() => parseTargets(targetsText), [targetsText]);
  const packIds = packs ? packIdsFor(packs, excluded) : undefined;
  const noPacks = packs !== null && packs.length === 0;
  const nothingSelected = packs !== null && packs.length > 0 && packIds !== undefined && packIds.length === 0;
  const hasInput = live ? targets.length > 0 && authorized : Boolean(target.trim());
  const canRun = hasInput && packs !== null && !noPacks && !nothingSelected && !busy && !activeWork && (mode === "path" || liveAllowed);

  const clearView = () => { setResult(null); setReceipt(null); setAttempt(null); setSelectedId(null); setError(null); resetProgress(); };
  const changeMode = (next: Mode) => {
    if (next === mode || busy) return;
    receiptRequest.current += 1;
    setMode(next);
    setAuthorized(false);
    clearView();
  };

  const run = async () => {
    if (!canRun || inFlight.current !== null) return;
    const label = live ? `${targets.length} live target${targets.length === 1 ? "" : "s"}` : target.trim();
    const ownership = acquireScan("template", label, "Template scan");
    if (ownership === null) return;
    inFlight.current = ownership;
    receiptRequest.current += 1;
    const tags = parseList(tagsText);
    const excludeTags = parseList(excludeTagsText);
    const request: TemplateScanRequest = {
      ...(live ? { targets, authorization: { acknowledged: true, statement: statement.trim() }, includeIntrusive: intrusive } : { path: target.trim() }),
      ...(packIds ? { packIds } : {}),
      ...(tags.length ? { tags } : {}),
      ...(excludeTags.length ? { excludeTags } : {}),
      ...(severities.length ? { severities } : {}),
      operationId: scanOperationId(ownership),
    };
    setBusy(true);
    setError(null);
    resetProgress();
    setPageStatus("template-scan", { label: "Template scan running", detail: label, tone: "running" });
    try {
      const next = await api.scanTemplates(request);
      const active = useScanWorkStore.getState().active;
      if (!mounted.current || active?.id !== ownership) return;
      if (active.cancelling || active.terminalStatus === "cancelled") {
        setError("Template scan cancelled; previous saved results remain available.");
        setPageStatus("template-scan", { label: "Template scan cancelled", tone: "neutral" });
        return;
      }
      setResult(next);
      setReceipt(null);
      setAttempt(null);
      setMatchTotal(next.matches.length);
      setNotEvaluatedTotal(next.notEvaluated.length);
      setSelectedId(null);
      const complete = next.state === "completed" && active.terminalStatus !== "failed" && active.terminalStatus !== "incomplete";
      setPageStatus("template-scan", { label: `Template scan ${complete ? "completed" : "incomplete"} · ${next.matches.length.toLocaleString()} matches`, tone: complete ? "success" : "neutral" });
      push(complete ? "success" : "info", `Template scan ${complete ? "completed" : "incomplete"}: ${next.matches.length.toLocaleString()} matches`);
    } catch (cause) {
      if (mounted.current && useScanWorkStore.getState().active?.id === ownership) {
        const message = normalizeCommandError(cause).message;
        const cancelled = message.toLowerCase().includes("cancelled") || Boolean(useScanWorkStore.getState().active?.cancelling);
        setError(message);
        setPageStatus("template-scan", { label: cancelled ? "Template scan cancelled" : "Template scan failed", tone: "neutral" });
      }
    } finally {
      inFlight.current = null;
      releaseScan(ownership);
      // The acknowledgement covers one run.
      if (mounted.current) { setAuthorized(false); setBusy(false); }
      void refreshScanWork(true);
    }
  };

  const matchQuery = useMemo(() => (search.trim() ? { search: search.trim() } : {}), [search]);
  const liveMatches = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (result?.matches ?? []).filter(row => !needle || [row.name, row.templateId, row.pack, row.matchedAt, row.protocol, row.matcherNames.join(" ")].join(" ").toLowerCase().includes(needle));
  }, [result, search]);
  const localMatches = usePagination(liveMatches);
  const savedMatches = useCanonicalPage<TemplateMatchRow>(receipt?.id ?? null, "matches", matchQuery, matchTotal);
  const matches = receipt ? savedMatches : localMatches;
  const neQuery = useMemo(() => (notEvaluatedSearch.trim() ? { search: notEvaluatedSearch.trim() } : {}), [notEvaluatedSearch]);
  const liveNotEvaluated = useMemo(() => {
    const needle = notEvaluatedSearch.trim().toLowerCase();
    return (result?.notEvaluated ?? []).filter(row => !needle || [row.reason, row.templateId, row.pack, row.file, row.protocol ?? "", row.target ?? ""].join(" ").toLowerCase().includes(needle));
  }, [result, notEvaluatedSearch]);
  const localNotEvaluated = usePagination(liveNotEvaluated);
  const savedNotEvaluated = useCanonicalPage<TemplateNotEvaluatedRow>(receipt?.id ?? null, "notEvaluated", neQuery, notEvaluatedTotal);
  const notEvaluated = receipt ? savedNotEvaluated : localNotEvaluated;
  const reasonCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of receipt ? savedNotEvaluated.items : result?.notEvaluated ?? []) counts.set(row.reason, (counts.get(row.reason) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [receipt, savedNotEvaluated.items, result]);
  const selected = matches.items.find(row => row.id === selectedId) ?? null;
  const incomplete = result !== null && result.state !== "completed";
  const progressNow = progress && activeWork && progress.operationId === activeWork.operationId ? progress : null;
  const progressDetail = progressNow
    ? [progressNow.requestsSent !== undefined ? `${progressNow.requestsSent.toLocaleString()} requests sent` : null,
      progressNow.matches !== undefined ? `${progressNow.matches.toLocaleString()} matches` : null,
      progressNow.bytesScanned !== undefined ? `${progressNow.bytesScanned.toLocaleString()} bytes read` : null].filter(Boolean).join(" · ") || undefined
    : undefined;

  const filters = <div className="space-y-3">
    {packs && packs.length > 0 && <PackSelector packs={packs} excluded={excluded} onChange={setExcluded} disabled={busy} unit="templates" />}
    <div className="grid gap-3 sm:grid-cols-2">
      <div>
        <label htmlFor="template-tags" className="mb-1.5 block text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted">Only tags</label>
        <Input id="template-tags" value={tagsText} disabled={busy} onChange={event => setTagsText(event.target.value)} placeholder="cve, exposure" />
        <p className="mt-1 text-[11px] text-text-muted">Comma separated. Empty means every tag.</p>
      </div>
      <div>
        <label htmlFor="template-exclude-tags" className="mb-1.5 block text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted">Exclude tags</label>
        <Input id="template-exclude-tags" value={excludeTagsText} disabled={busy} onChange={event => setExcludeTagsText(event.target.value)} placeholder="tech, misc" />
        <p className="mt-1 text-[11px] text-text-muted">Comma separated.</p>
      </div>
    </div>
    <fieldset disabled={busy}>
      <legend className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted">Severities (none selected means all)</legend>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5">
        {SEVERITY_CHOICES.map(item => <Checkbox key={item} labelClassName="capitalize" checked={severities.includes(item)}
          onChange={event => setSeverities(event.target.checked ? [...severities, item] : severities.filter(value => value !== item))}>{item}</Checkbox>)}
      </div>
    </fieldset>
    {mode === "targets" && <div>
      <Switch checked={intrusive} onChange={setIntrusive} disabled={busy} label="Include intrusive templates" />
      <p className="mt-1 text-[11px] text-text-muted">Off by default. Templates tagged intrusive or fuzz may change or stress the target. Templates tagged dos never run.</p>
    </div>}
  </div>;

  const primary = <>
    <Button variant="primary" disabled={!canRun} onClick={() => void run()}>
      <Crosshair size={13} aria-hidden="true" />{live ? "Run live scan" : "Run template scan"}
    </Button>
    {busy && <Button variant="danger" disabled={activeWork?.cancelling} onClick={() => void cancelActiveScan()}>
      <CircleX size={13} aria-hidden="true" />{activeWork?.cancelling ? "Cancelling…" : "Cancel"}
    </Button>}
  </>;

  return (
    <ToolPage title="Template Scan" description="Run Nuclei templates you have imported against a local path, or against live targets you are authorized to test.">
      <div className="space-y-4">
        <fieldset disabled={busy} className="min-w-0">
          <legend className="sr-only">Scan mode</legend>
          <div role="radiogroup" aria-label="Scan mode" className="inline-flex h-9 items-center gap-0.5 rounded-md border border-control-border bg-surface-primary p-[3px] text-[12px] transition-colors hover:border-text-muted">
            {([["path", "Local path"], ["targets", "Live targets"]] as Array<[Mode, string]>).map(([value, label]) => (
              <label key={value} className={`inline-flex h-7 cursor-pointer items-center rounded-sm px-3 font-medium has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent ${mode === value ? "bg-accent-subtle text-accent" : "text-text-secondary hover:bg-surface-hover hover:text-text-primary"}`}>
                <input type="radio" name="template-mode" value={value} checked={mode === value} onChange={() => changeMode(value)} className="sr-only" />{label}
              </label>
            ))}
          </div>
        </fieldset>

        {mode === "targets" && !liveAllowed && <InlineState tone="unavailable" title="Live targets are turned off on this server"
          description="This headless server was started without live-target scanning. Start it with --allow-live-targets (or OXAUDIT_SERVER_ALLOW_LIVE_TARGETS=1) to scan live targets. No request is sent from here. Local path scans work without it." />}

        {live && <p role="note" className="surface-card px-4 py-3 text-[12px] leading-relaxed text-text-secondary">
          Live scans send network requests to the listed targets only. Redirects and lookups outside them are refused. Rate, concurrency, timeout and proxy limits come from{" "}
          <button type="button" className="rounded-sm text-accent underline underline-offset-2 hover:text-accent-hover" onClick={() => openSettings("live-scanning")}>Settings, Live scanning</button>.
        </p>}

        <TargetBar primary={primary} secondary={<>
          {live && <div className="mb-3 space-y-2 rounded-md border border-border bg-surface-primary p-3">
            <h2 className="text-[12px] font-semibold text-text-primary">Authorization (required for each run)</h2>
            <Checkbox labelClassName="text-text-primary" checked={authorized} disabled={busy} onChange={event => setAuthorized(event.target.checked)}>
              I am authorized to test these targets
            </Checkbox>
            <div>
              <label htmlFor="template-authorization-statement" className="mb-1 block text-[11px] font-semibold text-text-muted">Statement (optional)</label>
              <Input id="template-authorization-statement" value={statement} disabled={busy} maxLength={200} onChange={event => setStatement(event.target.value)} placeholder="Engagement reference or who approved this" />
              <p className="mt-1 text-[11px] text-text-muted">Saved with this run's results, with the time. The acknowledgement is not remembered; tick it again for every run.</p>
            </div>
          </div>}
          {filters}
        </>}>
          {mode === "path" || !liveAllowed ? (
            <TargetInput
              label="Scan target" inputLabel="Template target" value={target} disabled={busy || Boolean(activeWork) || mode === "targets"}
              pickers={["file", "folder"]} pickerLabels={{ file: "Choose file…", folder: "Choose folder…" }}
              placeholder="Path to a file or folder"
              hint="Only file-protocol templates run against local files."
              onChange={value => { targetEdited.current = true; receiptRequest.current += 1; setTarget(value); clearView(); }}
            />
          ) : (
            <div className="min-w-0">
              <label htmlFor="template-targets" className="mb-1.5 block text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted">Targets</label>
              <Textarea id="template-targets" rows={5} value={targetsText} disabled={busy} spellCheck={false} className="font-mono text-xs"
                placeholder={"https://staging.example.com\n10.0.0.5:8080\n192.168.1.0/28"}
                onChange={event => { setTargetsText(event.target.value); setAuthorized(false); }} />
              <p className="mt-1.5 text-[11px] leading-relaxed text-text-muted">{targets.length.toLocaleString()} {targets.length === 1 ? "target" : "targets"}. {MAX_LIVE_TARGETS_HINT} Repeated lines are removed.</p>
            </div>
          )}
        </TargetBar>

        {noPacks && <InlineState tone="empty" title="No Nuclei templates are enabled"
          description="Template Scan runs templates you import. Import a template file, folder or .zip in Rule Library and keep its pack enabled, then return here."
          action={<Button variant="outline" onClick={() => setPage("rule-library")}>Open Rule Library</Button>} />}
        {packsError && <InlineState tone="error" title="Installed packs could not be listed" description={packsError} />}

        <RunTimeline kind="template" running={busy} hasCompletedResult={Boolean(result)} title={live ? "Running templates against live targets" : "Scanning files with templates"}
          progress={progressNow ? { operationId: progressNow.operationId, label: progressNow.message } : null} detail={progressDetail} unavailable={progressError !== null} />

        {error && <InlineState tone={error.toLowerCase().includes("cancelled") ? "unavailable" : "error"}
          title={error.toLowerCase().includes("cancelled") ? "Template scan cancelled" : "Template scan unavailable"} description={error} />}
        {attempt && !result && attempt.state !== "completed" && (
          <p role="status" className="text-[12px] text-warning">Latest saved attempt: {attempt.state}. Saved results could not be loaded.</p>
        )}
        {incomplete && <InlineState tone="unavailable" title="This run is incomplete"
          description={`What did not run was not evaluated, so the matches below may be partial.${result.notes.length ? ` ${result.notes.join(" ")}` : ""}`} />}

        {result && <EvidenceSummary label="Template" evidence={templateEvidence(result, receipt, { matches: matchTotal, notEvaluated: notEvaluatedTotal })} running={busy} cancelling={activeWork?.cancelling} attempt={attempt}
          operation={error ? error.toLowerCase().includes("cancelled") ? "Latest operation cancelled" : "Latest operation failed or results unavailable" : null}
          action={<Button size="sm" variant="outline" onClick={() => openExport(result.runId)}>Open Export Center</Button>}>
          <p>Target: <span className="break-all font-mono">{result.target}</span></p>
          {result.packs.map(pack => <p key={pack.id}>Pack {pack.name} · {pack.license} · {pack.templateCount.toLocaleString()} templates · <span className="break-all font-mono">{pack.contentSha256}</span></p>)}
        </EvidenceSummary>}

        {result?.mode === "targets" && <ScopeSummary result={result} />}

        {result && matchTotal === 0 && !busy && (
          <InlineState tone="empty" title="No template matched."
            description={notEvaluatedTotal > 0 ? `${notEvaluatedTotal.toLocaleString()} templates or checks were not evaluated; they did not run.` : undefined} />
        )}

        {result && matchTotal > 0 && (
          <section aria-label="Template results" className="overflow-hidden surface-card">
            <ResultsToolbar
              countLabel={receipt && savedMatches.loading ? `Loading this view · ${matchTotal.toLocaleString()} matches` : receipt && savedMatches.error ? `This view is unavailable · ${matchTotal.toLocaleString()} matches` : `${matches.total.toLocaleString()} shown · ${matchTotal.toLocaleString()} ${matchTotal === 1 ? "match" : "matches"}`}
              search={<SearchField aria-label="Search matches" wrapperClassName="w-60" value={search} onChange={event => { setSearch(event.target.value); setSelectedId(null); }} placeholder="Search template, target, matcher…" />}
            />
            {receipt && <ServerPageState page={savedMatches} />}
            <SplitWorkspace panelId="template-matches" listLabel="Template matches"
              list={<>
                <ul aria-label="Template matches">
                  {matches.items.map(row => {
                    const active = selected?.id === row.id;
                    return <li key={row.id}>
                      <button type="button" data-detail-trigger aria-current={active ? "true" : undefined} onClick={() => setSelectedId(row.id)}
                        className={`block w-full border-b border-border px-3 py-2.5 text-left transition-colors ${active ? "bg-accent-subtle" : "hover:bg-surface-hover"}`}>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <SeverityBadge severity={row.severity} />
                          <span className="text-[12px] font-medium text-text-primary">{row.name}</span>
                          <span className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase text-text-muted">{row.protocol}</span>
                        </div>
                        <p className="mt-1 truncate font-mono text-[11px] text-text-muted">{row.templateId} · {row.pack}</p>
                        <p className="mt-0.5 truncate font-mono text-[12px] text-text-secondary">{row.matchedAt}</p>
                        {row.matcherNames.length > 0 && <p className="mt-0.5 truncate text-[11px] text-text-muted">Matchers: {row.matcherNames.join(", ")}</p>}
                      </button>
                    </li>;
                  })}
                </ul>
                <ResultPagination pagination={matches} label="template matches" onPageChange={matches.setPage} />
              </>}
              detailLabel="Match detail" hasSelection={selected !== null} onBackToList={() => setSelectedId(null)}
              detail={selected ? <MatchDetail row={selected} /> : <InlineState tone="idle" title="Select a match" description="Choose a match to see the template's description, evidence and remediation." />}
            />
            {result.matchesDropped > 0 && <p className="border-t border-border px-4 py-2 text-[11px] text-text-muted">{result.matchesDropped.toLocaleString()} further matches were counted but not stored.</p>}
          </section>
        )}

        {result && notEvaluatedTotal > 0 && (
          <section aria-label="Not evaluated" className="overflow-hidden surface-card">
            <div className="border-b border-border px-4 py-3">
              <h2 className="text-[13px] font-semibold text-text-primary">Not evaluated ({notEvaluatedTotal.toLocaleString()})</h2>
              <p className="mt-1 text-[12px] text-text-muted">These templates or checks did not run, so nothing is known from them. They are listed rather than dropped.{result.notEvaluatedDropped > 0 ? ` ${result.notEvaluatedDropped.toLocaleString()} more were not listed.` : ""}</p>
              {reasonCounts.length > 0 && <ul aria-label={receipt ? "Reasons on this page" : "Reasons"} className="mt-2 flex flex-wrap gap-2">
                {reasonCounts.map(([reason, count]) => <li key={reason} className="rounded-md border border-border bg-surface-primary px-2 py-1 text-[11px] text-text-secondary">{count.toLocaleString()} · {reason}</li>)}
              </ul>}
              <SearchField aria-label="Search not evaluated" wrapperClassName="mt-2 w-72" value={notEvaluatedSearch} onChange={event => setNotEvaluatedSearch(event.target.value)} placeholder="Search reason, template, target…" />
            </div>
            {receipt && <ServerPageState page={savedNotEvaluated} />}
            <ul aria-label="Templates and checks that were not evaluated" className="divide-y divide-border">
              {notEvaluated.items.map((row, index) => <li key={`${notEvaluated.start + index}`} className="px-4 py-2 text-[12px]">
                <p className="text-text-primary">{row.reason}</p>
                <p className="mt-0.5 break-all font-mono text-[11px] text-text-muted">{row.templateId || "(file did not load as a template)"} · {row.pack}/{row.file}{row.protocol ? ` · ${row.protocol}` : ""}{row.target ? ` · ${row.target}` : ""}</p>
              </li>)}
            </ul>
            <ResultPagination pagination={notEvaluated} label="not evaluated checks" onPageChange={notEvaluated.setPage} />
          </section>
        )}

        {result && result.skipped.length > 0 && <PagedSection title={`Files that were not scanned (${result.skipped.length.toLocaleString()})`} note="These files were not evaluated." label="Skipped files" items={result.skipped}
          render={file => <><span className="break-all font-mono text-text-primary">{file.path}</span><span className="mt-0.5 block text-text-muted">{file.reason}</span></>} />}

        {result && result.notes.length > 0 && (
          <section aria-label="Run notes" className="surface-card px-4 py-3">
            <h2 className="text-[13px] font-semibold text-text-primary">Run notes</h2>
            <ul className="mt-1 list-disc space-y-1 pl-4 text-[12px] text-text-secondary">{result.notes.map(note => <li key={note}>{note}</li>)}</ul>
          </section>
        )}
      </div>
    </ToolPage>
  );
}

function PagedSection<T>({ title, note, label, items, render }: { title: string; note?: string; label: string; items: readonly T[]; render(item: T): ReactNode }): JSX.Element {
  const pagination = usePagination(items, 25);
  return <section aria-label={title} className="overflow-hidden surface-card">
    <div className="border-b border-border px-4 py-3">
      <h2 className="text-[13px] font-semibold text-text-primary">{title}</h2>
      {note && <p className="mt-1 text-[12px] text-text-muted">{note}</p>}
    </div>
    <ul aria-label={label} className="divide-y divide-border">
      {pagination.items.map((item, index) => <li key={pagination.start + index} className="px-4 py-2 text-[12px]">{render(item)}</li>)}
    </ul>
    {pagination.pageCount > 1 && <ResultPagination pagination={pagination} label={label} onPageChange={pagination.setPage} />}
  </section>;
}

function ScopeSummary({ result }: { result: TemplateScanResult }): JSX.Element {
  const authorization = result.authorization;
  const when = authorization ? new Date(authorization.acknowledgedAtMs) : null;
  return <section aria-label="Scope" className="surface-card">
    <div className="border-b border-border px-4 py-3"><h2 className="text-[13px] font-semibold text-text-primary">Scope</h2>
      <p className="mt-1 text-[12px] text-text-muted">What this live run was allowed to reach, and what it did.</p></div>
    <dl className="grid gap-3 px-4 py-3 text-[12px] min-[700px]:grid-cols-3">
      <div><dt className="text-[11px] font-semibold text-text-muted">Requests sent</dt><dd className="mt-1 text-text-primary">{result.requestsSent.toLocaleString()}</dd></div>
      <div><dt className="text-[11px] font-semibold text-text-muted">Requests refused (outside the listed targets)</dt><dd className="mt-1 text-text-primary">{result.requestsRefused.toLocaleString()}</dd></div>
      <div><dt className="text-[11px] font-semibold text-text-muted">Recorded authorization</dt>
        <dd className="mt-1 text-text-primary">{authorization ? <>{authorization.acknowledged ? "Acknowledged" : "Not acknowledged"}{when && Number.isFinite(when.getTime()) ? <> at <time dateTime={when.toISOString()}>{when.toISOString()}</time></> : null}
          {authorization.statement ? <span className="mt-0.5 block break-words text-text-secondary">Statement: {authorization.statement}</span> : <span className="mt-0.5 block text-text-muted">No statement given.</span>}</> : "None recorded"}</dd></div>
    </dl>
    {result.refusedHosts.length > 0 && <div className="border-t border-border px-4 py-3"><PagedSection title={`Refused hosts (${result.refusedHosts.length.toLocaleString()})`} note="Nothing was sent to these hosts." label="Refused hosts" items={result.refusedHosts} render={host => <span className="break-all font-mono text-text-primary">{host}</span>} /></div>}
    {result.resolved.length > 0 && <div className="border-t border-border px-4 py-3"><PagedSection title={`Resolved addresses (${result.resolved.length.toLocaleString()})`} note="Each host was resolved once; these addresses were used for the whole run." label="Resolved addresses" items={result.resolved}
      render={entry => <><span className="break-all font-mono text-text-primary">{entry.host}</span><span className="mt-0.5 block break-all font-mono text-text-muted">{entry.addresses.join(", ")}</span></>} /></div>}
    {result.unreachableTargets.length > 0 && <div className="border-t border-border px-4 py-3"><PagedSection title={`Unreachable targets (${result.unreachableTargets.length.toLocaleString()})`} note="These targets were not evaluated." label="Unreachable targets" items={result.unreachableTargets}
      render={entry => <><span className="break-all font-mono text-text-primary">{entry.target}</span><span className="mt-0.5 block text-text-muted">{entry.reason}</span></>} /></div>}
  </section>;
}

function Block({ title, children }: { title: string; children: ReactNode }): JSX.Element {
  return <div><h3 className="text-[12px] font-semibold uppercase tracking-wide text-text-muted">{title}</h3><div className="mt-1">{children}</div></div>;
}

function CodeBlock({ label, text }: { label: string; text: string }): JSX.Element {
  // Text node only: stored exchanges are untrusted network content.
  return <pre aria-label={label} className="selectable max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-surface-code p-2 font-mono text-[11px] text-text-primary">{text}</pre>;
}

function MatchDetail({ row }: { row: TemplateMatchRow }): JSX.Element {
  const exchange = row.exchange;
  const classification = row.classification;
  const hasClassification = classification.cveId.length > 0 || classification.cweId.length > 0 || classification.cvssScore !== null;
  const lines = usePagination(row.lines, 25);
  return <div className="space-y-4 p-4 text-[13px] text-text-secondary">
    <div className="flex flex-wrap items-center gap-2">
      <SeverityBadge severity={row.severity} />
      <span className="text-[14px] font-semibold text-text-primary">{row.name}</span>
      <span className="font-mono text-[12px] text-text-muted">[{row.templateId}]</span>
    </div>
    <dl className="grid gap-2 text-[12px]">
      <div><dt className="font-semibold text-text-muted">Matched at</dt><dd className="break-all font-mono">{row.matchedAt}</dd></div>
      <div><dt className="font-semibold text-text-muted">Protocol</dt><dd className="uppercase">{row.protocol}</dd></div>
      <div><dt className="font-semibold text-text-muted">Pack</dt><dd>{row.pack}</dd></div>
      {row.matcherNames.length > 0 && <div><dt className="font-semibold text-text-muted">Matchers</dt><dd>{row.matcherNames.join(", ")}</dd></div>}
      {row.tags.length > 0 && <div><dt className="font-semibold text-text-muted">Tags</dt><dd>{row.tags.join(", ")}</dd></div>}
    </dl>
    {row.description && <Block title="Description"><p className="whitespace-pre-wrap">{row.description}</p></Block>}
    {hasClassification && <Block title="Classification"><dl className="grid gap-1 text-[12px]">
      {classification.cveId.length > 0 && <div><dt className="inline font-semibold text-text-muted">CVE: </dt><dd className="inline font-mono">{classification.cveId.join(", ")}</dd></div>}
      {classification.cweId.length > 0 && <div><dt className="inline font-semibold text-text-muted">CWE: </dt><dd className="inline font-mono">{classification.cweId.join(", ")}</dd></div>}
      {classification.cvssScore !== null && <div><dt className="inline font-semibold text-text-muted">CVSS: </dt><dd className="inline font-mono">{classification.cvssScore}</dd></div>}
    </dl></Block>}
    {row.reference.length > 0 && <Block title="References"><ul className="list-disc space-y-1 pl-4 text-[12px]">
      {row.reference.map((reference, index) => <li key={`${index}:${reference}`} className="break-all"><MarkdownLink href={reference} className="text-accent underline">{reference}</MarkdownLink></li>)}
    </ul></Block>}
    {row.remediation && <Block title="Remediation"><p className="whitespace-pre-wrap">{row.remediation}</p></Block>}
    {row.extracted.length > 0 && <Block title="Extracted values"><ul className="space-y-1 text-[12px]">
      {row.extracted.map(([name, values], index) => <li key={`${index}:${name}`}><span className="font-medium text-text-muted">{name || "(unnamed extractor)"}: </span><span className="break-all font-mono text-text-primary">{values.join(", ")}</span></li>)}
    </ul></Block>}
    {row.lines.length > 0 && <Block title="Matched lines">
      <ul aria-label="Matched lines" className="space-y-1">
        {lines.items.map((line, index) => <li key={`${line.line}:${line.startColumn}:${index}`}>
          <span className="font-mono text-[11px] text-text-muted">Line {line.line}, columns {line.startColumn}–{line.endColumn}</span>
          <pre className="selectable mt-0.5 overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border bg-surface-code p-2 font-mono text-[11px] text-text-primary">{line.text}</pre>
        </li>)}
      </ul>
      {lines.pageCount > 1 && <ResultPagination pagination={lines} label="matched lines" onPageChange={lines.setPage} />}
    </Block>}
    {exchange && <Block title="Stored exchange">
      <p className="mb-2 text-[11px] text-text-muted">Recorded for {exchange.target} over {exchange.protocol}. Credential-bearing values are redacted. Shown as plain text.</p>
      <p className="text-[11px] font-semibold text-text-muted">Request</p>
      <CodeBlock label="Request" text={exchange.request} />
      <p className="mt-2 text-[11px] font-semibold text-text-muted">Response excerpt</p>
      {exchange.responseExcerpt ? <CodeBlock label="Response excerpt" text={exchange.responseExcerpt} /> : <p className="text-[12px] text-text-muted">No response excerpt was stored for this match.</p>}
      {exchange.responseTruncated && <p className="mt-1 text-[11px] text-warning">The response was truncated; only the first part is stored.</p>}
    </Block>}
  </div>;
}
