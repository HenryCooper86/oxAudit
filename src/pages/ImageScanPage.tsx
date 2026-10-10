import { progressMessage } from "../features/runs/nativeProgress";
import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "../lib/events";
import { CircleX, ScanSearch } from "lucide-react";
import { api } from "../lib/api";
import type { BinaryComponent, CanonicalRun, ImageScanOutcome } from "../lib/types";
import { useAppStore, useToastStore } from "../lib/stores";
import { acquireScan, cancelActiveScan, detachScan, refreshScanWork, releaseScan, scanOperationId, useScanWorkStore } from "../features/project-home/coordinator";
import { readSavedScanReceipt } from "../features/runs/savedScanReceipt";
import { EvidenceSummary, imageEvidence } from "../features/runs/EvidenceSummary";
import { ResultPagination } from "../components/workbench/ResultPagination";
import { useCanonicalPage } from "../lib/serverPagination";
import { ServerPageState } from "../components/workbench/ServerPageState";
import { usePagination } from "../lib/pagination";
import { normalizeCommandError } from "../lib/commandError";
import { Button, Switch } from "../components/ui";
import { ToolPage } from "../components/workbench/ToolPage";
import { TargetBar } from "../components/workbench/TargetBar";
import { TargetInput } from "../components/workbench/TargetInput";
import { RunTimeline } from "../features/runs/RunTimeline";
import { InlineState } from "../components/workbench/InlineState";

export function ImageScanPage() {
  const push = useToastStore((s) => s.push);
  const openExport = useAppStore(s => s.openExport);
  const setPageStatus = useAppStore(s => s.setPageStatus);
  const clearPageStatus = useAppStore(s => s.clearPageStatus);
  const activeWork = useScanWorkStore(s => s.active);
  const recoveryRevision = useScanWorkStore(s => s.recoveryRevision);
  const [target, setTarget] = useState(() => useScanWorkStore.getState().lastTargets.image ?? "");
  const [advisoryDbPath, setAdvisoryDbPath] = useState("");
  const [offline, setOffline] = useState(false);
  const [localBusy, setBusy] = useState(false);
  const busy = localBusy || activeWork?.owner === "image";
  const [progress, setProgress] = useState<string[]>([]);
  const [progressOperationId, setProgressOperationId] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<ImageScanOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState<CanonicalRun | null>(null);
  const [receipt, setReceipt] = useState<CanonicalRun | null>(null);
  const [layerTotal, setLayerTotal] = useState(0);
  const [componentTotal, setComponentTotal] = useState(0);
  const mounted = useRef(true);
  const scanInFlight = useRef<number | null>(null);
  const receiptRequest = useRef(0);
  const targetEdited = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      receiptRequest.current += 1;
      if (scanInFlight.current !== null) detachScan(scanInFlight.current);
      clearPageStatus("image-scan");
    };
  }, [clearPageStatus]);

  useEffect(() => {
    const generation = ++receiptRequest.current;
    if (activeWork?.owner === "image" && !target.trim()) { setTarget(activeWork.path); return; }
    if (busy || (!target.trim() && targetEdited.current)) return;
    const recent = useScanWorkStore.getState().backend.recent.find(work => work.kind === "image" && work.target === target.trim());
    void readSavedScanReceipt<ImageScanOutcome>("image", target.trim(), recent?.runId).then(saved => {
      if (!mounted.current || generation !== receiptRequest.current) return;
      setAttempt(saved.attempt);
      if (saved.loadError) setError(`Saved image evidence could not be loaded: ${saved.loadError}`);
      if (saved.data) {
        setOutcome(saved.data);
        setReceipt(saved.receipt);
        setLayerTotal(saved.sections.layers ?? 0);
        setComponentTotal(saved.sections.components ?? 0);
        if (!target.trim()) setTarget(saved.target);
        setPageStatus("image-scan", { label: `Saved image results · ${saved.data.state} · ${saved.data.result.summary.vulnerabilities} vulnerabilities`, tone: saved.data.state === "completed" ? "success" : "neutral" });
      }
    }).catch(cause => {
      if (mounted.current && generation === receiptRequest.current) setError(`Saved image evidence could not be loaded: ${String(cause)}`);
    });
    return () => { receiptRequest.current += 1; };
  }, [activeWork?.owner, activeWork?.path, busy, recoveryRevision, setPageStatus, target]);

  useEffect(() => {
    let disposed = false;
    let stop: (() => void) | undefined;
    void listen<string | { operationId: string; message?: string; line?: string }>("image://progress", (event) => {
      const active = useScanWorkStore.getState().active;
      if (disposed || active?.owner !== "image" || active.terminalStatus) return;
      const parsed = progressMessage(event.payload);
      if (!parsed || (parsed.operationId ? parsed.operationId !== active.operationId : scanInFlight.current !== active.id)) return;
      const message = parsed.message;
      setProgressOperationId(active.operationId);
      setProgress((lines) => [...lines.slice(-199), message]);
    }).then((unlisten) => {
      if (disposed) unlisten();
      else stop = unlisten;
    }).catch((cause) => {
      if (!disposed) setError(String(cause));
    });
    return () => { disposed = true; stop?.(); };
  }, []);

  const scan = async () => {
    if (!target.trim() || scanInFlight.current !== null) return;
    const ownership = acquireScan("image", target.trim(), "Scanning image");
    if (ownership === null) return;
    scanInFlight.current = ownership;
    receiptRequest.current += 1;
    setBusy(true);
    setProgress([]);
    setError(null);
    setPageStatus("image-scan", { label: "Scanning image", detail: target.trim(), tone: "running" });
    try {
      const next = await api.scanImage({
        target: target.trim(),
        advisoryDbPath: advisoryDbPath.trim() || null,
        offline,
        operationId: scanOperationId(ownership),
      });
      const active = useScanWorkStore.getState().active;
      if (!mounted.current || active?.id !== ownership) return;
      if (active.cancelling || active.terminalStatus === "cancelled" || next.state === "cancelled") {
        setError("Image scan cancelled; previous saved results remain available.");
        setPageStatus("image-scan", { label: "Image scan cancelled", tone: "neutral" });
        return;
      }
      setOutcome(next);
      setAttempt(null);
      setReceipt(null);
      const complete = (!next.state || next.state === "completed") && active.terminalStatus !== "failed" && active.terminalStatus !== "incomplete";
      setPageStatus("image-scan", { label: `Image scan ${complete ? "complete" : next.state ?? active.terminalStatus} · ${next.result.summary.vulnerabilities} vulnerabilities`, tone: complete ? "success" : "neutral" });
      push(complete ? "success" : "info", `Image scan ${complete ? "complete" : next.state ?? active.terminalStatus}: ${next.result.summary.vulnerabilities} vulnerabilities`);
    } catch (cause) {
      if (mounted.current && useScanWorkStore.getState().active?.id === ownership) {
        const message = normalizeCommandError(cause).message;
        setError(message);
        setPageStatus("image-scan", { label: message.includes("cancelled") || useScanWorkStore.getState().active?.cancelling ? "Image scan cancelled" : "Image scan failed", tone: "neutral" });
      }
    } finally {
      scanInFlight.current = null;
      releaseScan(ownership);
      if (mounted.current) setBusy(false);
      void refreshScanWork(true);
    }
  };

  const summary = outcome?.result.summary;
  const components = useMemo(() => outcome?.result.components ?? [], [outcome]);
  const localPagination = usePagination(components);
  const savedComponents = useCanonicalPage<BinaryComponent>(receipt?.id ?? null, "components", {}, componentTotal);
  const pagination = receipt ? savedComponents : localPagination;
  const layers = useMemo(() => outcome?.layers ?? [], [outcome]);
  const localLayerPagination = usePagination(layers);
  const savedLayers = useCanonicalPage<ImageScanOutcome["layers"][number]>(receipt?.id ?? null, "layers", {}, layerTotal);
  const layerPagination = receipt ? savedLayers : localLayerPagination;

  return (
    <ToolPage
      title="Image Scan"
      description="Scan a container image — a saved tar, an OCI layout, or a registry reference pulled directly — with the built-in scanner, including the OS package database inside it."
    >
      <div className="space-y-4">
        <TargetBar primary={<>
          <Button disabled={Boolean(activeWork) || busy || !target.trim()} onClick={() => void scan()} variant="primary">
            <ScanSearch size={13} aria-hidden="true" />Scan
          </Button>
          {busy && <Button variant="danger" disabled={activeWork?.cancelling} onClick={() => void cancelActiveScan()}>
            <CircleX size={13} aria-hidden="true" />{activeWork?.cancelling ? "Cancelling…" : "Cancel"}
          </Button>}
        </>} secondary={<div className="flex min-w-0 flex-wrap items-start gap-3">
          <TargetInput
            label="Advisory database (optional)" inputLabel="Advisory database path"
            value={advisoryDbPath} onChange={setAdvisoryDbPath} disabled={busy}
            pickers={["file"]} pickerLabels={{ file: "Choose database…" }}
            placeholder="advisories.sqlite3"
            hint="Used for local advisory matching. Build a database on the Advisory Database page."
          />
          <Switch checked={offline} onChange={setOffline} disabled={busy} label="Offline advisories" />
        </div>}>
          <TargetInput
            label="Image target" inputLabel="Image target" value={target}
            disabled={busy || Boolean(activeWork)}
            pickers={["file", "folder"]}
            pickerLabels={{ file: "Choose image file…", folder: "Choose OCI folder…" }}
            placeholder="registry.example.com/team/app:tag or a saved image path"
            hint="Supports a saved image tar, OCI layout folder, firmware archive, or a full registry reference. Type registry.example.com/team/app:tag or a digest reference. Choose Scan when ready."
            onChange={value => { targetEdited.current = true; receiptRequest.current += 1; setTarget(value); setOutcome(null); setReceipt(null); setAttempt(null); setProgress([]); setError(null); }}
          />
        </TargetBar>

        <RunTimeline kind="image" running={busy} hasCompletedResult={Boolean(outcome)}
          title="Scanning image" detail={progress[progress.length - 1]} logs={progress} detailsOperationId={progressOperationId} />

        {error && (
          <InlineState tone={error.toLowerCase().includes("cancelled") ? "unavailable" : "error"} title={error.toLowerCase().includes("cancelled") ? "Image scan cancelled" : "Image scan unavailable"} description={error}
            action={!busy && !error.toLowerCase().includes("cancelled") ? <Button variant="outline" onClick={() => void scan()} disabled={Boolean(activeWork) || !target.trim()}>Retry scan</Button> : undefined} />
        )}
        {attempt && !outcome && attempt.state !== "completed" && (
          <p role="status" className="text-[12px] text-warning">Latest saved attempt: {attempt.state}. Saved evidence could not be loaded.</p>
        )}



        {outcome && <EvidenceSummary label="Image" evidence={imageEvidence(outcome, receipt, receipt ? layerTotal : undefined)} running={busy} cancelling={activeWork?.cancelling} attempt={attempt}
          operation={error ? error.toLowerCase().includes("cancelled") ? "Latest operation cancelled" : "Latest operation failed or evidence unavailable" : null}
          action={<Button type="button" variant="outline" size="sm" onClick={() => openExport(outcome.runId)}>Open Export Center</Button>}>
              <p>Target: <span className="break-all font-mono">{outcome.result.target}</span></p>
              {outcome.imageDigest && <p>Image digest: <span className="break-all font-mono">{outcome.imageDigest}</span></p>}
              {outcome.localEvidence && <div className="space-y-1 border-t border-border pt-2">
                <p>Local identity kind: {outcome.localEvidence.kind}</p>
                {outcome.localEvidence.file?.sha256 && <p>File SHA-256: <span className="break-all font-mono">{outcome.localEvidence.file.sha256}</span> · {outcome.localEvidence.file.bytesHashed.toLocaleString()} bytes hashed</p>}
                {outcome.localEvidence.file?.prefixSha256 && <p>Prefix SHA-256: <span className="break-all font-mono">{outcome.localEvidence.file.prefixSha256}</span> · {outcome.localEvidence.file.bytesHashed.toLocaleString()} bytes hashed</p>}
                {outcome.localEvidence.oci?.indexSha256 && <p>OCI index SHA-256: <span className="break-all font-mono">{outcome.localEvidence.oci.indexSha256}</span></p>}
              </div>}
            {layerPagination.total > 0 && <>
              {receipt && <ServerPageState page={savedLayers} />}
              <ul aria-label="Saved image layers" className="divide-y divide-border px-4 text-[11px] text-text-muted">
                {layerPagination.items.map(layer => <li key={layer.digest} className="py-2"><span className="font-mono break-all">{layer.digest}</span> · {layer.sizeBytes.toLocaleString()} bytes · {layer.mediaType ?? "Media type unknown"}</li>)}
              </ul>
              {layerPagination.pageCount > 1 && <ResultPagination pagination={layerPagination} label="image layers" onPageChange={layerPagination.setPage} />}
            </>}
        </EvidenceSummary>}

        {outcome && summary && (
          <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary text-[13px]">
            <div className="border-b border-border px-4 py-3 font-semibold">
              {outcome.result.target}: {summary.components} component{summary.components === 1 ? "" : "s"},{" "}
              {summary.vulnerabilities} vulnerabilit{summary.vulnerabilities === 1 ? "y" : "ies"}
              {Number(summary.vulnerabilities) > 0 &&
                ` (${[["critical", summary.critical], ["high", summary.high], ["medium", summary.medium], ["low", summary.low]]
                  .filter(([, count]) => Number(count) > 0)
                  .map(([name, count]) => `${count} ${name}`)
                  .join(", ")})`}
            </div>
            {receipt && <ServerPageState page={savedComponents} />}
            <ul aria-label="Image components" className="divide-y divide-border">
              {pagination.items.map((component) => (
                <ImageComponentRow key={`${component.vendor}:${component.product}@${component.version}`} component={component} />
              ))}
            </ul>
            <ResultPagination pagination={pagination} label="image components" onPageChange={pagination.setPage} />
          </section>
        )}

        <p className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
          Registry pulls verify every blob against its manifest digest. Saved runs retain resolved image and layer identities and the effective advisory mode. Offline absence does not establish a clean result.
        </p>
      </div>
    </ToolPage>
  );
}

function ImageComponentRow({ component }: { component: BinaryComponent }) {
  const pagination = usePagination(component.vulnerabilities, 20);
  return <li className="px-4 py-3">
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="font-semibold">{component.product} <span className="text-text-secondary">{component.version}</span></span>
                    <span className="text-[11px] font-mono text-text-muted">{component.paths[0]}</span>
                  </div>
                  {component.vulnerabilities.length > 0 && (
                    <ul className="mt-1 space-y-1">
                      {pagination.items.map((vulnerability) => (
                        <li key={vulnerability.cveId} className="text-[12px] text-text-secondary">
                          <span className="font-semibold uppercase">{vulnerability.severity}</span>{" "}
                          {vulnerability.cveId} ({vulnerability.source}
                          {vulnerability.fixedIn ? `, fixed in ${vulnerability.fixedIn}` : ""})
                        </li>
                      ))}
                    </ul>
                  )}
    {pagination.pageCount > 1 && <ResultPagination pagination={pagination} label={`image CVEs for ${component.product} ${component.version}`} onPageChange={pagination.setPage} />}
  </li>;
}
