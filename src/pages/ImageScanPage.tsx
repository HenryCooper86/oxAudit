import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "../lib/events";
import { CircleX, ScanSearch } from "lucide-react";
import { api } from "../lib/api";
import type { BinaryComponent, CanonicalRun, ImageScanOutcome } from "../lib/types";
import { useAppStore, useToastStore } from "../lib/stores";
import { acquireScan, cancelActiveScan, detachScan, refreshScanWork, releaseScan, scanOperationId, useScanWorkStore } from "../features/project-home/coordinator";
import { readSavedScanReceipt } from "../features/runs/savedScanReceipt";
import { ResultPagination } from "../components/workbench/ResultPagination";
import { usePagination } from "../lib/pagination";
import { normalizeCommandError } from "../lib/commandError";
import { Button, SectionLabel, Switch } from "../components/ui";
import { ToolPage } from "../components/workbench/ToolPage";

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
  const [outcome, setOutcome] = useState<ImageScanOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState<CanonicalRun | null>(null);
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
      if (typeof event.payload !== "string" && event.payload.operationId !== active.operationId) return;
      const message = typeof event.payload === "string" ? event.payload : event.payload.message ?? event.payload.line ?? "";
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
  const pagination = usePagination(components);
  const layers = useMemo(() => outcome?.layers ?? [], [outcome]);
  const layerPagination = usePagination(layers);

  return (
    <ToolPage
      title="Image Scan"
      description="Scan a container image — a saved tar, an OCI layout, or a registry reference pulled directly — with the built-in scanner, including the OS package database inside it."
    >
      <div className="space-y-4">
        <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px]">
          <SectionLabel>Target</SectionLabel>
          <input
            aria-label="Image target"
            className="mt-2 w-full rounded-sm border border-border bg-surface px-2 py-1 text-[13px] text-text-primary"
            placeholder="registry-1.docker.io/library/nginx:1.25, a saved image tar, an OCI layout directory, a firmware archive"
            value={target}
            disabled={busy}
            onChange={(event) => { targetEdited.current = true; receiptRequest.current += 1; setTarget(event.target.value); setOutcome(null); setAttempt(null); setError(null); }}
            onKeyDown={(event) => {
              if (event.key === "Enter") void scan();
            }}
          />
          <label className="mt-3 flex items-center gap-2 text-[12px] text-text-secondary">
            Advisory database (optional — offline advisory matching)
            <input
              aria-label="Advisory database path"
              className="min-w-[260px] flex-1 rounded-sm border border-border bg-surface px-2 py-1 text-[12px] text-text-primary"
              placeholder="advisories.sqlite3 (built on the Advisory Database page)"
              value={advisoryDbPath}
              disabled={busy}
              onChange={(event) => setAdvisoryDbPath(event.target.value)}
            />
          </label>
          <label className="mt-3 flex items-center gap-2 text-[12px] text-text-secondary">
            <Switch checked={offline} onChange={setOffline} disabled={busy} label="Offline advisories" />
            Offline advisories — answer distro packages only from the advisory database
          </label>
          <div className="mt-3 flex gap-2">
            <Button disabled={Boolean(activeWork) || busy || !target.trim()} onClick={scan}>
              <ScanSearch size={13} aria-hidden />
              Scan
            </Button>
            {busy && (
              <Button variant="outline" disabled={activeWork?.cancelling} onClick={() => void cancelActiveScan()}>
                <CircleX size={13} aria-hidden />
                Cancel
              </Button>
            )}
          </div>
        </section>

        {error && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px] text-warning">{error}</section>
        )}
        {attempt && attempt.state !== "completed" && (
          <p role="status" className="text-[12px] text-warning">Latest saved attempt: {attempt.state} · {attempt.id}. {outcome?.runId !== attempt.id ? "Previous saved evidence is shown below." : ""}</p>
        )}

        {progress.length > 0 && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4">
            <SectionLabel>Progress</SectionLabel>
            <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-text-secondary">
              {progress.join("\n")}
            </pre>
          </section>
        )}

        {outcome && summary && (
          <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary text-[13px]">
            <div className="space-y-1 border-b border-border px-4 py-3 text-[11px] text-text-muted">
              <p>Saved run: {outcome.runId} · {outcome.state ?? "completed"} · {outcome.offline ? "Offline advisories" : "Online advisories permitted"}</p>
              {outcome.state && outcome.state !== "completed" && <p className="text-warning">Coverage is unproven for this {outcome.state} receipt. Zero recorded vulnerabilities does not establish a clean image.</p>}
              {outcome.imageDigest && <p>Image digest: <span className="break-all font-mono">{outcome.imageDigest}</span></p>}
              {outcome.localEvidence && <div className="space-y-1 border-t border-border pt-2">
                <p>Pre-scan identity snapshot · {outcome.localEvidence.kind}. This records evidence before scanning and does not bind the bytes read later by the scan.</p>
                {!outcome.localEvidence.complete && <p className="text-warning">Local identity capture is incomplete; complete byte identity is unproven.</p>}
                {outcome.localEvidence.file?.sha256 && <p>File SHA-256: <span className="break-all font-mono">{outcome.localEvidence.file.sha256}</span> · {outcome.localEvidence.file.bytesHashed.toLocaleString()} bytes hashed</p>}
                {outcome.localEvidence.file?.prefixSha256 && <p>Prefix SHA-256: <span className="break-all font-mono">{outcome.localEvidence.file.prefixSha256}</span> · {outcome.localEvidence.file.bytesHashed.toLocaleString()} bytes hashed</p>}
                {outcome.localEvidence.file?.changedDuringRead === true && <p className="text-warning">The file changed while its identity was captured.</p>}
                {outcome.localEvidence.oci?.indexSha256 && <p>OCI index SHA-256: <span className="break-all font-mono">{outcome.localEvidence.oci.indexSha256}</span></p>}
                {outcome.localEvidence.notes.map((note, index) => <p key={index}>{note}</p>)}
              </div>}
              <Button type="button" variant="outline" size="sm" onClick={() => openExport(outcome.runId)}>Open Export Center</Button>
            </div>
            {layers.length > 0 && <>
              <ul aria-label="Saved image layers" className="divide-y divide-border px-4 text-[11px] text-text-muted">
                {layerPagination.items.map(layer => <li key={layer.digest} className="py-2"><span className="font-mono break-all">{layer.digest}</span> · {layer.sizeBytes.toLocaleString()} bytes · {layer.mediaType ?? "Media type unknown"}</li>)}
              </ul>
              {layerPagination.pageCount > 1 && <ResultPagination pagination={layerPagination} label="image layers" onPageChange={layerPagination.setPage} />}
            </>}
            <div className="border-b border-border px-4 py-3 font-semibold">
              {outcome.result.target}: {summary.components} component{summary.components === 1 ? "" : "s"},{" "}
              {summary.vulnerabilities} vulnerabilit{summary.vulnerabilities === 1 ? "y" : "ies"}
              {Number(summary.vulnerabilities) > 0 &&
                ` (${[["critical", summary.critical], ["high", summary.high], ["medium", summary.medium], ["low", summary.low]]
                  .filter(([, count]) => Number(count) > 0)
                  .map(([name, count]) => `${count} ${name}`)
                  .join(", ")})`}
            </div>
            <ul aria-label="Image components" className="divide-y divide-border">
              {pagination.items.map((component) => (
                <ImageComponentRow key={`${component.vendor}:${component.product}@${component.version}`} component={component} />
              ))}
            </ul>
            <ResultPagination pagination={pagination} label="image components" onPageChange={pagination.setPage} />
            {outcome.notes.length > 0 && (
              <div className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
                {outcome.notes.map((note, index) => (
                  <p key={index}>{note}</p>
                ))}
              </div>
            )}
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
