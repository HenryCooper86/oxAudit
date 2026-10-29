import { CheckCircle2, Download, FileJson, ShieldAlert, TriangleAlert, Upload } from "lucide-react";
import { open, save } from "../lib/dialog";
import { useEffect, useMemo, useRef, useState, type JSX } from "react";
import { Button, Input, Select } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { serverMode } from "../lib/transport";
import { useAppStore, useToastStore } from "../lib/stores";
import type { CanonicalRun, ExportFormat, ExportPreview, ImportPreview } from "../lib/types";
import { errorMessage } from "../lib/commandError";

const FORMATS: Array<{ id: ExportFormat; label: string; description: string }> = [
  { id: "oxaudit-json", label: "oxAudit JSON", description: "Complete canonical graph, evidence, provenance, and screen projection." },
  { id: "sarif", label: "SARIF 2.1.0", description: "Source, secret, policy, and semantic observations for code-scanning tools." },
  { id: "cyclonedx", label: "CycloneDX 1.6 SBOM", description: "Normalized dependency and binary component inventory." },
  { id: "spdx", label: "SPDX 2.3", description: "Portable software-package inventory with purl references." },
  { id: "openvex", label: "OpenVEX", description: "Advisory affected statements without inventing an analyst disposition." },
  { id: "cyclonedx-vex", label: "CycloneDX VEX", description: "CycloneDX inventory plus vulnerability analysis records." },
  { id: "github-issues-csv", label: "GitHub Issues CSV", description: "One importable issue per finding: title, description with location and recommendation, labels." },
  { id: "jira-csv", label: "Jira CSV", description: "One importable issue per finding: summary, task type, description, mapped priority, labels." },
];

export function ExportCenterPage(): JSX.Element {
  const push = useToastStore((state) => state.push);
  const [runs, setRuns] = useState<CanonicalRun[] | null>(null);
  const [runsError, setRunsError] = useState<string | null>(null);
  const [runsCapped, setRunsCapped] = useState(false);
  const [runsRevision, setRunsRevision] = useState(0);
  const [runId, setRunId] = useState(() => useAppStore.getState().exportHandoff?.runId ?? "");
  const [format, setFormat] = useState<ExportFormat>("oxaudit-json");
  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewRevision, setPreviewRevision] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importPath, setImportPath] = useState("");
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [importLoading, setImportLoading] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [serverExportPath, setServerExportPath] = useState("");
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [exportWorking, setExportWorking] = useState(false);
  const exportRevision = useRef(0);
  const importRevision = useRef(0);
  const exportBusy = useRef(false);
  const importBusy = useRef(false);
  const mounted = useRef(true);

  const invalidateExport = () => {
    exportRevision.current += 1;
    setError(null);
    setSavedPath(null);
  };

  const selectRun = (id: string) => {
    invalidateExport();
    setRunId(id);
  };

  const changeImportPath = (path: string) => {
    importRevision.current += 1;
    setImportPath(path);
    setImportPreview(null);
    setImportError(null);
  };

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      exportRevision.current += 1;
      importRevision.current += 1;
    };
  }, []);

  useEffect(() => {
    const applyHandoff = () => {
      const handoff = useAppStore.getState().exportHandoff;
      if (handoff) {
        selectRun(handoff.runId);
        useAppStore.setState({ exportHandoff: null });
      }
    };
    applyHandoff();
    return useAppStore.subscribe((state, previous) => {
      if (state.exportHandoff !== previous.exportHandoff) applyHandoff();
    });
  }, []);

  useEffect(() => {
    let disposed = false;
    setRunsError(null);
    void api.listCanonicalRuns(undefined, 100).then((loaded) => {
      if (disposed) return;
      const completed = loaded.filter((run) => ["completed", "incomplete", "failed", "cancelled"].includes(run.state));
      setRuns(completed);
      setRunsCapped(loaded.length >= 100);
      setRunId((current) => current || completed[0]?.id || "");
    }).catch((cause) => {
      if (!disposed) setRunsError(errorMessage(cause));
    });
    return () => { disposed = true; };
  }, [runsRevision]);

  useEffect(() => {
    let disposed = false;
    setPreviewError(null);
    if (!runId) {
      setPreview(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    setPreview(null);
    setError(null);
    void api.previewRunExport(runId, format).then((next) => {
      if (!disposed) setPreview(next);
    }).catch((cause) => {
      if (!disposed) {
        setPreview(null);
        setPreviewError(errorMessage(cause));
      }
    }).finally(() => {
      if (!disposed) setLoading(false);
    });
    return () => { disposed = true; };
  }, [format, runId, previewRevision]);

  const selectedFormat = useMemo(() => FORMATS.find((item) => item.id === format)!, [format]);
  const exportFile = async () => {
    if (!preview || loading || exportBusy.current || (serverMode && !serverExportPath.trim())) return;
    exportBusy.current = true;
    const requestedRevision = ++exportRevision.current;
    const requestedRun = runId;
    const requestedFormat = format;
    const requestedLabel = selectedFormat.label;
    const requestedPath = serverExportPath.trim();
    setExportWorking(true);
    setError(null);
    setSavedPath(null);
    try {
      const destination = serverMode ? requestedPath : await save({
        defaultPath: preview.suggestedFileName,
        filters: [{ name: requestedLabel, extensions: [requestedFormat.endsWith("-csv") ? "csv" : "json"] }],
      });
      if (!destination || requestedRevision !== exportRevision.current) return;
      // Once submitted, a write retains its captured run, format and destination.
      await api.writeRunExport(requestedRun, requestedFormat, destination);
      if (mounted.current) {
        if (requestedRevision === exportRevision.current) setSavedPath(destination);
        push("success", `Saved ${requestedLabel} to ${destination}`);
      }
    } catch (cause) {
      if (requestedRevision === exportRevision.current) {
        setError(errorMessage(cause));
        push("error", "The export could not be saved");
      }
    } finally {
      exportBusy.current = false;
      if (mounted.current) setExportWorking(false);
    }
  };

  const chooseImport = async () => {
    if (importBusy.current || (serverMode && !importPath.trim())) return;
    importBusy.current = true;
    const requestedRevision = ++importRevision.current;
    const requestedPath = importPath.trim();
    setImportLoading(true);
    setImportError(null);
    try {
      const selected = serverMode ? requestedPath : await open({
        multiple: false,
        directory: false,
        filters: [{ name: "Security report", extensions: ["json", "sarif", "spdx", "cdx"] }],
      });
      if (!selected || Array.isArray(selected) || requestedRevision !== importRevision.current) return;
      setImportPath(selected);
      setImportPreview(null);
      const result = await api.previewReportImport(selected);
      if (requestedRevision === importRevision.current) setImportPreview(result);
    } catch (cause) {
      if (requestedRevision === importRevision.current) setImportError(errorMessage(cause));
    } finally {
      importBusy.current = false;
      if (mounted.current) setImportLoading(false);
    }
  };

  const importReport = async (kind: "inventory" | "external") => {
    if (!importPreview || !importPath || importBusy.current) return;
    importBusy.current = true;
    const requestedRevision = ++importRevision.current;
    const requestedPath = importPath;
    const expectedSha256 = importPreview.contentSha256;
    const componentRecords = importPreview.componentRecords;
    const mappedClaimCount = importPreview.mappedClaimCount;
    setImportLoading(true);
    setImportError(null);
    try {
      const importedRun = kind === "inventory"
        ? await api.importInventoryReport(requestedPath, expectedSha256)
        : await api.importExternalReport(requestedPath, expectedSha256);
      if (mounted.current) {
        setRuns((current) => [importedRun, ...(current ?? []).filter((run) => run.id !== importedRun.id)]);
        setRunId((current) => current || importedRun.id);
        push("success", kind === "inventory"
          ? `Imported ${componentRecords} components from ${requestedPath} as a separate durable run`
          : `Retained ${mappedClaimCount} mapped claims from ${requestedPath} with external-unverified trust`);
      }
    } catch (cause) {
      if (requestedRevision === importRevision.current) {
        setImportError(errorMessage(cause));
        push("error", kind === "inventory" ? "The inventory was not imported" : "The external claims were not imported");
      }
    } finally {
      importBusy.current = false;
      if (mounted.current) setImportLoading(false);
    }
  };

  return (
    <ToolPage
      title="Export Center"
      description="Choose saved evidence, preview exactly what leaves oxAudit, validate the format, and save the complete report. Incomplete or failed receipts retain their coverage state."
    >
      <section className="rounded-sm border border-border bg-surface-secondary p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="max-w-2xl">
            <h2 className="text-[13px] font-semibold text-text-primary">Import and conflict preview</h2>
            <p className="mt-1 text-[12px] leading-relaxed text-text-muted">Inspect bounded oxAudit JSON, SARIF, CycloneDX, SPDX, or OpenVEX before anything is persisted. SBOM components can be imported into a separate immutable run; VEX and SARIF never overwrite local findings or reviews.</p>
          </div>
          <div className="flex min-w-0 flex-wrap items-end gap-2">
            {serverMode && (
              <label className="min-w-0 flex-1 text-[12px] text-text-secondary">
                Report file on server
                <Input
                  className="mt-1"
                  value={importPath}
                  onChange={(event) => changeImportPath(event.target.value)}
                  placeholder="/data/inventory.json"
                  aria-describedby="import-server-path-help"
                />
              </label>
            )}
            <Button
              type="button"
              onClick={() => void chooseImport()}
              variant="outline"
              size="md"
              disabled={importLoading || (serverMode && !importPath.trim())}
            >
              <Upload size={13} aria-hidden="true" />
              {importLoading ? "Inspecting…" : serverMode ? "Inspect report" : "Choose report…"}
            </Button>
          </div>
        </div>
        {serverMode && (
          <p id="import-server-path-help" className="mt-2 text-[11px] text-text-muted">
            Enter a report path on the server, not your browser's computer. Inspect it before importing;
            changing the path requires a new preview. Import verifies the inspected file's SHA-256.
          </p>
        )}
        {importError && <div className="mt-3"><InlineState compact tone="error" title="Import preview failed" description={importError} /></div>}
        {importPreview && (
          <div className="mt-3 overflow-hidden rounded-sm border border-border bg-surface-primary">
            <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-3 py-2">
              <div>
                <p className="text-[12px] font-medium text-text-primary">{importPreview.fileName} <span className="font-mono text-[10px] text-text-muted">{importPreview.format}</span></p>
                <p className="mt-0.5 text-[10px] text-text-muted">{importPreview.componentRecords} components · {importPreview.findingRecords} findings · {importPreview.reviewRecords} review statements · {importPreview.unmappedCount} unmapped</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {importPreview.canImportInventory && (
                  <Button type="button" onClick={() => void importReport("inventory")} variant="primary" size="md" disabled={importLoading}><Upload size={13} aria-hidden="true" />Import separate inventory</Button>
                )}
                {importPreview.canImportExternalClaims && (
                  <Button type="button" onClick={() => void importReport("external")} variant="outline" size="md" disabled={importLoading}><ShieldAlert size={13} aria-hidden="true" />Retain external claims</Button>
                )}
                {!importPreview.canImportInventory && !importPreview.canImportExternalClaims && (
                <span className="inline-flex items-center gap-1 text-[11px] text-warning"><ShieldAlert size={13} aria-hidden="true" />Preview only—mapping required</span>
                )}
              </div>
            </header>
            {importPreview.warnings.map((warning) => <p key={warning} className="flex items-start gap-2 border-b border-warning-subtle bg-warning-subtle px-3 py-2 text-[11px] text-text-secondary"><TriangleAlert size={13} aria-hidden="true" className="mt-0.5 shrink-0" />{warning}</p>)}
            <div className="grid gap-3 p-3 text-[11px] min-[760px]:grid-cols-2">
              <div>
                <p className="font-semibold text-text-secondary">Identity conflicts ({importPreview.conflictCount})</p>
                {importPreview.conflicts.length ? <ul className="mt-1 list-disc space-y-1 pl-4 text-text-muted">{importPreview.conflicts.map((conflict) => <li key={conflict}>{conflict}</li>)}</ul> : <p className="mt-1 text-text-muted">No identity overlap found in the latest 100 durable runs.</p>}
              </div>
              <div>
                <p className="font-semibold text-text-secondary">Unmapped records ({importPreview.unmappedCount})</p>
                {importPreview.unmappedRecords.length ? <ul className="mt-1 list-disc space-y-1 pl-4 text-text-muted">{importPreview.unmappedRecords.map((record) => <li key={record}>{record}</li>)}</ul> : <p className="mt-1 text-text-muted">Every record passed the preview mapper.</p>}
              </div>
              <div className="min-[760px]:col-span-2">
                <p className="font-semibold text-text-secondary">Mapped external claims ({importPreview.mappedClaimCount})</p>
                {importPreview.mappedClaims.length ? (
                  <ul className="mt-1 space-y-1 text-text-muted">
                    {importPreview.mappedClaims.slice(0, 20).map((claim) => (
                      <li key={claim.recordId} className="flex flex-wrap gap-x-2">
                        <span className="font-mono text-text-secondary">{claim.vulnerabilityId ?? claim.ruleId}</span>
                        <span>{claim.status}</span>
                        <span>{claim.subjectIds.join(", ")}</span>
                        <span className="text-warning">{claim.trust}</span>
                      </li>
                    ))}
                  </ul>
                ) : <p className="mt-1 text-text-muted">No record met the strict identifier, subject, status, and provenance mapping rules.</p>}
              </div>
            </div>
            <p className="break-all border-t border-border px-3 py-2 font-mono text-[10px] text-text-muted">SHA-256 {importPreview.contentSha256}</p>
          </div>
        )}
      </section>
      <section className="rounded-sm border border-border bg-surface-secondary p-4">
        <div className="grid gap-4 min-[760px]:grid-cols-2">
          <label className="text-[12px] text-text-secondary">Saved run
            <Select className="mt-1 w-full" value={runId} onChange={(event) => selectRun(event.target.value)} disabled={!runs?.length && !runId}>
              {runId && !runs?.some(run => run.id === runId) && <option value={runId}>Selected saved run · {runId}</option>}
              {(runs ?? []).map((run) => <option key={run.id} value={run.id}>{run.kind} · {run.targetLabel} · {run.state} · {new Date(run.updatedAtMs).toLocaleString()}</option>)}
            </Select>
          </label>
          <label className="text-[12px] text-text-secondary">Format
            <Select className="mt-1 w-full" value={format} onChange={(event) => {
              invalidateExport();
              setPreview(null);
              setFormat(event.target.value as ExportFormat);
            }}>
              {FORMATS.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
            </Select>
          </label>
        </div>
        {runsCapped && <p className="mt-2 text-[11px] text-text-muted">The run list is limited to the latest 100 durable runs.</p>}
        <p className="mt-3 text-[12px] leading-relaxed text-text-muted">{selectedFormat.description}</p>
        {serverMode && (
          <div className="mt-4">
            <label className="block text-[12px] text-text-secondary">
              Export file on server
              <Input
                className="mt-1"
                value={serverExportPath}
                onChange={(event) => {
                  invalidateExport();
                  setServerExportPath(event.target.value);
                }}
                placeholder={preview ? `/data/${preview.suggestedFileName}` : "/data/report.json"}
                aria-describedby="export-server-path-help"
              />
            </label>
            <p id="export-server-path-help" className="mt-2 text-[11px] text-text-muted">
              Enter the full file path on the server, including the extension. The destination folder
              must exist. Saving replaces an existing file at this path; it does not download to your browser.
            </p>
          </div>
        )}
      </section>

      {!runs && !runsError && <InlineState tone="running" title="Loading durable runs" />}
      {runsError && <InlineState tone="error" title="Saved runs are unavailable" description={runsError}
        action={<Button type="button" variant="outline" onClick={() => setRunsRevision((revision) => revision + 1)}>Retry loading runs</Button>} />}
      {runs?.length === 0 && !runId && <InlineState tone="empty" title="No saved canonical runs are available yet" description="Run a Source, Dependency, Binary, Image, or History scan first." />}
      {loading && <InlineState tone="running" compact title="Generating and validating preview" />}
      {previewError && <InlineState tone="error" title="Export preview is unavailable" description={previewError}
        action={<Button type="button" variant="outline" onClick={() => setPreviewRevision((revision) => revision + 1)}>Retry preview</Button>} />}
      {error && <InlineState tone="error" title="Export is unavailable" description={error} />}
      {savedPath && <p role="status" className="break-all text-[12px] text-success">Saved export to {savedPath}</p>}
      {preview && !loading && (
        <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
            <div>
              <h2 className="flex items-center gap-2 text-[13px] font-semibold text-text-primary"><FileJson size={14} aria-hidden="true" />{selectedFormat.label} preview</h2>
              <p className="mt-1 font-mono text-[10px] text-text-muted">{preview.mediaType} · {preview.artifacts} artifacts · {preview.components} components · {preview.observations} observations</p>
            </div>
            <div className="flex items-center gap-3">
              {preview.valid ? (
                <span className="inline-flex items-center gap-1 text-[11px] text-success"><CheckCircle2 size={12} aria-hidden="true" />Structure valid</span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[11px] text-error"><TriangleAlert size={12} aria-hidden="true" />Structure invalid</span>
              )}
              <Button type="button" onClick={() => void exportFile()} variant="primary" size="md" disabled={exportWorking || (serverMode && !serverExportPath.trim())}>
                <Download size={13} aria-hidden="true" />
                {exportWorking ? "Saving…" : serverMode ? "Save to server" : "Save export…"}
              </Button>
            </div>
          </header>
          {preview.warnings.map((warning) => <p key={warning} className="flex items-start gap-2 border-b border-warning-subtle bg-warning-subtle px-4 py-2 text-[11px] text-text-secondary"><TriangleAlert size={13} aria-hidden="true" className="mt-0.5 shrink-0" />{warning}</p>)}
          <pre className="selectable max-h-[34rem] overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-[11px] leading-relaxed text-text-secondary">{preview.content}</pre>
          {preview.truncated && <p className="border-t border-border px-4 py-2 text-[11px] text-text-muted">Preview limited to 1 MiB. The saved report contains the complete validated document.</p>}
        </section>
      )}
    </ToolPage>
  );
}
