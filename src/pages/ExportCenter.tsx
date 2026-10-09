import { CheckCircle2, Download, FileJson, ShieldAlert, TriangleAlert, Upload } from "lucide-react";
import { open, save } from "../lib/dialog";
import { useEffect, useMemo, useState, type JSX } from "react";
import { Button, Select } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import type { CanonicalRun, ExportFormat, ExportPreview, ImportPreview } from "../lib/types";

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
  const [runId, setRunId] = useState(() => useAppStore.getState().exportHandoff?.runId ?? "");
  const [format, setFormat] = useState<ExportFormat>("oxaudit-json");
  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importPath, setImportPath] = useState("");
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [importLoading, setImportLoading] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  useEffect(() => {
    const applyHandoff = () => {
      const handoff = useAppStore.getState().exportHandoff;
      if (handoff) {
        setRunId(handoff.runId);
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
    void api.listCanonicalRuns(undefined, 100).then((loaded) => {
      if (disposed) return;
      const completed = loaded.filter((run) => ["completed", "incomplete", "failed", "cancelled"].includes(run.state));
      setRuns(completed);
      setRunId((current) => current || completed[0]?.id || "");
    }).catch((cause) => {
      if (!disposed) setError(String(cause));
    });
    return () => { disposed = true; };
  }, []);

  useEffect(() => {
    let disposed = false;
    if (!runId) {
      setPreview(null);
      return;
    }
    setLoading(true);
    setError(null);
    void api.previewRunExport(runId, format).then((next) => {
      if (!disposed) setPreview(next);
    }).catch((cause) => {
      if (!disposed) {
        setPreview(null);
        setError(String(cause));
      }
    }).finally(() => {
      if (!disposed) setLoading(false);
    });
    return () => { disposed = true; };
  }, [format, runId]);

  const selectedFormat = useMemo(() => FORMATS.find((item) => item.id === format)!, [format]);
  const exportFile = async () => {
    if (!preview) return;
    const destination = await save({
      defaultPath: preview.suggestedFileName,
      filters: [{ name: selectedFormat.label, extensions: [selectedFormat.id.endsWith("-csv") ? "csv" : "json"] }],
    });
    if (!destination) return;
    try {
      await api.writeRunExport(runId, format, destination);
      push("success", `Saved ${selectedFormat.label}`);
    } catch (cause) {
      setError(String(cause));
      push("error", "The export could not be saved");
    }
  };

  const chooseImport = async () => {
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Security report", extensions: ["json", "sarif", "spdx", "cdx"] }],
    });
    if (!selected || Array.isArray(selected)) return;
    setImportPath(selected);
    setImportPreview(null);
    setImportError(null);
    setImportLoading(true);
    try {
      setImportPreview(await api.previewReportImport(selected));
    } catch (cause) {
      setImportError(String(cause));
    } finally {
      setImportLoading(false);
    }
  };

  const importInventory = async () => {
    if (!importPreview || !importPath) return;
    setImportLoading(true);
    setImportError(null);
    try {
      const importedRun = await api.importInventoryReport(importPath, importPreview.contentSha256);
      setRuns((current) => current ? [importedRun, ...current.filter((run) => run.id !== importedRun.id)] : [importedRun]);
      push("success", `Imported ${importPreview.componentRecords} components as a separate durable run`);
    } catch (cause) {
      setImportError(String(cause));
      push("error", "The inventory was not imported");
    } finally {
      setImportLoading(false);
    }
  };

  const importExternalClaims = async () => {
    if (!importPreview || !importPath) return;
    setImportLoading(true);
    setImportError(null);
    try {
      const importedRun = await api.importExternalReport(importPath, importPreview.contentSha256);
      setRuns((current) => current ? [importedRun, ...current.filter((run) => run.id !== importedRun.id)] : [importedRun]);
      push("success", `Retained ${importPreview.mappedClaimCount} mapped claims with external-unverified trust`);
    } catch (cause) {
      setImportError(String(cause));
      push("error", "The external claims were not imported");
    } finally {
      setImportLoading(false);
    }
  };

  return (
    <ToolPage
      title="Export Center"
      description="Choose saved evidence, preview exactly what leaves oxAudit, validate the format, and save it locally. Incomplete or failed receipts retain their coverage state."
    >
      <section className="rounded-sm border border-border bg-surface-secondary p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="max-w-2xl">
            <h2 className="text-[13px] font-semibold text-text-primary">Import and conflict preview</h2>
            <p className="mt-1 text-[12px] leading-relaxed text-text-muted">Inspect bounded oxAudit JSON, SARIF, CycloneDX, SPDX, or OpenVEX before anything is persisted. SBOM components can be imported into a separate immutable run; VEX and SARIF never overwrite local findings or reviews.</p>
          </div>
          <Button type="button" onClick={() => void chooseImport()} variant="outline" size="md" disabled={importLoading}><Upload size={13} aria-hidden="true" />{importLoading ? "Inspecting…" : "Choose report…"}</Button>
        </div>
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
                  <Button type="button" onClick={() => void importInventory()} variant="primary" size="md" disabled={importLoading}><Upload size={13} aria-hidden="true" />Import separate inventory</Button>
                )}
                {importPreview.canImportExternalClaims && (
                  <Button type="button" onClick={() => void importExternalClaims()} variant="outline" size="md" disabled={importLoading}><ShieldAlert size={13} aria-hidden="true" />Retain external claims</Button>
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
            <Select className="mt-1 w-full" value={runId} onChange={(event) => setRunId(event.target.value)} disabled={!runs?.length && !runId}>
              {runId && !runs?.some(run => run.id === runId) && <option value={runId}>Selected saved run · {runId}</option>}
              {(runs ?? []).map((run) => <option key={run.id} value={run.id}>{run.kind} · {run.targetLabel} · {run.state} · {new Date(run.updatedAtMs).toLocaleString()}</option>)}
            </Select>
          </label>
          <label className="text-[12px] text-text-secondary">Format
            <Select className="mt-1 w-full" value={format} onChange={(event) => setFormat(event.target.value as ExportFormat)}>
              {FORMATS.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
            </Select>
          </label>
        </div>
        <p className="mt-3 text-[12px] leading-relaxed text-text-muted">{selectedFormat.description}</p>
      </section>

      {!runs && !error && <InlineState tone="running" title="Loading durable runs" />}
      {runs?.length === 0 && !runId && <InlineState tone="empty" title="No saved canonical runs are available yet" description="Run a Source, Dependency, Binary, Image, or History scan first." />}
      {loading && <InlineState tone="running" compact title="Generating and validating preview" />}
      {error && <InlineState tone="error" title="Export is unavailable" description={error} />}
      {preview && !loading && (
        <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
            <div>
              <h2 className="flex items-center gap-2 text-[13px] font-semibold text-text-primary"><FileJson size={14} aria-hidden="true" />{selectedFormat.label} preview</h2>
              <p className="mt-1 font-mono text-[10px] text-text-muted">{preview.mediaType} · {preview.artifacts} artifacts · {preview.components} components · {preview.observations} observations</p>
            </div>
            <div className="flex items-center gap-3">
              <span className="inline-flex items-center gap-1 text-[11px] text-success"><CheckCircle2 size={12} aria-hidden="true" />Structure valid</span>
              <Button type="button" onClick={() => void exportFile()} variant="primary" size="md"><Download size={13} aria-hidden="true" />Save export…</Button>
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
