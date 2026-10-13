import { Download, FileCode2, FileSpreadsheet, FileText, RefreshCw, ShieldAlert } from "lucide-react";
import { save } from "../lib/dialog";
import { useEffect, useMemo, useRef, useState, type JSX } from "react";
import { Button, Input, Select, Switch, Textarea } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { serverMode } from "../lib/transport";
import { useToastStore } from "../lib/stores";
import type { ComplianceAssessment, ComplianceReportFormat, ComplianceReportMetadata, ComplianceReportPreview } from "../lib/types";

const REPORT_FORMATS: Array<{ id: ComplianceReportFormat; label: string; description: string; icon: typeof FileText }> = [
  { id: "pdf", label: "Professional PDF", description: "Paginated executive report with headers, footers, page numbers, control details, and source boundary.", icon: FileText },
  { id: "html", label: "Self-contained HTML", description: "Responsive, print-ready report with embedded styling and no external assets or scripts.", icon: FileCode2 },
  { id: "markdown", label: "Markdown", description: "Portable narrative report suitable for repositories, review systems, and documentation portals.", icon: FileText },
  { id: "csv", label: "CSV control matrix", description: "Spreadsheet-ready control, status, evidence, and review matrix.", icon: FileSpreadsheet },
  { id: "json", label: "Canonical JSON", description: "Machine-readable assessment, report metadata, evidence references, reviews, and claim boundary.", icon: FileCode2 },
];

function defaultMetadata(assessment?: ComplianceAssessment): ComplianceReportMetadata {
  return {
    title: assessment ? `${assessment.profileName} readiness report` : "Compliance readiness report",
    organization: assessment?.metadata.organization ?? "",
    assessor: assessment?.metadata.assessor ?? "",
    classification: "Confidential",
    executiveSummary: "This report summarizes collected evidence, automated readiness signals, open gaps, and qualified reviewer decisions. It does not assert certification or legal conformity.",
    includeEvidence: true,
    includeReviews: true,
    includeReferences: true,
  };
}

export function ReportStudioPage(): JSX.Element {
  const push = useToastStore((state) => state.push);
  const [assessments, setAssessments] = useState<ComplianceAssessment[] | null>(null);
  const [assessmentId, setAssessmentId] = useState("");
  const [format, setFormat] = useState<ComplianceReportFormat>("pdf");
  const [metadata, setMetadata] = useState<ComplianceReportMetadata>(() => defaultMetadata());
  const [preview, setPreview] = useState<ComplianceReportPreview | null>(null);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [serverPath, setServerPath] = useState("");
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const revision = useRef(0);
  const busy = useRef(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    let disposed = false;
    void api.listComplianceAssessments(100).then((loaded) => {
      if (disposed) return;
      setAssessments(loaded);
      const first = loaded[0];
      if (first) {
        setAssessmentId(first.id);
        setMetadata(defaultMetadata(first));
      }
    }).catch((cause) => { if (!disposed) setError(String(cause)); });
    return () => { disposed = true; mounted.current = false; revision.current += 1; };
  }, []);

  const selectedAssessment = useMemo(() => assessments?.find((assessment) => assessment.id === assessmentId), [assessmentId, assessments]);
  const selectedFormat = REPORT_FORMATS.find((item) => item.id === format) ?? REPORT_FORMATS[0];

  const invalidatePreview = () => {
    // A -> B -> A is a new input lifetime, even when the values match again.
    revision.current += 1;
    setPreview(null);
    setError(null);
    setSavedPath(null);
  };

  const selectAssessment = (id: string) => {
    invalidatePreview();
    setAssessmentId(id);
    const assessment = assessments?.find((item) => item.id === id);
    if (assessment) setMetadata(defaultMetadata(assessment));
  };

  const updateMetadata = <K extends keyof ComplianceReportMetadata>(key: K, value: ComplianceReportMetadata[K]) => {
    invalidatePreview();
    setMetadata((current) => ({ ...current, [key]: value }));
  };

  const buildPreview = async () => {
    if (!assessmentId || busy.current) return;
    busy.current = true;
    const requestedRevision = ++revision.current;
    setWorking(true);
    setError(null);
    try {
      const result = await api.previewComplianceReport({ assessmentId, format, metadata });
      if (requestedRevision === revision.current) setPreview(result);
    } catch (cause) {
      if (requestedRevision === revision.current) setError(String(cause));
    } finally {
      busy.current = false;
      if (mounted.current) setWorking(false);
    }
  };

  const saveReport = async () => {
    if (!assessmentId || busy.current || (serverMode && !serverPath.trim())) return;
    busy.current = true;
    const requestedRevision = ++revision.current;
    const request = { assessmentId, format, metadata };
    const requestedPath = serverPath.trim();
    setWorking(true);
    setError(null);
    setSavedPath(null);
    try {
      let currentPreview = preview;
      if (!currentPreview || currentPreview.format !== format) {
        currentPreview = await api.previewComplianceReport(request);
        if (requestedRevision !== revision.current) return;
        setPreview(currentPreview);
      }
      const destination = serverMode ? requestedPath : await save({ defaultPath: currentPreview.suggestedFileName, filters: [{ name: selectedFormat.label, extensions: [format === "markdown" ? "md" : format] }] });
      if (!destination || requestedRevision !== revision.current) return;
      const receipt = await api.writeComplianceReport(request, destination);
      if (mounted.current) {
        setSavedPath(receipt.outputPath);
        push("success", `Saved ${receipt.outputPath} · SHA-256 ${receipt.contentSha256.slice(0, 12)}…`);
      }
    } catch (cause) {
      if (requestedRevision === revision.current) {
        setError(String(cause));
        push("error", "The report could not be saved");
      }
    } finally {
      busy.current = false;
      if (mounted.current) setWorking(false);
    }
  };

  const canGenerate = Boolean(assessmentId && metadata.title.trim() && metadata.organization.trim() && metadata.assessor.trim() && metadata.classification.trim() && metadata.executiveSummary.trim());

  return (
    <ToolPage title="Report Studio" description="Compile one durable assessment into a professional, reproducible report without changing its evidence or review history.">
      <div className="rounded-sm border border-warning-border bg-warning-subtle px-4 py-3 text-[12px] text-text-secondary"><p className="flex items-start gap-2"><ShieldAlert size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-warning" /><span>Every format carries the same claim boundary: evidence readiness is not certification, legal advice, or a conformity determination.</span></p></div>
      {!assessments && !error ? <InlineState tone="running" title="Loading durable assessments" /> : null}
      {assessments?.length === 0 ? <InlineState tone="empty" title="No compliance assessments are available" description="Run checks in Compliance Center before compiling a report." /> : null}
      {error ? <InlineState tone="error" title="Report Studio unavailable" description={error} /> : null}
      {savedPath && <p role="status" className="break-all text-[12px] text-success">Saved report to {savedPath}</p>}

      {assessments?.length ? (
        <div className="grid gap-5 min-[1050px]:grid-cols-[minmax(0,1fr)_minmax(24rem,0.9fr)]">
          <div className="space-y-5">
            <section className="rounded-sm border border-border bg-surface-secondary p-4">
              <h2 className="text-[13px] font-semibold text-text-primary">1. Report source</h2>
              <label className="mt-3 block text-[11px] text-text-secondary">Durable assessment<Select className="mt-1" value={assessmentId} onChange={(event) => selectAssessment(event.target.value)}>{assessments.map((assessment) => <option key={assessment.id} value={assessment.id}>{assessment.profileName} · {assessment.summary.evidenceCoveragePercent}% · {new Date(assessment.createdAtMs).toLocaleString()}</option>)}</Select></label>
              {selectedAssessment ? <div className="mt-3 grid grid-cols-2 gap-2 text-[10px] min-[640px]:grid-cols-4"><div className="rounded-sm border border-border bg-surface-primary p-2"><span className="text-text-muted">Controls</span><strong className="mt-1 block text-base text-text-primary">{selectedAssessment.summary.total}</strong></div><div className="rounded-sm border border-border bg-surface-primary p-2"><span className="text-text-muted">Coverage</span><strong className="mt-1 block text-base text-text-primary">{selectedAssessment.summary.evidenceCoveragePercent}%</strong></div><div className="rounded-sm border border-border bg-surface-primary p-2"><span className="text-text-muted">Gaps</span><strong className="mt-1 block text-base text-text-primary">{selectedAssessment.summary.gap}</strong></div><div className="rounded-sm border border-border bg-surface-primary p-2"><span className="text-text-muted">Manual</span><strong className="mt-1 block text-base text-text-primary">{selectedAssessment.summary.manualReview}</strong></div></div> : null}
            </section>

            <section className="rounded-sm border border-border bg-surface-secondary p-4">
              <h2 className="text-[13px] font-semibold text-text-primary">2. Document identity</h2>
              <div className="mt-3 grid gap-3 min-[700px]:grid-cols-2">
                <label className="text-[11px] text-text-secondary min-[700px]:col-span-2">Report title<Input className="mt-1" value={metadata.title} onChange={(event) => updateMetadata("title", event.target.value)} maxLength={160} /></label>
                <label className="text-[11px] text-text-secondary">Organization<Input className="mt-1" value={metadata.organization} onChange={(event) => updateMetadata("organization", event.target.value)} maxLength={160} /></label>
                <label className="text-[11px] text-text-secondary">Assessor<Input className="mt-1" value={metadata.assessor} onChange={(event) => updateMetadata("assessor", event.target.value)} maxLength={160} /></label>
                <label className="text-[11px] text-text-secondary">Classification<Input className="mt-1" value={metadata.classification} onChange={(event) => updateMetadata("classification", event.target.value)} maxLength={80} /></label>
                <label className="text-[11px] text-text-secondary min-[700px]:col-span-2">Executive summary<Textarea className="mt-1 min-h-28 resize-y" value={metadata.executiveSummary} onChange={(event) => updateMetadata("executiveSummary", event.target.value)} maxLength={8000} /></label>
              </div>
            </section>

            <section className="rounded-sm border border-border bg-surface-secondary p-4">
              <h2 className="text-[13px] font-semibold text-text-primary">3. Format and disclosure</h2>
              <div className="mt-3 grid gap-2 min-[700px]:grid-cols-2">
                {REPORT_FORMATS.map((item) => { const Icon = item.icon; const active = format === item.id; return <button key={item.id} type="button" aria-pressed={active} onClick={() => { invalidatePreview(); setFormat(item.id); }} className={`flex items-start gap-3 rounded-sm border p-3 text-left ${active ? "border-accent bg-accent-subtle" : "border-border bg-surface-primary hover:bg-surface-hover"}`}><Icon size={15} aria-hidden="true" className={active ? "text-accent" : "text-text-muted"} /><span><strong className="block text-[11px] text-text-primary">{item.label}</strong><span className="mt-1 block text-[10px] leading-relaxed text-text-muted">{item.description}</span></span></button>; })}
              </div>
              <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 border-t border-border pt-4"><Switch checked={metadata.includeEvidence} onChange={(value) => updateMetadata("includeEvidence", value)} label="Include evidence references" /><Switch checked={metadata.includeReviews} onChange={(value) => updateMetadata("includeReviews", value)} label="Include human reviews" /><Switch checked={metadata.includeReferences} onChange={(value) => updateMetadata("includeReferences", value)} label="Include source references" /></div>
            </section>
          </div>

          <section className="min-w-0 self-start overflow-hidden rounded-sm border border-border bg-surface-secondary min-[1050px]:sticky min-[1050px]:top-5">
            {serverMode && <div className="border-b border-border p-4"><label className="block text-[12px] text-text-secondary">Report file on server<Input className="mt-1" value={serverPath} onChange={(event) => { invalidatePreview(); setServerPath(event.target.value); }} placeholder={`/data/report.${format === "markdown" ? "md" : format}`} aria-describedby="report-server-path-help" /></label><p id="report-server-path-help" className="mt-2 text-[11px] text-text-muted">Enter the full file path on the server, including the extension. The destination folder must exist. Saving replaces an existing file at this path.</p></div>}
            <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3"><div><h2 className="text-[13px] font-semibold text-text-primary">Report preview</h2><p className="mt-1 text-[10px] text-text-muted">{selectedFormat.label} · generated from saved assessment truth</p></div><div className="flex gap-2"><Button variant="outline" disabled={!canGenerate || working} onClick={() => void buildPreview()}><RefreshCw size={13} aria-hidden="true" />{working ? "Working…" : "Build preview"}</Button><Button variant="primary" disabled={!canGenerate || working || (serverMode && !serverPath.trim())} onClick={() => void saveReport()}><Download size={13} aria-hidden="true" />{serverMode ? "Save to server" : "Save…"}</Button></div></header>
            {!preview ? <div className="p-4"><InlineState tone="idle" title="Preview has not been compiled" description="Choose a format and build a fresh preview. PDF previews show document size and contents summary; saved PDF output is fully paginated." /></div> : null}
            {preview ? <><div className="border-b border-border px-4 py-2 text-[10px] text-text-muted">{preview.mediaType} · {preview.bytes.toLocaleString()} bytes · {preview.suggestedFileName}</div>{preview.warnings.map((warning) => <p key={warning} className="border-b border-warning-border bg-warning-subtle px-4 py-2 text-[10px] text-text-secondary">{warning}</p>)}<pre className="selectable max-h-[46rem] overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-[10px] leading-relaxed text-text-secondary">{preview.content}</pre>{preview.truncated ? <p className="border-t border-border px-4 py-2 text-[10px] text-text-muted">Preview limited to 1 MiB; the saved report is complete.</p> : null}</> : null}
          </section>
        </div>
      ) : null}
    </ToolPage>
  );
}
