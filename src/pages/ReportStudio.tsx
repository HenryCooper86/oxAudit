import { Download, FileCode2, FileSpreadsheet, FileText, RefreshCw, ShieldAlert } from "lucide-react";
import { save } from "../lib/dialog";
import { useEffect, useMemo, useState, type JSX } from "react";
import { Button, Input, Select, Switch, Textarea } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
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

  useEffect(() => {
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
    return () => { disposed = true; };
  }, []);

  const selectedAssessment = useMemo(() => assessments?.find((assessment) => assessment.id === assessmentId), [assessmentId, assessments]);
  const selectedFormat = REPORT_FORMATS.find((item) => item.id === format) ?? REPORT_FORMATS[0];

  const selectAssessment = (id: string) => {
    setAssessmentId(id);
    setPreview(null);
    const assessment = assessments?.find((item) => item.id === id);
    if (assessment) setMetadata(defaultMetadata(assessment));
  };

  const updateMetadata = <K extends keyof ComplianceReportMetadata>(key: K, value: ComplianceReportMetadata[K]) => {
    setMetadata((current) => ({ ...current, [key]: value }));
    setPreview(null);
  };

  const buildPreview = async () => {
    if (!assessmentId) return;
    setWorking(true);
    setError(null);
    try {
      setPreview(await api.previewComplianceReport({ assessmentId, format, metadata }));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setWorking(false);
    }
  };

  const saveReport = async () => {
    if (!assessmentId) return;
    let currentPreview = preview;
    if (!currentPreview || currentPreview.format !== format) {
      setWorking(true);
      try {
        currentPreview = await api.previewComplianceReport({ assessmentId, format, metadata });
        setPreview(currentPreview);
      } catch (cause) {
        setError(String(cause));
        setWorking(false);
        return;
      }
      setWorking(false);
    }
    const destination = await save({ defaultPath: currentPreview.suggestedFileName, filters: [{ name: selectedFormat.label, extensions: [format === "markdown" ? "md" : format] }] });
    if (!destination) return;
    setWorking(true);
    try {
      const receipt = await api.writeComplianceReport({ assessmentId, format, metadata }, destination);
      push("success", `Saved report · SHA-256 ${receipt.contentSha256.slice(0, 12)}…`);
    } catch (cause) {
      setError(String(cause));
      push("error", "The report could not be saved");
    } finally {
      setWorking(false);
    }
  };

  const canGenerate = Boolean(assessmentId && metadata.title.trim() && metadata.organization.trim() && metadata.assessor.trim() && metadata.classification.trim() && metadata.executiveSummary.trim());

  return (
    <ToolPage title="Report Studio" description="Compile one durable assessment into a professional, reproducible report without changing its evidence or review history.">
      <div className="rounded-sm border border-warning-border bg-warning-subtle px-4 py-3 text-[12px] text-text-secondary"><p className="flex items-start gap-2"><ShieldAlert size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-warning" /><span>Every format carries the same claim boundary: evidence readiness is not certification, legal advice, or a conformity determination.</span></p></div>
      {!assessments && !error ? <InlineState tone="running" title="Loading durable assessments" /> : null}
      {assessments?.length === 0 ? <InlineState tone="empty" title="No compliance assessments are available" description="Run checks in Compliance Center before compiling a report." /> : null}
      {error ? <InlineState tone="error" title="Report Studio unavailable" description={error} /> : null}

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
                {REPORT_FORMATS.map((item) => { const Icon = item.icon; const active = format === item.id; return <button key={item.id} type="button" aria-pressed={active} onClick={() => { setFormat(item.id); setPreview(null); }} className={`flex items-start gap-3 rounded-sm border p-3 text-left ${active ? "border-accent bg-accent-subtle" : "border-border bg-surface-primary hover:bg-surface-hover"}`}><Icon size={15} aria-hidden="true" className={active ? "text-accent" : "text-text-muted"} /><span><strong className="block text-[11px] text-text-primary">{item.label}</strong><span className="mt-1 block text-[10px] leading-relaxed text-text-muted">{item.description}</span></span></button>; })}
              </div>
              <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 border-t border-border pt-4"><Switch checked={metadata.includeEvidence} onChange={(value) => updateMetadata("includeEvidence", value)} label="Include evidence references" /><Switch checked={metadata.includeReviews} onChange={(value) => updateMetadata("includeReviews", value)} label="Include human reviews" /><Switch checked={metadata.includeReferences} onChange={(value) => updateMetadata("includeReferences", value)} label="Include source references" /></div>
            </section>
          </div>

          <section className="min-w-0 self-start overflow-hidden rounded-sm border border-border bg-surface-secondary min-[1050px]:sticky min-[1050px]:top-5">
            <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3"><div><h2 className="text-[13px] font-semibold text-text-primary">Report preview</h2><p className="mt-1 text-[10px] text-text-muted">{selectedFormat.label} · generated from saved assessment truth</p></div><div className="flex gap-2"><Button variant="outline" disabled={!canGenerate || working} onClick={() => void buildPreview()}><RefreshCw size={13} aria-hidden="true" />{working ? "Building…" : "Build preview"}</Button><Button variant="primary" disabled={!canGenerate || working} onClick={() => void saveReport()}><Download size={13} aria-hidden="true" />Save…</Button></div></header>
            {!preview ? <div className="p-4"><InlineState tone="idle" title="Preview has not been compiled" description="Choose a format and build a fresh preview. PDF previews show document size and contents summary; saved PDF output is fully paginated." /></div> : null}
            {preview ? <><div className="border-b border-border px-4 py-2 text-[10px] text-text-muted">{preview.mediaType} · {preview.bytes.toLocaleString()} bytes · {preview.suggestedFileName}</div>{preview.warnings.map((warning) => <p key={warning} className="border-b border-warning-border bg-warning-subtle px-4 py-2 text-[10px] text-text-secondary">{warning}</p>)}<pre className="selectable max-h-[46rem] overflow-auto whitespace-pre-wrap break-words p-4 font-mono text-[10px] leading-relaxed text-text-secondary">{preview.content}</pre>{preview.truncated ? <p className="border-t border-border px-4 py-2 text-[10px] text-text-muted">Preview limited to 1 MiB; the saved report is complete.</p> : null}</> : null}
          </section>
        </div>
      ) : null}
    </ToolPage>
  );
}
