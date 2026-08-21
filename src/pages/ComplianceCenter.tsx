import {
  BookOpen,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  FileCheck2,
  History,
  Play,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useMemo, useState, type JSX } from "react";
import { FolderPicker } from "../components/FolderPicker";
import { Button, Input, Select, Textarea } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ToolPage } from "../components/workbench/ToolPage";
import { READINESS_OPTIONS, readinessClass, readinessLabel } from "../features/compliance/model";
import { api } from "../lib/api";
import { useAppStore, useToastStore } from "../lib/stores";
import type {
  ComplianceAssessment,
  ComplianceAssessmentView,
  ComplianceControlAssessment,
  ComplianceProfile,
  ComplianceReadinessStatus,
  ComplianceReview,
} from "../lib/types";

function StatusPill({ status, prefix }: { status: ComplianceReadinessStatus; prefix?: string }): JSX.Element {
  return (
    <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold ${readinessClass(status)}`}>
      {prefix}{readinessLabel(status)}
    </span>
  );
}

function SummaryCards({ assessment }: { assessment: ComplianceAssessment }): JSX.Element {
  const summary = assessment.summary;
  const metrics = [
    ["Coverage", `${summary.evidenceCoveragePercent}%`],
    ["Supported", summary.supported],
    ["Partial", summary.partial],
    ["Gaps", summary.gap],
    ["Manual", summary.manualReview],
    ["N/A", summary.notApplicable],
  ];
  return (
    <div className="grid grid-cols-2 gap-2 min-[680px]:grid-cols-6">
      {metrics.map(([label, value]) => (
        <div key={label} className="rounded-sm border border-border bg-surface-primary px-3 py-2.5">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">{label}</p>
          <p className="mt-1 text-xl font-semibold tabular-nums text-text-primary">{value}</p>
        </div>
      ))}
    </div>
  );
}

function ControlReviewCard({
  assessmentId,
  control,
  latestReview,
  defaultAuthor,
  onSaved,
}: {
  assessmentId: string;
  control: ComplianceControlAssessment;
  latestReview: ComplianceReview | undefined;
  defaultAuthor: string;
  onSaved: (review: ComplianceReview) => void;
}): JSX.Element {
  const push = useToastStore((state) => state.push);
  const [status, setStatus] = useState<ComplianceReadinessStatus>(latestReview?.status ?? "manualReview");
  const [author, setAuthor] = useState(latestReview?.author ?? defaultAuthor);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  const saveReview = async () => {
    setSaving(true);
    try {
      const review = await api.saveComplianceReview(assessmentId, control.controlId, status, note, author);
      setNote("");
      onSaved(review);
      push("success", `Recorded review for ${control.reference}`);
    } catch (cause) {
      push("error", String(cause));
    } finally {
      setSaving(false);
    }
  };

  return (
    <details className="group border-t border-border first:border-t-0">
      <summary className="flex cursor-pointer list-none items-start gap-3 px-4 py-3 hover:bg-surface-hover">
        <ChevronRight size={14} aria-hidden="true" className="mt-0.5 shrink-0 text-text-muted transition-transform group-open:rotate-90" />
        <div className="min-w-0 flex-1">
          <p className="text-[12px] font-semibold text-text-primary">{control.reference} · {control.title}</p>
          <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-text-muted">{control.objective}</p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <StatusPill status={control.automatedStatus} prefix="Evidence: " />
          {latestReview ? <StatusPill status={latestReview.status} prefix="Review: " /> : null}
        </div>
      </summary>
      <div className="border-t border-border bg-surface-primary px-4 py-4 pl-11">
        <p className="text-[12px] leading-relaxed text-text-secondary">{control.rationale}</p>
        <div className="mt-3">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">Matched evidence ({control.evidence.length})</p>
          {control.evidence.length ? (
            <ul className="mt-1.5 space-y-1.5">
              {control.evidence.map((evidence) => (
                <li key={`${evidence.kind}:${evidence.locator}`} className="break-all rounded-sm border border-border bg-surface-secondary px-2.5 py-2 font-mono text-[10px] text-text-secondary">
                  <span className="mr-2 font-sans font-semibold uppercase text-accent">{evidence.kind}</span>{evidence.locator}
                  {evidence.contentSha256 ? <span className="mt-1 block text-text-muted">SHA-256 {evidence.contentSha256}</span> : null}
                </li>
              ))}
            </ul>
          ) : <p className="mt-1 text-[11px] text-text-muted">No matching evidence was collected for this control.</p>}
        </div>
        {latestReview ? (
          <div className="mt-3 rounded-sm border border-success-border bg-success-subtle px-3 py-2 text-[11px] text-text-secondary">
            Latest review by <strong>{latestReview.author}</strong> on {new Date(latestReview.reviewedAtMs).toLocaleString()}: {latestReview.note}
          </div>
        ) : null}
        <div className="mt-4 grid gap-3 border-t border-border pt-4 min-[760px]:grid-cols-2">
          <label className="text-[11px] text-text-secondary">Reviewer
            <Input className="mt-1" value={author} onChange={(event) => setAuthor(event.target.value)} maxLength={160} />
          </label>
          <label className="text-[11px] text-text-secondary">Decision
            <Select className="mt-1" value={status} onChange={(event) => setStatus(event.target.value as ComplianceReadinessStatus)}>
              {READINESS_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </Select>
          </label>
          <label className="text-[11px] text-text-secondary min-[760px]:col-span-2">Decision note
            <Textarea className="mt-1 min-h-20 resize-y" value={note} onChange={(event) => setNote(event.target.value)} maxLength={4000} placeholder="Explain the decision and point to authoritative evidence. Every save appends an audit event." />
          </label>
        </div>
        <div className="mt-3 flex justify-end">
          <Button variant="primary" size="md" disabled={saving || note.trim().length < 4 || author.trim().length < 2} onClick={() => void saveReview()}>
            <ClipboardCheck size={13} aria-hidden="true" />{saving ? "Recording…" : "Record review"}
          </Button>
        </div>
      </div>
    </details>
  );
}

export function ComplianceCenterPage(): JSX.Element {
  const activeProject = useAppStore((state) => state.activeProject);
  const setPage = useAppStore((state) => state.setPage);
  const push = useToastStore((state) => state.push);
  const [profiles, setProfiles] = useState<ComplianceProfile[] | null>(null);
  const [history, setHistory] = useState<ComplianceAssessment[] | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [targetPath, setTargetPath] = useState(activeProject ?? "");
  const [title, setTitle] = useState("Compliance evidence readiness assessment");
  const [organization, setOrganization] = useState("");
  const [assessor, setAssessor] = useState("");
  const [scope, setScope] = useState("Product software, supporting development lifecycle, and available project evidence.");
  const [selectedView, setSelectedView] = useState<ComplianceAssessmentView | null>(null);
  const [running, setRunning] = useState(false);
  const [loadingView, setLoadingView] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let disposed = false;
    void Promise.all([api.listComplianceProfiles(), api.listComplianceAssessments(50)])
      .then(([loadedProfiles, loadedHistory]) => {
        if (disposed) return;
        setProfiles(loadedProfiles);
        setHistory(loadedHistory);
        setSelectedIds(loadedProfiles.map((profile) => profile.id));
      })
      .catch((cause) => { if (!disposed) setError(String(cause)); });
    return () => { disposed = true; };
  }, []);

  const latestReviews = useMemo(() => {
    const byControl = new Map<string, ComplianceReview>();
    for (const review of selectedView?.reviews ?? []) {
      if (!byControl.has(review.controlId)) byControl.set(review.controlId, review);
    }
    return byControl;
  }, [selectedView?.reviews]);

  const toggleProfile = (profileId: string) => {
    setSelectedIds((current) => current.includes(profileId)
      ? current.filter((id) => id !== profileId)
      : [...current, profileId]);
  };

  const loadAssessment = async (assessmentId: string) => {
    setLoadingView(true);
    setError(null);
    try {
      setSelectedView(await api.loadComplianceAssessment(assessmentId));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setLoadingView(false);
    }
  };

  const runAssessment = async () => {
    setRunning(true);
    setError(null);
    try {
      const assessments = await api.runComplianceAssessment({ targetPath, profileIds: selectedIds, title, organization, assessor, scope });
      setHistory((current) => [...assessments, ...(current ?? [])]);
      if (assessments[0]) await loadAssessment(assessments[0].id);
      push("success", `Created ${assessments.length} durable readiness assessment${assessments.length === 1 ? "" : "s"}`);
    } catch (cause) {
      setError(String(cause));
      push("error", "The compliance assessment could not be completed");
    } finally {
      setRunning(false);
    }
  };

  const recordReview = (review: ComplianceReview) => {
    setSelectedView((current) => current ? { ...current, reviews: [review, ...current.reviews] } : current);
  };

  const canRun = targetPath.trim() && selectedIds.length && title.trim() && organization.trim() && assessor.trim() && scope.trim();

  return (
    <ToolPage
      title="Compliance Center"
      description="Collect bounded project evidence, map it to readiness profiles, and record qualified human decisions without claiming certification."
      actions={<Button variant="outline" onClick={() => setPage("report-studio")}><FileCheck2 size={13} aria-hidden="true" />Open Report Studio</Button>}
    >
      <div className="rounded-sm border border-warning-border bg-warning-subtle px-4 py-3 text-[12px] leading-relaxed text-text-secondary">
        <p className="flex items-start gap-2"><ShieldAlert size={15} aria-hidden="true" className="mt-0.5 shrink-0 text-warning" /><span><strong>Evidence readiness, not certification.</strong> Built-in profiles are original high-level mappings to official sources. oxAudit never bundles copyrighted ISO requirements or substitutes for legal, safety, privacy, audit, or type-approval judgment.</span></p>
      </div>

      <section className="rounded-sm border border-border bg-surface-secondary p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div><h2 className="text-[13px] font-semibold text-text-primary">1. Choose evidence scope</h2><p className="mt-1 text-[11px] text-text-muted">The collector follows no symlinks, skips build/vendor trees, caps depth and file count, and sends no file contents to the UI.</p></div>
          <span className="rounded-full border border-border bg-surface-primary px-2 py-1 text-[10px] text-text-muted">Local-only · bounded · content hashes</span>
        </div>
        <div className="mt-4"><FolderPicker value={targetPath} onChange={setTargetPath} inputLabel="Compliance evidence project folder" /></div>
        <div className="mt-4 grid gap-3 min-[760px]:grid-cols-3">
          <label className="text-[11px] text-text-secondary">Assessment title<Input className="mt-1" value={title} onChange={(event) => setTitle(event.target.value)} maxLength={160} /></label>
          <label className="text-[11px] text-text-secondary">Organization<Input className="mt-1" value={organization} onChange={(event) => setOrganization(event.target.value)} maxLength={160} placeholder="Organization or program" /></label>
          <label className="text-[11px] text-text-secondary">Assessor<Input className="mt-1" value={assessor} onChange={(event) => setAssessor(event.target.value)} maxLength={160} placeholder="Responsible reviewer" /></label>
          <label className="text-[11px] text-text-secondary min-[760px]:col-span-3">Scope and boundaries<Textarea className="mt-1 min-h-20 resize-y" value={scope} onChange={(event) => setScope(event.target.value)} maxLength={2000} /></label>
        </div>
      </section>

      <section className="rounded-sm border border-border bg-surface-secondary p-4">
        <div className="flex items-center justify-between gap-3"><div><h2 className="text-[13px] font-semibold text-text-primary">2. Select frameworks</h2><p className="mt-1 text-[11px] text-text-muted">{selectedIds.length} of {profiles?.length ?? 0} selected. Each produces a separate immutable assessment.</p></div><Button variant="primary" disabled={!canRun || running} onClick={() => void runAssessment()}><Play size={13} aria-hidden="true" />{running ? "Assessing…" : "Run selected checks"}</Button></div>
        {!profiles && !error ? <div className="mt-3"><InlineState compact tone="running" title="Loading built-in profiles" /></div> : null}
        <div className="mt-4 grid gap-2 min-[720px]:grid-cols-2">
          {(profiles ?? []).map((profile) => {
            const selected = selectedIds.includes(profile.id);
            return (
              <button key={profile.id} type="button" role="checkbox" aria-checked={selected} onClick={() => toggleProfile(profile.id)} className={`rounded-sm border p-3 text-left transition-colors ${selected ? "border-accent bg-accent-subtle" : "border-border bg-surface-primary hover:bg-surface-hover"}`}>
                <div className="flex items-start gap-3"><span className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border ${selected ? "border-accent bg-accent text-accent-contrast" : "border-border-strong"}`}>{selected ? <CheckCircle2 size={12} aria-hidden="true" /> : null}</span><div><p className="text-[12px] font-semibold text-text-primary">{profile.name} <span className="font-normal text-text-muted">{profile.version}</span></p><p className="mt-1 text-[11px] text-text-muted">{profile.domain} · {profile.controls.length} controls</p><p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-text-muted">{profile.jurisdiction}</p></div></div>
              </button>
            );
          })}
        </div>
      </section>

      {error ? <InlineState tone="error" title="Compliance workflow unavailable" description={error} /> : null}

      <div className="grid gap-5 min-[1000px]:grid-cols-[17rem_minmax(0,1fr)]">
        <section className="min-w-0 rounded-sm border border-border bg-surface-secondary">
          <header className="border-b border-border px-3 py-3"><h2 className="flex items-center gap-2 text-[12px] font-semibold text-text-primary"><History size={13} aria-hidden="true" />Assessment history</h2></header>
          {!history ? <div className="p-3"><InlineState compact tone="running" title="Loading history" /></div> : null}
          {history?.length === 0 ? <div className="p-3"><InlineState compact tone="empty" title="No assessments yet" /></div> : null}
          <div className="max-h-[42rem] overflow-y-auto">
            {(history ?? []).map((assessment) => (
              <button key={assessment.id} type="button" onClick={() => void loadAssessment(assessment.id)} className={`w-full border-b border-border px-3 py-3 text-left last:border-b-0 hover:bg-surface-hover ${selectedView?.assessment.id === assessment.id ? "bg-accent-subtle" : ""}`}>
                <p className="truncate text-[11px] font-semibold text-text-primary">{assessment.profileName}</p><p className="mt-1 truncate font-mono text-[9px] text-text-muted">{assessment.targetLabel}</p><div className="mt-2 flex items-center justify-between text-[10px] text-text-muted"><span>{new Date(assessment.createdAtMs).toLocaleDateString()}</span><span>{assessment.summary.evidenceCoveragePercent}% coverage</span></div>
              </button>
            ))}
          </div>
        </section>

        <section className="min-w-0 overflow-hidden rounded-sm border border-border bg-surface-secondary">
          {loadingView ? <div className="p-4"><InlineState tone="running" title="Loading assessment evidence" /></div> : null}
          {!selectedView && !loadingView ? <div className="p-4"><InlineState tone="idle" title="Select or run an assessment" description="The durable control matrix, evidence paths, and append-only review tools will appear here." /></div> : null}
          {selectedView && !loadingView ? (
            <>
              <header className="border-b border-border p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-[10px] font-semibold uppercase tracking-wide text-accent">{selectedView.assessment.domain}</p><h2 className="mt-1 text-[14px] font-semibold text-text-primary">{selectedView.assessment.profileName} · {selectedView.assessment.profileVersion}</h2><p className="mt-1 break-all font-mono text-[10px] text-text-muted">{selectedView.assessment.targetLabel}</p></div><a href={selectedView.assessment.sourceUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[11px] text-accent hover:underline"><BookOpen size={12} aria-hidden="true" />Official source</a></div><div className="mt-4"><SummaryCards assessment={selectedView.assessment} /></div></header>
              <div className="border-b border-warning-border bg-warning-subtle px-4 py-2 text-[10px] leading-relaxed text-text-secondary">{selectedView.assessment.disclaimer}</div>
              <div className="max-h-[50rem] overflow-y-auto [content-visibility:auto]">
                {selectedView.assessment.controls.map((control) => <ControlReviewCard key={control.controlId} assessmentId={selectedView.assessment.id} control={control} latestReview={latestReviews.get(control.controlId)} defaultAuthor={assessor || selectedView.assessment.metadata.assessor} onSaved={recordReview} />)}
              </div>
            </>
          ) : null}
        </section>
      </div>
    </ToolPage>
  );
}
