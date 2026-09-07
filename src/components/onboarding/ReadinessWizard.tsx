import {
  CheckCircle2,
  Database,
  Loader2,
  RefreshCw,
  ScanSearch,
  Settings2,
  FolderOpen,
  Sparkles,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { open as pickFolder } from "@tauri-apps/plugin-dialog";
import { normalizeCommandError } from "../../lib/commandError";
import { startProjectCheck, useScanWorkStore } from "../../features/project-home/coordinator";
import { api } from "../../lib/api";
import {
  completeReadinessWizard,
  isReadinessWizardComplete,
  READINESS_WIZARD_OPEN_EVENT,
} from "../../lib/readinessWizard";
import { useAppStore } from "../../lib/stores";
import type { BinaryScannersStatus, DataSourceStatus } from "../../lib/types";
import { BrandMark } from "../brand/BrandMark";
import { Button } from "../ui";

interface ReadinessChecks {
  scanners: BinaryScannersStatus | null;
  sources: DataSourceStatus[] | null;
  loading: boolean;
  error: boolean;
}

const INITIAL_CHECKS: ReadinessChecks = {
  scanners: null,
  sources: null,
  loading: true,
  error: false,
};

const STEPS = ["Welcome", "Core readiness", "Optional AI", "Your first project"];

export function ReadinessWizard() {
  const settings = useAppStore((state) => state.settings);
  const settingsLoadError = useAppStore((state) => state.settingsLoadError);
  const aiReadiness = useAppStore((state) => state.aiReadiness);
  const setPage = useAppStore((state) => state.setPage);
  const [open, setOpen] = useState(() =>
    typeof localStorage === "undefined"
      ? false
      : !isReadinessWizardComplete(localStorage),
  );
  const [step, setStep] = useState(0);
  const [projectPath, setProjectPath] = useState(() => useAppStore.getState().selectedProject ?? "");
  const [projectError, setProjectError] = useState<string | null>(null);
  const [selecting, setSelecting] = useState(false);
  const activeScan = useScanWorkStore((state) => state.active);
  const generation = useRef(0);
  const readinessRequest = useRef(0);
  const [checks, setChecks] = useState<ReadinessChecks>(INITIAL_CHECKS);
  const rootRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const firstActionRef = useRef<HTMLButtonElement>(null);
  const eligible = settings !== null || settingsLoadError;

  const refreshChecks = useCallback(async () => {
    const request = ++readinessRequest.current;
    setChecks((current) => ({ ...current, loading: true, error: false }));
    const [scanners, sources] = await Promise.allSettled([
      api.binaryToolStatus(),
      api.listDataSources(),
    ]);
    if (readinessRequest.current !== request) return;
    setChecks({
      scanners: scanners.status === "fulfilled" ? scanners.value : null,
      sources: sources.status === "fulfilled" ? sources.value : null,
      loading: false,
      error: scanners.status === "rejected" || sources.status === "rejected",
    });
  }, []);

  useEffect(() => {
    const reopen = () => {
      generation.current += 1;
      readinessRequest.current += 1;
      setSelecting(false);
      setProjectError(null);
      setStep(0);
      setOpen(true);
    };
    window.addEventListener(READINESS_WIZARD_OPEN_EVENT, reopen);
    return () => {
      generation.current += 1;
      readinessRequest.current += 1;
      window.removeEventListener(READINESS_WIZARD_OPEN_EVENT, reopen);
    };
  }, []);

  useEffect(() => {
    if (open && eligible) void refreshChecks();
  }, [eligible, open, refreshChecks]);

  const finish = useCallback(() => {
    generation.current += 1;
    readinessRequest.current += 1;
    setSelecting(false);
    completeReadinessWizard(localStorage);
    setOpen(false);
  }, []);

  const changeProject = (path: string) => {
    generation.current += 1;
    setProjectPath(path);
    setProjectError(null);
    setSelecting(false);
  };
  const browseProject = async () => {
    const token = ++generation.current;
    setProjectError(null);
    setSelecting(false);
    try {
      const path = await pickFolder({ directory: true, multiple: false, title: "Select your first project" });
      if (generation.current === token && typeof path === "string") changeProject(path);
    } catch (error) {
      if (generation.current === token) setProjectError(normalizeCommandError(error).message);
    }
  };
  const checkProject = async () => {
    if (!projectPath.trim() || !settings || useScanWorkStore.getState().active) return;
    const token = ++generation.current;
    setSelecting(true);
    setProjectError(null);
    try {
      const context = await api.inspectSourceProject(projectPath.trim());
      if (generation.current !== token) return;
      if (useScanWorkStore.getState().active) {
        setProjectError("Another scan is active. Wait for it to finish or cancel it from the status bar.");
        return;
      }
      // This explicit handoff selects Home. The shared coordinator owns all
      // scan work after this point; late work cannot mutate runtime selection.
      useAppStore.getState().setSelectedProject(context.canonicalPath);
      setPage("dashboard");
      void startProjectCheck(context.canonicalPath, settings.scan);
      finish();
    } catch (error) {
      if (generation.current === token) setProjectError(normalizeCommandError(error).message);
    } finally {
      if (generation.current === token) setSelecting(false);
    }
  };

  useEffect(() => {
    if (!open || !eligible) return;
    const focusFrame = requestAnimationFrame(() => firstActionRef.current?.focus());
    const root = rootRef.current;
    const main = root?.parentElement;
    const shellSection = main?.parentElement;
    const appShell = shellSection?.parentElement;
    const outsideRegions = [
      ...Array.from(main?.children ?? []).filter((element) => element !== root),
      ...Array.from(shellSection?.children ?? []).filter((element) => element !== main),
      ...Array.from(appShell?.children ?? []).filter((element) => element !== shellSection),
    ] as HTMLElement[];
    const previousIsolation = outsideRegions.map((element) => ({
      element,
      inert: element.inert,
      ariaHidden: element.getAttribute("aria-hidden"),
    }));
    for (const { element } of previousIsolation) {
      element.inert = true;
      element.setAttribute("aria-hidden", "true");
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        finish();
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", onKeyDown);
      for (const { element, inert, ariaHidden } of previousIsolation) {
        element.inert = inert;
        if (ariaHidden === null) element.removeAttribute("aria-hidden");
        else element.setAttribute("aria-hidden", ariaHidden);
      }
    };
  }, [eligible, finish, open, step]);

  if (!open || !eligible) return null;

  const offlineSources =
    checks.sources?.filter((source) => source.state === "offlineReady").length ?? 0;
  const aiConfigured = Boolean(settings?.ai.enabled && settings.ai.baseUrl.trim());
  const aiReady = aiReadiness.status === "ready";

  return (
    <div
      ref={rootRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 sm:p-6"
    >
      <section
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="readiness-wizard-title"
        aria-describedby="readiness-wizard-description"
        className="flex max-h-[min(680px,calc(100vh-2rem))] w-full max-w-2xl flex-col overflow-hidden rounded-md border border-border bg-surface-primary shadow-lg"
      >
        <div className="border-b border-border bg-surface-secondary px-5 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-sm bg-accent-subtle text-accent">
              <BrandMark className="h-4 w-4" />
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-accent">
                First-launch readiness
              </p>
              <h1 id="readiness-wizard-title" className="mt-0.5 text-[17px] font-semibold text-text-primary">
                {STEPS[step]}
              </h1>
            </div>
            <span className="font-mono text-[11px] tabular-nums text-text-muted">
              {step + 1} / {STEPS.length}
            </span>
          </div>
          <div className="mt-3 grid grid-cols-4 gap-1" aria-hidden="true">
            {STEPS.map((label, index) => (
              <span
                key={label}
                className={`h-1 rounded-full ${index <= step ? "bg-accent" : "bg-surface-tertiary"}`}
              />
            ))}
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5 sm:px-6">
          {step === 0 && (
            <div>
              <p id="readiness-wizard-description" className="text-[14px] leading-relaxed text-text-secondary">
                oxAudit is GUI-first: the built-in scanners work without a command line, and optional integrations can be added when you need them.
              </p>
              <div className="mt-5 grid gap-3 sm:grid-cols-3">
                <Feature icon={<ScanSearch size={16} />} title="Scan locally" text="Choose a folder or binary and start from the interface." />
                <Feature icon={<Database size={16} />} title="Know your data" text="See advisory provenance and offline availability." />
                <Feature icon={<Sparkles size={16} />} title="AI is optional" text="Core scanning and reports do not require an AI provider." />
              </div>
            </div>
          )}

          {step === 1 && (
            <div>
              <p id="readiness-wizard-description" className="text-[13px] leading-relaxed text-text-secondary">
                These checks describe what is ready on this device. Optional tools improve coverage but do not block your first scan.
              </p>
              <div className="mt-4 space-y-2">
                <CheckRow
                  ready={checks.scanners?.canScan === true}
                  pending={checks.loading}
                  title="Built-in binary scanning"
                  description={checks.scanners?.canScan ? "Ready without an external scanner." : checks.loading ? "Checking the native scanning engine…" : "Scanner readiness could not be read; try the check again."}
                />
                <CheckRow
                  ready={(checks.sources?.length ?? 0) > 0}
                  pending={checks.loading}
                  title="Advisory source registry"
                  description={checks.sources ? `${checks.sources.length} sources registered; ${offlineSources} currently available offline.` : checks.loading ? "Checking local source metadata…" : "Source readiness could not be read; try the check again."}
                />
                <CheckRow
                  ready={!checks.error}
                  pending={checks.loading}
                  title="Desktop command bridge"
                  description={checks.error ? "Some readiness details were unavailable. Core screens remain usable." : "Native desktop services responded."}
                />
              </div>
              <Button className="mt-4" variant="ghost" onClick={() => void refreshChecks()} disabled={checks.loading}>
                <RefreshCw size={13} aria-hidden="true" className={checks.loading ? "animate-spin" : ""} />
                Check again
              </Button>
            </div>
          )}

          {step === 2 && (
            <div>
              <p id="readiness-wizard-description" className="text-[13px] leading-relaxed text-text-secondary">
                The assistant supports OpenAI-compatible cloud and local endpoints. You can skip this and configure it later from Settings.
              </p>
              <div className="mt-4 rounded-sm border border-border bg-surface-secondary p-4">
                <div className="flex items-start gap-3">
                  <span className={`mt-0.5 ${aiReady ? "text-success" : "text-text-muted"}`}>
                    {aiReadiness.status === "checking" ? <Loader2 size={17} className="animate-spin" /> : <Sparkles size={17} />}
                  </span>
                  <div>
                    <p className="text-[13px] font-medium text-text-primary">
                      {aiReady ? "AI assistant ready" : aiConfigured ? "AI provider configured" : "No AI provider configured"}
                    </p>
                    <p className="mt-1 text-[12px] leading-relaxed text-text-muted">
                      {aiReady ? `${settings?.ai.model ?? "Configured model"} is reachable.` : aiConfigured ? "The saved endpoint is not currently ready; review or test it in Settings." : "This is optional. Scanning, compliance checks, and reports continue to work."}
                    </p>
                  </div>
                </div>
              </div>
              <Button
                className="mt-4"
                variant="outline"
                onClick={() => {
                  finish();
                  setPage("settings");
                }}
              >
                <Settings2 size={13} aria-hidden="true" />
                Configure AI in Settings
              </Button>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-4">
              <p id="readiness-wizard-description" className="text-[13px] leading-relaxed text-text-secondary">
                Choose a project folder, then check its source and dependencies from Home. AI is optional. No repository scripts are executed.
              </p>
              <div className="flex items-center gap-2">
                <input
                  aria-label="First project folder"
                  value={projectPath}
                  onChange={(event) => changeProject(event.target.value)}
                  placeholder="Choose a project folder…"
                  className="selectable min-w-0 flex-1 rounded-sm border border-border bg-surface-secondary px-3 py-2 font-mono text-xs text-text-primary placeholder:text-text-muted"
                />
                <Button ref={firstActionRef} variant="outline" onClick={() => void browseProject()}>
                  <FolderOpen size={14} aria-hidden="true" /> Browse…
                </Button>
              </div>
              {selecting && <p role="status" className="text-[13px] text-text-secondary">Inspecting project…</p>}
              {projectError && <p role="alert" className="text-[13px] text-error">Project unavailable: {projectError}</p>}
              {!settings && <p className="text-[13px] text-warning">Settings could not be loaded. Open Settings and retry before checking a project.</p>}
              {activeScan && <p className="text-[13px] text-text-secondary">Another scan is active. You can return to Home to follow its progress.</p>}
              <p className="text-[12px] leading-relaxed text-text-muted">
                Home keeps your project history and results. You can reopen this setup from Settings and add a project later.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button variant="primary"
                  disabled={!projectPath.trim() || !settings || selecting || Boolean(activeScan)}
                  onClick={() => void checkProject()}>
                  <ScanSearch size={13} aria-hidden="true" /> Check project
                </Button>
                <Button variant="outline" onClick={() => { finish(); setPage("dashboard"); }}>Go to Home</Button>
                <Button variant="ghost" onClick={finish}>Skip for now</Button>
              </div>
            </div>
          )}
        </div>

        {step < 3 && (
          <div className="flex items-center justify-between gap-3 border-t border-border bg-surface-secondary px-5 py-3 sm:px-6">
            <Button ref={firstActionRef} variant="ghost" onClick={step === 0 ? finish : () => setStep((current) => current - 1)}>
              {step === 0 ? "Skip for now" : "Back"}
            </Button>
            <Button variant="primary" onClick={() => setStep((current) => Math.min(3, current + 1))}>
              {step === 2 ? "Continue without AI" : "Continue"}
            </Button>
          </div>
        )}
      </section>
    </div>
  );
}

function Feature({ icon, title, text }: { icon: ReactNode; title: string; text: string }) {
  return (
    <div className="rounded-sm border border-border bg-surface-secondary p-3.5">
      <span className="text-accent" aria-hidden="true">{icon}</span>
      <p className="mt-2 text-[13px] font-medium text-text-primary">{title}</p>
      <p className="mt-1 text-[11px] leading-relaxed text-text-muted">{text}</p>
    </div>
  );
}

function CheckRow({ ready, pending, title, description }: { ready: boolean; pending: boolean; title: string; description: string }) {
  return (
    <div className="flex items-start gap-3 rounded-sm border border-border bg-surface-secondary p-3.5">
      {pending ? (
        <Loader2 size={16} aria-hidden="true" className="mt-0.5 shrink-0 animate-spin text-accent" />
      ) : (
        <CheckCircle2 size={16} aria-hidden="true" className={`mt-0.5 shrink-0 ${ready ? "text-success" : "text-warning"}`} />
      )}
      <div>
        <p className="text-[13px] font-medium text-text-primary">{title}</p>
        <p className="mt-0.5 text-[11px] leading-relaxed text-text-muted">{description}</p>
      </div>
    </div>
  );
}
