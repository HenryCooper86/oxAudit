import { useEffect, useRef, useState } from "react";
import {
  Binary,
  CheckCircle2,
  Coins,
  Database,
  Loader2,
  Monitor,
  Moon,
  Palette,
  RotateCcw,
  Save,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  XCircle,
} from "lucide-react";
import { Field } from "../components/workbench/Field";
import { InlineState } from "../components/workbench/InlineState";
import { Input, Switch, Textarea } from "../components/ui";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { normalizeThemePreference, THEME_PREFERENCES, type ThemePreference } from "../lib/theme";
import { DEFAULT_SYSTEM_PROMPT } from "../lib/defaults";
import { LatestRequestQueue } from "../lib/latestRequest";
import {
  loadingAiReadiness,
  persistedSettingsRequests,
  publishPersistedAiReadiness,
  savePersistedSettingsSnapshot,
  savePersistedThemePreference,
  unavailableAiReadiness,
} from "../lib/settingsRequests";
import { useAppStore, useToastStore } from "../lib/stores";
import type { AiSettings, AiStatus, AppSettings, UsageSummary } from "../lib/types";

const DEFAULT_SETTINGS: AppSettings = {
  ai: {
    enabled: false,
    baseUrl: "https://api.openai.com/v1",
    apiKey: "",
    model: "gpt-4o-mini",
    temperature: 0.2,
    timeoutSecs: 120,
    maxTokens: 2048,
    systemPrompt: DEFAULT_SYSTEM_PROMPT,
  },
  scan: {
    maxFileSizeKb: 1024,
    followSymlinks: false,
    includeGit: false,
    ignoredDirs: [
      "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build",
      "target", ".next", ".nuxt", ".output", "out", "coverage", ".tox",
      ".mypy_cache", ".pytest_cache", ".ruff_cache", "Pods", ".gradle",
      ".idea", ".vscode", ".svn", ".hg", "bower_components", "jspm_packages",
      ".cache", ".parcel-cache", "env", ".env", "site-packages", "lib64",
    ],
    scanSecrets: true,
    scanVulnerabilities: true,
  },
  nvdApiKey: null,
  theme: "dark",
  binaryScannerPath: null,
};

function cloneSettings(settings: AppSettings): AppSettings {
  return {
    ...settings,
    ai: { ...settings.ai },
    scan: {
      ...settings.scan,
      ignoredDirs: [...settings.scan.ignoredDirs],
    },
  };
}

export function SettingsPage() {
  const settings = useAppStore((state) => state.settings);
  const setSettings = useAppStore((state) => state.setSettings);
  const setAiReadiness = useAppStore((state) => state.setAiReadiness);
  const settingsLoadError = useAppStore((state) => state.settingsLoadError);
  const setSettingsLoadError = useAppStore((state) => state.setSettingsLoadError);
  const push = useToastStore((state) => state.push);

  const [form, setForm] = useState<AppSettings | null>(() =>
    settings ? cloneSettings(settings) : null,
  );
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [draftStatus, setDraftStatus] = useState<AiStatus | null>(null);
  const [saveState, setSaveState] = useState<
    { tone: "success" | "error"; message: string } | null
  >(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [totalUsage, setTotalUsage] = useState<UsageSummary | null>(null);
  const [usageLoading, setUsageLoading] = useState(true);
  const [usageError, setUsageError] = useState(false);
  const formRef = useRef<AppSettings | null>(form);
  const formInitializedRef = useRef(form !== null);
  const editRevisionRef = useRef(0);
  const savePendingRef = useRef(false);
  const testPendingRef = useRef(false);
  const mountedRef = useRef(false);
  const draftRequestsRef = useRef<LatestRequestQueue | null>(null);
  if (!draftRequestsRef.current) {
    draftRequestsRef.current = new LatestRequestQueue();
  }
  const draftRequests = draftRequestsRef.current;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      testPendingRef.current = false;
      draftRequests.invalidate();
    };
  }, [draftRequests]);

  useEffect(() => {
    if (!settings || formInitializedRef.current) return;
    const initial = cloneSettings(settings);
    formInitializedRef.current = true;
    formRef.current = initial;
    setForm(initial);
    setDirty(false);
    setLoadError(null);
  }, [settings]);

  useEffect(() => {
    let cancelled = false;
    api
      .getTotalUsage()
      .then((usage) => {
        if (cancelled) return;
        setTotalUsage(usage);
        setUsageError(false);
      })
      .catch(() => {
        if (!cancelled) setUsageError(true);
      })
      .finally(() => {
        if (!cancelled) setUsageLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const retryLoad = async () => {
    const token = persistedSettingsRequests.begin();
    setAiReadiness(loadingAiReadiness(token));
    if (mountedRef.current) setLoadError(null);
    setSettingsLoadError(false);
    try {
      const loaded = await api.loadSettings();
      if (!persistedSettingsRequests.isCurrent(token)) return;
      setSettingsLoadError(false);
      const readiness = publishPersistedAiReadiness(
        loaded,
        token,
        setAiReadiness,
      );
      setSettings(loaded);
      await readiness;
    } catch (error) {
      if (!persistedSettingsRequests.isCurrent(token)) return;
      setSettingsLoadError(true);
      setAiReadiness(unavailableAiReadiness(token));
      if (mountedRef.current) setLoadError(String(error));
    }
  };

  if (!form) {
    return (
      <ToolPage title="Settings" description="AI endpoint, scan defaults, and data sources">
        <InlineState
          tone={loadError || settingsLoadError ? "unavailable" : "running"}
          title={loadError || settingsLoadError ? "Settings unavailable" : "Loading settings"}
          description={
            loadError || settingsLoadError
              ? `The local configuration could not be loaded.${loadError ? ` ${loadError}` : ""}`
              : "Settings are unavailable until the local configuration has loaded."
          }
          action={
            loadError || settingsLoadError ? (
              <button
                type="button"
                onClick={() => void retryLoad()}
                className="rounded-sm border border-warning-border bg-transparent px-3 py-1.5 text-[12px] font-medium text-warning hover:bg-warning-subtle"
              >
                Retry
              </button>
            ) : undefined
          }
          compact
        />
      </ToolPage>
    );
  }

  const publishDraft = (next: AppSettings) => {
    formRef.current = next;
    editRevisionRef.current += 1;
    setForm(next);
    setDirty(true);
    draftRequests.invalidate();
    testPendingRef.current = false;
    setTesting(false);
    setDraftStatus(null);
    setSaveState(null);
  };

  const applyTheme = (preference: ThemePreference) => {
    const current = formRef.current ?? form;
    if (!current || current.theme === preference) return;

    // Mirror into the draft first so `dirty` never reports a phantom theme
    // diff, then persist. Theme cannot affect AI readiness, so this write
    // skips the connection test a full save performs.
    const next = { ...current, theme: preference };
    formRef.current = next;
    setForm(next);

    void savePersistedThemePreference(
      () => useAppStore.getState().settings,
      preference,
      setSettings,
    ).catch(() => {
      push("error", "Could not save the theme preference.");
    });
  };

  const update = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    const current = formRef.current ?? form;
    publishDraft({ ...current, [key]: value } as AppSettings);
  };

  const updateAi = (patch: Partial<AiSettings>) => {
    const current = formRef.current ?? form;
    publishDraft({ ...current, ai: { ...current.ai, ...patch } });
  };

  const save = async () => {
    const current = formRef.current;
    if (!current || savePendingRef.current) return;
    const snapshot = cloneSettings(current);
    const submittedRevision = editRevisionRef.current;
    savePendingRef.current = true;
    setSaving(true);
    setSaveState(null);
    try {
      const publication = await savePersistedSettingsSnapshot(
        snapshot,
        setSettings,
        setAiReadiness,
      );
      if (!publication) return;
      setSettingsLoadError(false);
      void publication.readiness;

      if (mountedRef.current) {
        const hasNewerEdits = editRevisionRef.current !== submittedRevision;
        setDirty(hasNewerEdits);
        setSaveState({
          tone: "success",
          message: hasNewerEdits
            ? "Settings saved; newer edits remain unsaved"
            : "Settings saved",
        });
        push("success", "Settings saved");
      }
    } catch (error) {
      if (!mountedRef.current) return;
      const message = String(error);
      setSaveState({ tone: "error", message });
    } finally {
      savePendingRef.current = false;
      if (mountedRef.current) setSaving(false);
    }
  };

  const reset = () => {
    publishDraft({
      ...DEFAULT_SETTINGS,
      ai: { ...DEFAULT_SETTINGS.ai },
      scan: { ...DEFAULT_SETTINGS.scan, ignoredDirs: [...DEFAULT_SETTINGS.scan.ignoredDirs] },
    });
  };

  const test = async () => {
    const current = formRef.current;
    if (!current || testPendingRef.current) return;
    const snapshot = { ...current.ai };
    const token = draftRequests.begin();
    testPendingRef.current = true;
    setTesting(true);
    setDraftStatus(null);
    try {
      const result = await api.testAiWith(snapshot);
      if (mountedRef.current && draftRequests.isCurrent(token)) {
        setDraftStatus(result);
      }
    } catch (error) {
      if (mountedRef.current && draftRequests.isCurrent(token)) {
        setDraftStatus({
          ok: false,
          message: String(error),
          model: null,
          latencyMs: 0,
        });
      }
    } finally {
      if (draftRequests.isCurrent(token)) {
        testPendingRef.current = false;
        if (mountedRef.current) setTesting(false);
      }
    }
  };

  const statusMessage = draftStatus
    ? `Draft test: ${draftStatus.message}${draftStatus.latencyMs > 0 ? ` (${draftStatus.latencyMs} ms)` : ""}`
    : null;

  return (
    <ToolPage
      title="Settings"
      description="AI endpoint, scan defaults, and data sources"
      context={dirty ? <span className="text-[11px] font-medium text-warning">Unsaved changes</span> : undefined}
      actions={
        <>
          {saveState && (
            <span
              role={saveState.tone === "error" ? "alert" : "status"}
              className={`inline-flex max-w-52 items-center gap-1.5 text-[12px] ${ saveState.tone === "success" ? "text-success" : "text-error" }`}
            >
              {saveState.tone === "success" ? (
                <CheckCircle2 size={13} aria-hidden="true" />
              ) : (
                <XCircle size={13} aria-hidden="true" />
              )}
              <span className="truncate">{saveState.message}</span>
            </span>
          )}
          <button type="button" onClick={reset} className={secondaryButtonCls}>
            <RotateCcw size={13} aria-hidden="true" /> Reset
          </button>
          <button
            type="button"
            onClick={() => void save()}
            disabled={!dirty || saving}
            className={primaryButtonCls}
          >
            {saving ? (
              <Loader2 size={13} aria-hidden="true" className="animate-spin" />
            ) : (
              <Save size={13} aria-hidden="true" />
            )}
            {saving ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <div className="max-w-4xl space-y-4">
        <section className={sectionCls} aria-labelledby="ai-engine-title">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 id="ai-engine-title" className={sectionTitleCls}>
                <ShieldCheck size={15} aria-hidden="true" className="text-accent" />
                AI Engine
              </h2>
              <p className={sectionDescriptionCls}>
                Configure any OpenAI-compatible endpoint used by assistant features.
              </p>
            </div>
            <Switch
              checked={form.ai.enabled}
              onChange={(enabled) => updateAi({ enabled })}
              label="Enable AI engine"
            />
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <Field
              label="Base URL"
              htmlFor="ai-base-url"
              hint="Examples include OpenAI, Ollama, LM Studio, vLLM, Groq, and OpenRouter."
            >
              <Input
                id="ai-base-url"
                aria-describedby="ai-base-url-hint"
                value={form.ai.baseUrl}
                onChange={(event) => updateAi({ baseUrl: event.target.value })}
                placeholder="https://api.openai.com/v1"
              />
            </Field>
            <Field label="Model" htmlFor="ai-model">
              <Input
                id="ai-model"
                value={form.ai.model}
                onChange={(event) => updateAi({ model: event.target.value })}
                placeholder="gpt-4o-mini"
              />
            </Field>
            <Field
              label="API key"
              htmlFor="ai-api-key"
              hint="Stored in the local app configuration and sent only to this endpoint."
            >
              <Input
                id="ai-api-key"
                aria-describedby="ai-api-key-hint"
                type="password"
                autoComplete="off"
                value={form.ai.apiKey}
                onChange={(event) => updateAi({ apiKey: event.target.value })}
                placeholder="sk-…"
              />
            </Field>
            <Field label="Timeout (seconds)" htmlFor="ai-timeout">
              <Input
                id="ai-timeout"
                type="number"
                value={form.ai.timeoutSecs}
                min={10}
                max={600}
                onChange={(event) => updateAi({ timeoutSecs: Number(event.target.value) || 120 })}
              />
            </Field>
            <Field label={`Temperature — ${form.ai.temperature.toFixed(2)}`} htmlFor="ai-temperature">
              <input
                id="ai-temperature"
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={form.ai.temperature}
                onChange={(event) => updateAi({ temperature: Number(event.target.value) })}
                className="h-9 w-full accent-[var(--accent)]"
              />
            </Field>
            <Field label="Max tokens" htmlFor="ai-max-tokens">
              <Input
                id="ai-max-tokens"
                type="number"
                value={form.ai.maxTokens}
                min={256}
                max={8192}
                step={256}
                onChange={(event) => updateAi({ maxTokens: Number(event.target.value) || 2048 })}
              />
            </Field>
          </div>

          <div className="mt-3">
            <Field label="System prompt" htmlFor="ai-system-prompt">
              <Textarea
                id="ai-system-prompt"
                value={form.ai.systemPrompt}
                onChange={(event) => updateAi({ systemPrompt: event.target.value })}
                rows={4}
                className="selectable resize-y"
              />
            </Field>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => void test()}
              disabled={testing || !form.ai.baseUrl}
              className={secondaryButtonCls}
            >
              {testing ? (
                <Loader2 size={13} aria-hidden="true" className="animate-spin" />
              ) : (
                <CheckCircle2 size={13} aria-hidden="true" />
              )}
              {testing ? "Testing…" : "Test connection"}
            </button>
            {statusMessage && (
              <span
                role={draftStatus?.ok ? "status" : "alert"}
                className={`inline-flex items-center gap-1.5 text-[12px] ${ draftStatus?.ok ? "text-success" : "text-error" }`}
              >
                {draftStatus?.ok ? (
                  <CheckCircle2 size={13} aria-hidden="true" />
                ) : (
                  <XCircle size={13} aria-hidden="true" />
                )}
                {statusMessage}
              </span>
            )}
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-text-muted">
            This checks the current draft only. Assistant readiness continues to reflect saved settings.
          </p>
        </section>

        <section className={sectionCls} aria-labelledby="appearance-title">
          <h2 id="appearance-title" className={sectionTitleCls}>
            <Palette size={15} aria-hidden="true" className="text-accent" />
            Appearance
          </h2>
          <p className={sectionDescriptionCls}>
            Choose the workbench theme. &ldquo;System&rdquo; follows the OS colour scheme and
            updates live when it changes.
          </p>
          <div
            role="radiogroup"
            aria-labelledby="appearance-title"
            className="mt-3 flex flex-wrap items-center gap-2"
          >
            {THEME_PREFERENCES.map((preference) => {
              const Icon = THEME_ICON[preference];
              const selected = normalizeThemePreference(form.theme) === preference;
              return (
                <button
                  key={preference}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  onClick={() => applyTheme(preference)}
                  className={`inline-flex items-center gap-2 rounded-sm border px-3 py-2 text-[12px] font-medium capitalize transition-colors ${
                    selected
                      ? "border-accent-glow bg-accent-subtle text-accent"
                      : "border-border bg-surface-primary text-text-secondary hover:bg-surface-hover hover:text-text-primary"
                  }`}
                >
                  <Icon size={14} aria-hidden="true" />
                  {preference}
                </button>
              );
            })}
          </div>
        </section>

        <section className={sectionCls} aria-labelledby="scan-defaults-title">
          <h2 id="scan-defaults-title" className={sectionTitleCls}>
            <SlidersHorizontal size={15} aria-hidden="true" className="text-accent" />
            Scan Defaults
          </h2>
          <p className={sectionDescriptionCls}>Set the initial scope and limits for new local scans.</p>
          <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-2.5">
            <Switch checked={form.scan.scanSecrets} onChange={(scanSecrets) => update("scan", { ...form.scan, scanSecrets })} label="Secrets scanning" />
            <Switch checked={form.scan.scanVulnerabilities} onChange={(scanVulnerabilities) => update("scan", { ...form.scan, scanVulnerabilities })} label="Pattern scanning" />
            <Switch checked={form.scan.includeGit} onChange={(includeGit) => update("scan", { ...form.scan, includeGit })} label="Include .git" />
            <Switch checked={form.scan.followSymlinks} onChange={(followSymlinks) => update("scan", { ...form.scan, followSymlinks })} label="Follow symlinks" />
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <Field label="Max file size (KB)" htmlFor="scan-max-file-size">
              <Input
                id="scan-max-file-size"
                type="number"
                value={form.scan.maxFileSizeKb}
                min={1}
                max={10240}
                onChange={(event) => update("scan", { ...form.scan, maxFileSizeKb: Number(event.target.value) || 1024 })}
              />
            </Field>
          </div>
          <div className="mt-3">
            <Field
              label="Ignored directories"
              htmlFor="scan-ignored-directories"
              hint="Enter one directory name per line."
            >
              <Textarea
                id="scan-ignored-directories"
                aria-describedby="scan-ignored-directories-hint"
                value={form.scan.ignoredDirs.join("\n")}
                onChange={(event) =>
                update("scan", {
                ...form.scan,
                ignoredDirs: event.target.value.split("\n").map((item) => item.trim()).filter(Boolean),
                })
                }
                rows={4}
              />
            </Field>
          </div>
        </section>

        <section className={sectionCls} aria-labelledby="data-sources-title">
          <h2 id="data-sources-title" className={sectionTitleCls}>
            <Database size={15} aria-hidden="true" className="text-accent" />
            Data Sources
          </h2>
          <p className={sectionDescriptionCls}>Configure credentials used to enrich vulnerability results.</p>
          <div className="mt-3 max-w-xl">
            <Field
              label="NVD API key"
              htmlFor="nvd-api-key"
              hint="Optional. Raises the NVD rate limit from 5 to 50 requests per 30 seconds."
            >
              <Input
                id="nvd-api-key"
                aria-describedby="nvd-api-key-hint"
                type="password"
                autoComplete="off"
                value={form.nvdApiKey ?? ""}
                onChange={(event) => update("nvdApiKey", event.target.value || null)}
                placeholder="Get a key at nvd.nist.gov/developers"
              />
            </Field>
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-text-muted">
            Scanning stays on this machine. Keys are stored in the app configuration directory and sent only to the services you configure.
          </p>
        </section>

        <section className={sectionCls} aria-labelledby="binary-scanner-title">
          <h2 id="binary-scanner-title" className={sectionTitleCls}>
            <Binary size={15} aria-hidden="true" className="text-accent" />
            Binary Scanning
          </h2>
          <p className={sectionDescriptionCls}>
            Binary and firmware scanning runs{" "}
            <a
              href="https://github.com/ossf/cve-bin-tool"
              target="_blank"
              rel="noreferrer"
              className="text-accent underline underline-offset-2"
            >
              cve-bin-tool
            </a>
            , a separate GPL-3.0 program from the OpenSSF. oxAudit invokes a copy you install
            rather than bundling it, so it stays under its own licence.
          </p>
          <div className="mt-3">
            <Field
              label="cve-bin-tool path"
              htmlFor="binary-scanner-path"
              hint="Leave empty to find it on PATH, or fall back to `python3 -m cve_bin_tool`."
            >
              <Input
                id="binary-scanner-path"
                aria-describedby="binary-scanner-path-hint"
                value={form.binaryScannerPath ?? ""}
                onChange={(event) =>
                  update("binaryScannerPath", event.target.value.trim() || null)
                }
                placeholder="/opt/homebrew/bin/cve-bin-tool"
                className="font-mono text-[12px]"
              />
            </Field>
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-text-muted">
            Enabling this adds network calls to cve-bin-tool&rsquo;s own mirror (cveb.in) and
            the advisory feeds it aggregates, beyond the NVD, OSV and AI endpoints oxAudit
            contacts on its own.
          </p>
        </section>

        <section className={sectionCls} aria-labelledby="usage-title">
          <h2 id="usage-title" className={sectionTitleCls}>
            <Coins size={15} aria-hidden="true" className="text-accent" />
            Usage
          </h2>
          <p className={sectionDescriptionCls}>Lifetime AI token and estimated cost totals stored locally.</p>
          <div className="mt-3">
            {usageLoading ? (
              <InlineState tone="running" title="Loading usage" compact />
            ) : usageError ? (
              <InlineState tone="unavailable" title="Usage unavailable" description="The local usage summary could not be loaded." compact />
            ) : totalUsage && totalUsage.turns > 0 ? (
              <dl className="grid gap-2 sm:grid-cols-3">
                <UsageMetric label="Turns" value={totalUsage.turns.toLocaleString()} />
                <UsageMetric label="Tokens" value={totalUsage.totalTokens.toLocaleString()} />
                <UsageMetric label="Estimated cost" value={`$${totalUsage.costUsd.toFixed(4)}`} />
              </dl>
            ) : (
              <InlineState tone="empty" title="No AI usage recorded" description="Usage appears here after an AI-assisted task completes." compact />
            )}
          </div>
        </section>
      </div>
    </ToolPage>
  );
}

function UsageMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-sm border border-border bg-surface-secondary px-3 py-2.5">
      <dt className="text-[11px] font-medium uppercase tracking-[0.08em] text-text-muted">{label}</dt>
      <dd className="mt-1 text-[14px] font-semibold tabular-nums text-text-primary">{value}</dd>
    </div>
  );
}

const THEME_ICON: Record<ThemePreference, typeof Moon> = {
  dark: Moon,
  light: Sun,
  system: Monitor,
};

const sectionCls = "rounded-sm border border-border bg-surface-secondary p-4";
const sectionTitleCls = "flex items-center gap-2 text-[14px] font-semibold text-text-primary";
const sectionDescriptionCls = "mt-1 text-[12px] leading-relaxed text-text-muted";
const secondaryButtonCls =
  "inline-flex items-center gap-1.5 rounded-sm border border-border bg-surface-secondary px-3 py-2 text-[12px] font-medium text-text-secondary hover:bg-surface-hover hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-40";
const primaryButtonCls =
  "inline-flex items-center gap-1.5 rounded-sm bg-accent px-3.5 py-2 text-[12px] font-semibold text-accent-contrast hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-40";
