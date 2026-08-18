import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Coins,
  Database,
  Loader2,
  RotateCcw,
  Save,
  ShieldCheck,
  SlidersHorizontal,
  XCircle,
} from "lucide-react";
import { Field } from "../components/workbench/Field";
import { InlineState } from "../components/workbench/InlineState";
import { Switch } from "../components/workbench/Switch";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { DEFAULT_SYSTEM_PROMPT } from "../lib/defaults";
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
};

export function SettingsPage() {
  const settings = useAppStore((state) => state.settings);
  const setSettings = useAppStore((state) => state.setSettings);
  const setAiReady = useAppStore((state) => state.setAiReady);
  const push = useToastStore((state) => state.push);

  const [form, setForm] = useState<AppSettings | null>(settings);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [saveState, setSaveState] = useState<
    { tone: "success" | "error"; message: string } | null
  >(null);
  const [totalUsage, setTotalUsage] = useState<UsageSummary | null>(null);
  const [usageLoading, setUsageLoading] = useState(true);
  const [usageError, setUsageError] = useState(false);

  useEffect(() => {
    if (settings) setForm(settings);
  }, [settings]);

  useEffect(() => {
    api
      .getTotalUsage()
      .then((usage) => {
        setTotalUsage(usage);
        setUsageError(false);
      })
      .catch(() => setUsageError(true))
      .finally(() => setUsageLoading(false));
  }, []);

  if (!form) {
    return (
      <ToolPage title="Settings" description="AI endpoint, scan defaults, and data sources">
        <InlineState
          tone="running"
          title="Loading settings"
          description="Settings are unavailable until the local configuration has loaded."
          compact
        />
      </ToolPage>
    );
  }

  const update = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setForm({ ...form, [key]: value } as AppSettings);
    setDirty(true);
    setStatus(null);
    setSaveState(null);
  };

  const updateAi = (patch: Partial<AiSettings>) => {
    setForm({ ...form, ai: { ...form.ai, ...patch } });
    setDirty(true);
    setStatus(null);
    setSaveState(null);
  };

  const save = async () => {
    setSaving(true);
    setSaveState(null);
    try {
      await api.saveSettings(form);
      setSettings(form);
      setDirty(false);
      setSaveState({ tone: "success", message: "Settings saved" });
      if (form.ai.enabled && form.ai.baseUrl) {
        api
          .testAi()
          .then((result) => setAiReady(result.ok))
          .catch(() => setAiReady(false));
      } else {
        setAiReady(null);
      }
      push("success", "Settings saved");
    } catch (error) {
      const message = String(error);
      setSaveState({ tone: "error", message });
      push("error", message);
    } finally {
      setSaving(false);
    }
  };

  const reset = () => {
    setForm({
      ...DEFAULT_SETTINGS,
      ai: { ...DEFAULT_SETTINGS.ai },
      scan: { ...DEFAULT_SETTINGS.scan, ignoredDirs: [...DEFAULT_SETTINGS.scan.ignoredDirs] },
    });
    setDirty(true);
    setStatus(null);
    setSaveState(null);
  };

  const test = async () => {
    setTesting(true);
    setStatus(null);
    try {
      const result = await api.testAiWith(form.ai);
      setStatus(result);
      setAiReady(result.ok);
    } catch (error) {
      setStatus({ ok: false, message: String(error), model: null, latencyMs: 0 });
      setAiReady(false);
    } finally {
      setTesting(false);
    }
  };

  const statusMessage = status
    ? `${status.message}${status.latencyMs > 0 ? ` (${status.latencyMs} ms)` : ""}`
    : null;

  return (
    <ToolPage
      title="Settings"
      description="AI endpoint, scan defaults, and data sources"
      context={dirty ? <span className="text-[11px] font-medium text-amber-300">Unsaved changes</span> : undefined}
      actions={
        <>
          {saveState && (
            <span
              role={saveState.tone === "error" ? "alert" : "status"}
              className={`inline-flex max-w-52 items-center gap-1.5 text-[12px] ${
                saveState.tone === "success" ? "text-emerald-300" : "text-red-300"
              }`}
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
                <ShieldCheck size={15} aria-hidden="true" className="text-accent-400" />
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
              <input
                id="ai-base-url"
                aria-describedby="ai-base-url-hint"
                value={form.ai.baseUrl}
                onChange={(event) => updateAi({ baseUrl: event.target.value })}
                placeholder="https://api.openai.com/v1"
                className={inputCls}
              />
            </Field>
            <Field label="Model" htmlFor="ai-model">
              <input
                id="ai-model"
                value={form.ai.model}
                onChange={(event) => updateAi({ model: event.target.value })}
                placeholder="gpt-4o-mini"
                className={inputCls}
              />
            </Field>
            <Field
              label="API key"
              htmlFor="ai-api-key"
              hint="Stored in the local app configuration and sent only to this endpoint."
            >
              <input
                id="ai-api-key"
                aria-describedby="ai-api-key-hint"
                type="password"
                autoComplete="off"
                value={form.ai.apiKey}
                onChange={(event) => updateAi({ apiKey: event.target.value })}
                placeholder="sk-…"
                className={inputCls}
              />
            </Field>
            <Field label="Timeout (seconds)" htmlFor="ai-timeout">
              <input
                id="ai-timeout"
                type="number"
                value={form.ai.timeoutSecs}
                min={10}
                max={600}
                onChange={(event) => updateAi({ timeoutSecs: Number(event.target.value) || 120 })}
                className={inputCls}
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
                className="h-9 w-full accent-[var(--color-accent-500)]"
              />
            </Field>
            <Field label="Max tokens" htmlFor="ai-max-tokens">
              <input
                id="ai-max-tokens"
                type="number"
                value={form.ai.maxTokens}
                min={256}
                max={8192}
                step={256}
                onChange={(event) => updateAi({ maxTokens: Number(event.target.value) || 2048 })}
                className={inputCls}
              />
            </Field>
          </div>

          <div className="mt-3">
            <Field label="System prompt" htmlFor="ai-system-prompt">
              <textarea
                id="ai-system-prompt"
                value={form.ai.systemPrompt}
                onChange={(event) => updateAi({ systemPrompt: event.target.value })}
                rows={4}
                className={`${inputCls} selectable resize-y`}
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
                role={status?.ok ? "status" : "alert"}
                className={`inline-flex items-center gap-1.5 text-[12px] ${
                  status?.ok ? "text-emerald-300" : "text-red-300"
                }`}
              >
                {status?.ok ? (
                  <CheckCircle2 size={13} aria-hidden="true" />
                ) : (
                  <XCircle size={13} aria-hidden="true" />
                )}
                {statusMessage}
              </span>
            )}
          </div>
        </section>

        <section className={sectionCls} aria-labelledby="scan-defaults-title">
          <h2 id="scan-defaults-title" className={sectionTitleCls}>
            <SlidersHorizontal size={15} aria-hidden="true" className="text-accent-400" />
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
              <input
                id="scan-max-file-size"
                type="number"
                value={form.scan.maxFileSizeKb}
                min={1}
                max={10240}
                onChange={(event) => update("scan", { ...form.scan, maxFileSizeKb: Number(event.target.value) || 1024 })}
                className={inputCls}
              />
            </Field>
          </div>
          <div className="mt-3">
            <Field
              label="Ignored directories"
              htmlFor="scan-ignored-directories"
              hint="Enter one directory name per line."
            >
              <textarea
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
                className={`${inputCls} selectable resize-y font-mono text-[12px]`}
              />
            </Field>
          </div>
        </section>

        <section className={sectionCls} aria-labelledby="data-sources-title">
          <h2 id="data-sources-title" className={sectionTitleCls}>
            <Database size={15} aria-hidden="true" className="text-accent-400" />
            Data Sources
          </h2>
          <p className={sectionDescriptionCls}>Configure credentials used to enrich vulnerability results.</p>
          <div className="mt-3 max-w-xl">
            <Field
              label="NVD API key"
              htmlFor="nvd-api-key"
              hint="Optional. Raises the NVD rate limit from 5 to 50 requests per 30 seconds."
            >
              <input
                id="nvd-api-key"
                aria-describedby="nvd-api-key-hint"
                type="password"
                autoComplete="off"
                value={form.nvdApiKey ?? ""}
                onChange={(event) => update("nvdApiKey", event.target.value || null)}
                placeholder="Get a key at nvd.nist.gov/developers"
                className={inputCls}
              />
            </Field>
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-stone-400">
            Scanning stays on this machine. Keys are stored in the app configuration directory and sent only to the services you configure.
          </p>
        </section>

        <section className={sectionCls} aria-labelledby="usage-title">
          <h2 id="usage-title" className={sectionTitleCls}>
            <Coins size={15} aria-hidden="true" className="text-accent-400" />
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
    <div className="rounded-md border border-ink-700 bg-ink-900 px-3 py-2.5">
      <dt className="text-[11px] font-medium uppercase tracking-[0.08em] text-stone-400">{label}</dt>
      <dd className="mt-1 text-[14px] font-semibold tabular-nums text-stone-100">{value}</dd>
    </div>
  );
}

const inputCls =
  "w-full rounded-md border border-ink-600 bg-ink-950 px-3 py-2 text-[13px] text-stone-200 placeholder:text-stone-500 focus:border-accent-500/70";
const sectionCls = "rounded-lg border border-ink-700 bg-ink-850 p-4";
const sectionTitleCls = "flex items-center gap-2 text-[14px] font-semibold text-stone-100";
const sectionDescriptionCls = "mt-1 text-[12px] leading-relaxed text-stone-400";
const secondaryButtonCls =
  "inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-900 px-3 py-2 text-[12px] font-medium text-stone-300 hover:bg-ink-800 hover:text-stone-100 disabled:cursor-not-allowed disabled:opacity-40";
const primaryButtonCls =
  "inline-flex items-center gap-1.5 rounded-md bg-accent-500 px-3.5 py-2 text-[12px] font-semibold text-ink-950 hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-40";
