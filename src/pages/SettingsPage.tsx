import { useEffect, useState } from "react";
import { CheckCircle2, Coins, Loader2, RotateCcw, Save, ShieldCheck, XCircle } from "lucide-react";
import { TopBar } from "../components/TopBar";
import { api } from "../lib/api";
import { DEFAULT_SYSTEM_PROMPT } from "../lib/defaults";
import { useAppStore, useToastStore } from "../lib/stores";
import type { AiSettings, AiStatus, AppSettings, UsageSummary } from "../lib/types";

export function SettingsPage() {
  const settings = useAppStore((s) => s.settings);
  const setSettings = useAppStore((s) => s.setSettings);
  const setAiReady = useAppStore((s) => s.setAiReady);
  const push = useToastStore((s) => s.push);

  const [form, setForm] = useState<AppSettings | null>(settings);
  const [dirty, setDirty] = useState(false);
  const [testing, setTesting] = useState(false);
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [totalUsage, setTotalUsage] = useState<UsageSummary | null>(null);

  useEffect(() => {
    if (settings) setForm(settings);
  }, [settings]);

  useEffect(() => {
    api
      .getTotalUsage()
      .then(setTotalUsage)
      .catch(() => undefined);
  }, []);

  if (!form) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-6">
        <TopBar title="Settings" subtitle="Loading…" />
      </div>
    );
  }

  const update = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setForm({ ...form, [key]: value } as AppSettings);
    setDirty(true);
    setStatus(null);
  };
  const updateAi = (patch: Partial<AiSettings>) => {
    setForm({ ...form, ai: { ...form.ai, ...patch } });
    setDirty(true);
    setStatus(null);
  };

  const save = async () => {
    try {
      await api.saveSettings(form);
      setSettings(form);
      setDirty(false);
      if (form.ai.enabled && form.ai.baseUrl) {
        api
          .testAi()
          .then((s) => setAiReady(s.ok))
          .catch(() => setAiReady(false));
      } else {
        setAiReady(null);
      }
      push("success", "Settings saved");
    } catch (e) {
      push("error", String(e));
    }
  };

  const reset = () => {
    const fresh: AppSettings = {
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
    setForm(fresh);
    setDirty(true);
  };

  const test = async () => {
    setTesting(true);
    setStatus(null);
    try {
      const s = await api.testAiWith(form.ai);
      setStatus(s);
      setAiReady(s.ok);
    } catch (e) {
      setStatus({ ok: false, message: String(e), model: null, latencyMs: 0 });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="mx-auto max-w-3xl px-6 py-6">
      <TopBar
        title="Settings"
        subtitle="AI endpoint, scan defaults, and data sources"
        actions={
          <>
            <button
              onClick={reset}
              className="inline-flex items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
            >
              <RotateCcw size={13} /> Reset
            </button>
            <button
              onClick={save}
              disabled={!dirty}
              className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 px-4 py-1.5 text-xs font-bold text-ink-950 shadow-lg shadow-teal-900/30 hover:opacity-90 disabled:opacity-40"
            >
              <Save size={13} /> Save settings
            </button>
          </>
        }
      />

      {/* AI */}
      <section className="mt-5 rounded-xl border border-ink-700 bg-ink-850 p-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <ShieldCheck size={15} className="text-teal-400" /> AI engine
            </h2>
            <p className="mt-0.5 text-[11px] text-slate-500">
              Any OpenAI-compatible API — OpenAI, Ollama, LM Studio, vLLM, Groq, OpenRouter…
            </p>
          </div>
          <Toggle checked={form.ai.enabled} onChange={(v) => updateAi({ enabled: v })} label="" />
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Field label="Base URL">
            <input
              value={form.ai.baseUrl}
              onChange={(e) => updateAi({ baseUrl: e.target.value })}
              placeholder="https://api.openai.com/v1"
              className={inputCls}
            />
          </Field>
          <Field label="Model">
            <input
              value={form.ai.model}
              onChange={(e) => updateAi({ model: e.target.value })}
              placeholder="gpt-4o-mini"
              className={inputCls}
            />
          </Field>
          <Field label="API key">
            <input
              type="password"
              value={form.ai.apiKey}
              onChange={(e) => updateAi({ apiKey: e.target.value })}
              placeholder="sk-…"
              className={inputCls}
            />
          </Field>
          <Field label="Timeout (seconds)">
            <input
              type="number"
              value={form.ai.timeoutSecs}
              min={10}
              max={600}
              onChange={(e) => updateAi({ timeoutSecs: Number(e.target.value) || 120 })}
              className={inputCls}
            />
          </Field>
          <Field label={`Temperature — ${form.ai.temperature.toFixed(2)}`}>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={form.ai.temperature}
              onChange={(e) => updateAi({ temperature: Number(e.target.value) })}
              className="w-full accent-teal-500"
            />
          </Field>
          <Field label="Max tokens">
            <input
              type="number"
              value={form.ai.maxTokens}
              min={256}
              max={8192}
              step={256}
              onChange={(e) => updateAi({ maxTokens: Number(e.target.value) || 2048 })}
              className={inputCls}
            />
          </Field>
        </div>

        <Field label="System prompt" className="mt-3">
          <textarea
            value={form.ai.systemPrompt}
            onChange={(e) => updateAi({ systemPrompt: e.target.value })}
            rows={4}
            className={`${inputCls} selectable resize-y`}
          />
        </Field>

        <div className="mt-4 flex items-center gap-2">
          <button
            onClick={test}
            disabled={testing || !form.ai.baseUrl}
            className="inline-flex items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-750 px-3.5 py-2 text-xs font-medium text-slate-200 hover:border-ink-500 disabled:opacity-40"
          >
            {testing ? <Loader2 size={13} className="animate-spin" /> : <CheckCircle2 size={13} />}
            {testing ? "Testing…" : "Test connection"}
          </button>
          {status && (
            <span
              className={`inline-flex items-center gap-1.5 text-xs ${
                status.ok ? "text-emerald-400" : "text-red-400"
              }`}
            >
              {status.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
              {status.message} {status.latencyMs > 0 && `(${status.latencyMs} ms)`}
            </span>
          )}
        </div>

        {totalUsage && totalUsage.turns > 0 && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-900 px-3.5 py-2.5 text-xs text-slate-400">
            <Coins size={14} className="text-teal-400" />
            <span>
              Total AI usage: <span className="font-semibold text-slate-200">{totalUsage.turns}</span>{" "}
              turns ·{" "}
              <span className="font-semibold text-slate-200">
                {(totalUsage.totalTokens / 1000).toFixed(1)}k
              </span>{" "}
              tokens ·{" "}
              <span className="font-semibold text-slate-200">
                ${totalUsage.costUsd.toFixed(4)}
              </span>
            </span>
          </div>
        )}
      </section>

      {/* Scan defaults */}
      <section className="mt-4 rounded-xl border border-ink-700 bg-ink-850 p-5">
        <h2 className="text-sm font-semibold text-slate-100">Scan defaults</h2>
        <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-2">
          <Toggle checked={form.scan.scanSecrets} onChange={(v) => update("scan", { ...form.scan, scanSecrets: v })} label="Secrets scanning" />
          <Toggle checked={form.scan.scanVulnerabilities} onChange={(v) => update("scan", { ...form.scan, scanVulnerabilities: v })} label="Pattern scanning" />
          <Toggle checked={form.scan.includeGit} onChange={(v) => update("scan", { ...form.scan, includeGit: v })} label="Include .git" />
          <Toggle checked={form.scan.followSymlinks} onChange={(v) => update("scan", { ...form.scan, followSymlinks: v })} label="Follow symlinks" />
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Field label="Max file size (KB)">
            <input
              type="number"
              value={form.scan.maxFileSizeKb}
              min={1}
              max={10240}
              onChange={(e) => update("scan", { ...form.scan, maxFileSizeKb: Number(e.target.value) || 1024 })}
              className={inputCls}
            />
          </Field>
          <Field label="NVD API key (optional — raises rate limit from 5 to 50 req/30s)">
            <input
              type="password"
              value={form.nvdApiKey ?? ""}
              onChange={(e) => update("nvdApiKey", e.target.value || null)}
              placeholder="Get one at nvd.nist.gov/developers"
              className={inputCls}
            />
          </Field>
        </div>
        <Field label="Ignored directories (one per line)" className="mt-3">
          <textarea
            value={form.scan.ignoredDirs.join("\n")}
            onChange={(e) =>
              update("scan", {
                ...form.scan,
                ignoredDirs: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean),
              })
            }
            rows={4}
            className={`${inputCls} selectable resize-y font-mono text-[11px]`}
          />
        </Field>
      </section>

      <p className="mt-4 text-center text-[11px] text-slate-600">
        All scanning happens locally on this machine. API keys are stored in the app config
        directory and only sent to the endpoints you configure.
      </p>
    </div>
  );
}

const inputCls =
  "w-full rounded-lg border border-ink-600 bg-ink-900 px-3 py-2 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60";

function Field({ label, children, className = "" }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <label className={`block ${className}`}>
      <span className="mb-1 block text-[11px] font-medium text-slate-500">{label}</span>
      {children}
    </label>
  );
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-300">
      <button
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative h-4 w-7 rounded-full transition-colors ${checked ? "bg-teal-500" : "bg-ink-600"}`}
      >
        <span
          className={`absolute top-0.5 h-3 w-3 rounded-full bg-white transition-all ${checked ? "left-3.5" : "left-0.5"}`}
        />
      </button>
      {label}
    </label>
  );
}
