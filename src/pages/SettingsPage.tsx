import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type JSX } from "react";
import { CheckCircle2, Loader2, Monitor, Moon, RotateCcw, Save, ShieldCheck, Sun, XCircle } from "lucide-react";
import { version as appVersion } from "../../package.json";
import { InlineState } from "../components/workbench/InlineState";
import { Button, Input, Select, SettingsGroup, SettingsItem, Switch, Textarea } from "../components/ui";
import { useHeaderActions, type HeaderAction } from "../lib/headerActions";
import { settingsSection as findSettingsSection } from "../lib/settingsSections";
import { api } from "../lib/api";
import { errorMessage } from "../lib/commandError";
import { serverMode } from "../lib/transport";
import { normalizeThemePreference, THEME_PREFERENCES, type ThemePreference } from "../lib/theme";
import { DEFAULT_SYSTEM_PROMPT } from "../lib/defaults";
import { requestReadinessWizard } from "../lib/readinessWizard";
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
import type { AiSettings, AiStatus, AppSettings, LiveScanSettings, UsageSummary } from "../lib/types";

/** Mirrors `LiveScanSettings::default()` in src-tauri/src/models.rs. */
const DEFAULT_LIVE_SCAN_SETTINGS: LiveScanSettings = {
  requestsPerSecond: 50,
  perHostConcurrency: 10,
  timeoutSeconds: 10,
  maxResponseKb: 4096,
  maxRequests: 100000,
  proxy: null,
};

const DEFAULT_SETTINGS: AppSettings = {
  editor: "system",
  ai: {
    enabled: false,
    baseUrl: "https://api.openai.com/v1",
    model: "gpt-4o-mini",
    temperature: 0.2,
    timeoutSecs: 120,
    maxTokens: 2048,
    contextWindow: 128000,
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
  credentials: { aiApiKey: false, nvdApiKey: false },
  theme: "dark",
  binaryScannerPath: null,
  binaryScannerRuntime: "auto",
  grypePath: null,
  agentAllowedFetchHosts: [],
  liveScan: { ...DEFAULT_LIVE_SCAN_SETTINGS },
};

type LiveNumberFieldKey = "liveRequestsPerSecond" | "livePerHostConcurrency" | "liveTimeoutSeconds" | "liveMaxResponseKb" | "liveMaxRequests";
type NumberFieldKey = "timeoutSecs" | "maxTokens" | "contextWindow" | "maxFileSizeKb" | LiveNumberFieldKey;
type ListFieldKey = "agentAllowedFetchHosts" | "ignoredDirs";
type RawFieldKey = NumberFieldKey | ListFieldKey | "liveProxy";

/** Which `settings.liveScan` property each live-scanning number field edits. */
const LIVE_FIELD_PROP: Record<LiveNumberFieldKey, Exclude<keyof LiveScanSettings, "proxy">> = {
  liveRequestsPerSecond: "requestsPerSecond",
  livePerHostConcurrency: "perHostConcurrency",
  liveTimeoutSeconds: "timeoutSeconds",
  liveMaxResponseKb: "maxResponseKb",
  liveMaxRequests: "maxRequests",
};

/** An explicit proxy must be an http or https URL without embedded credentials. */
export function validateProxyUrl(raw: string): string | null {
  const text = raw.trim();
  if (!text) return null;
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    return "Enter a full http:// or https:// URL, for example http://127.0.0.1:8080.";
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "The proxy must use http:// or https://.";
  if (parsed.username || parsed.password) return "Credentials in the proxy URL are not accepted. Configure the proxy to allow this machine instead.";
  return null;
}

/** Bounds a number field must satisfy before the draft can be saved. */
const NUMBER_BOUNDS: Record<NumberFieldKey, { min: number; max: number }> = {
  timeoutSecs: { min: 10, max: 600 },
  maxTokens: { min: 256, max: 8192 },
  contextWindow: { min: 4096, max: 2_000_000 },
  maxFileSizeKb: { min: 1, max: 10240 },
  liveRequestsPerSecond: { min: 1, max: 1000 },
  livePerHostConcurrency: { min: 1, max: 100 },
  liveTimeoutSeconds: { min: 1, max: 120 },
  liveMaxResponseKb: { min: 1, max: 32768 },
  liveMaxRequests: { min: 1, max: 1_000_000_000 },
};

/** Parses a non-negative whole number within bounds, or explains why not. */
export function parseBoundedInteger(
  raw: string,
  { min, max }: { min: number; max: number },
): { value: number; error: null } | { value: null; error: string } {
  const text = raw.trim();
  const value = /^\d+$/.test(text) ? Number(text) : Number.NaN;
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    return { value: null, error: `Enter a whole number between ${min.toLocaleString("en-US")} and ${max.toLocaleString("en-US")}.` };
  }
  return { value, error: null };
}

const LIVE_FIELDS: Array<{ key: LiveNumberFieldKey; id: string; label: string; hint: string }> = [
  { key: "liveRequestsPerSecond", id: "live-requests-per-second", label: "Requests per second", hint: "Across the whole run, 1 to 1,000." },
  { key: "livePerHostConcurrency", id: "live-per-host-concurrency", label: "Concurrent requests per host", hint: "Requests in flight to one host, 1 to 100." },
  { key: "liveTimeoutSeconds", id: "live-timeout-seconds", label: "Request timeout (seconds)", hint: "One request, 1 to 120 seconds." },
  { key: "liveMaxResponseKb", id: "live-max-response-kb", label: "Max response size (KiB)", hint: "Larger responses are cut off, 1 to 32,768 KiB." },
  { key: "liveMaxRequests", id: "live-max-requests", label: "Max requests per run", hint: "Reaching it ends the run as incomplete." },
];

/** One entry per non-blank line, trimmed. */
export function parseLineList(raw: string): string[] {
  return raw.split("\n").map((item) => item.trim()).filter(Boolean);
}

function cloneSettings(settings: AppSettings): AppSettings {
  return {
    ...settings,
    editor: settings.editor ?? "system",
    ai: { ...settings.ai },
    credentials: { ...settings.credentials },
    scan: {
      ...settings.scan,
      ignoredDirs: [...settings.scan.ignoredDirs],
    },
    agentAllowedFetchHosts: [...(settings.agentAllowedFetchHosts ?? [])],
    // A store loaded before the field existed gets the defaults.
    liveScan: { ...DEFAULT_LIVE_SCAN_SETTINGS, ...settings.liveScan },
  };
}

export function SettingsPage() {
  const settings = useAppStore((state) => state.settings);
  const setSettings = useAppStore((state) => state.setSettings);
  const setAiReadiness = useAppStore((state) => state.setAiReadiness);
  const settingsLoadError = useAppStore((state) => state.settingsLoadError);
  const setSettingsLoadError = useAppStore((state) => state.setSettingsLoadError);
  const push = useToastStore((state) => state.push);
  const sectionId = useAppStore((state) => state.settingsSection);

  const [diagnostics, setDiagnostics] = useState<string | null>(null);
  const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [form, setForm] = useState<AppSettings | null>(() =>
    settings ? cloneSettings(settings) : null,
  );
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [aiApiKeyDraft, setAiApiKeyDraft] = useState("");
  const [nvdApiKeyDraft, setNvdApiKeyDraft] = useState("");
  const [removeAiApiKey, setRemoveAiApiKey] = useState(false);
  const [removeNvdApiKey, setRemoveNvdApiKey] = useState(false);
  const [draftStatus, setDraftStatus] = useState<AiStatus | null>(null);
  const [saveState, setSaveState] = useState<
    { tone: "success" | "error"; message: string } | null
  >(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Raw text of fields being edited. List and number inputs show this text
  // instead of the parsed draft so typing a newline, a trailing space, or an
  // empty/partial number is not rewritten under the cursor.
  const [rawFields, setRawFields] = useState<Partial<Record<RawFieldKey, string>>>({});
  const [totalUsage, setTotalUsage] = useState<UsageSummary | null>(null);
  const [usageLoading, setUsageLoading] = useState(true);
  const [usageError, setUsageError] = useState(false);
  const formRef = useRef<AppSettings | null>(form);
  const formInitializedRef = useRef(form !== null);
  const editRevisionRef = useRef(0);
  const themeRevisionRef = useRef(0);
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
    setRawFields({});
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
      if (mountedRef.current) setLoadError(errorMessage(error));
    }
  };

  if (!form) {
    return (
      <div className="w-full animate-fade-in px-4 pb-10 pt-4 md:px-6 md:pt-6">
        <div>
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
                <Button type="button" variant="warning" onClick={() => void retryLoad()}>
                  Retry
                </Button>
              ) : undefined
            }
            compact
          />
        </div>
      </div>
    );
  }

  const publishDraft = (next: AppSettings) => {
    if (formRef.current?.theme !== next.theme) themeRevisionRef.current += 1;
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

  const publishCredentialDraft = () => {
    editRevisionRef.current += 1;
    setDirty(true);
    draftRequests.invalidate();
    testPendingRef.current = false;
    setTesting(false);
    setDraftStatus(null);
    setSaveState(null);
  };

  const credentialMutation = (draft: string, remove: boolean) => {
    if (remove) return { action: "delete" } as const;
    const value = draft.trim();
    return value
      ? ({ action: "replace", value } as const)
      : ({ action: "unchanged" } as const);
  };

  const applyTheme = (preference: ThemePreference) => {
    const current = formRef.current ?? form;
    if (!current || current.theme === preference) return;

    // Mirror into the draft first so `dirty` never reports a phantom theme
    // diff, then persist. Theme cannot affect AI readiness, so this write
    // skips the connection test a full save performs.
    const next = { ...current, theme: preference };
    const themeRevision = ++themeRevisionRef.current;
    formRef.current = next;
    setForm(next);

    void savePersistedThemePreference(
      () => useAppStore.getState().settings,
      preference,
      setSettings,
    ).then(persisted => {
      if (!persisted || !mountedRef.current || themeRevision !== themeRevisionRef.current) return;
      const draft = formRef.current;
      if (!draft) return;
      const updated = { ...draft, theme: persisted.theme };
      formRef.current = updated;
      setForm(updated);
    }).catch(() => {
      if (mountedRef.current && themeRevision === themeRevisionRef.current) {
        const draft = formRef.current;
        const persisted = useAppStore.getState().settings;
        if (draft && persisted) {
          const restored = { ...draft, theme: persisted.theme };
          formRef.current = restored;
          setForm(restored);
        }
      }
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
    if (!current || savePendingRef.current || hasFieldErrors) return;
    const snapshot = cloneSettings(current);
    const credentials = {
      aiApiKey: credentialMutation(aiApiKeyDraft, removeAiApiKey),
      nvdApiKey: credentialMutation(nvdApiKeyDraft, removeNvdApiKey),
    };
    const submittedRevision = editRevisionRef.current;
    const submittedThemeRevision = themeRevisionRef.current;
    savePendingRef.current = true;
    setSaving(true);
    setSaveState(null);
    try {
      const publication = await savePersistedSettingsSnapshot(
        snapshot,
        setSettings,
        setAiReadiness,
        {},
        credentials,
      );
      if (!publication) return;
      setSettingsLoadError(false);
      void publication.readiness;

      if (mountedRef.current) {
        const hasNewerEdits = editRevisionRef.current !== submittedRevision;
        if (!hasNewerEdits) {
          const persisted = cloneSettings(publication.settings);
          if (themeRevisionRef.current !== submittedThemeRevision) {
            persisted.theme = formRef.current?.theme ?? persisted.theme;
          }
          formRef.current = persisted;
          setForm(persisted);
          setRawFields({});
          setAiApiKeyDraft("");
          setNvdApiKeyDraft("");
          setRemoveAiApiKey(false);
          setRemoveNvdApiKey(false);
        }
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
      const message = errorMessage(error, "Settings could not be saved.");
      setSaveState({ tone: "error", message });
    } finally {
      savePendingRef.current = false;
      if (mountedRef.current) setSaving(false);
    }
  };

  const reset = () => {
    const current = formRef.current ?? form;
    setRawFields({});
    publishDraft({
      ...DEFAULT_SETTINGS,
      ai: { ...DEFAULT_SETTINGS.ai },
      credentials: { ...current.credentials },
      scan: { ...DEFAULT_SETTINGS.scan, ignoredDirs: [...DEFAULT_SETTINGS.scan.ignoredDirs] },
    });
  };

  const gatherDiagnostics = async () => {
    setDiagnosticsError(null);
    setCopied(false);
    try {
      const report = await api.collectDiagnostics();
      const text = [
        `oxAudit ${report.version} on ${report.os}/${report.architecture}`,
        `AI endpoint configured: ${report.aiConfigured ? "yes" : "no"}`,
        `Log: ${report.logPath ?? "not running"} (${report.logBytes} bytes)`,
        "",
        ...report.notes.map((note) => `Note: ${note}`),
        "",
        "--- log tail ---",
        report.logTail || "(empty)",
      ].join("\n");
      setDiagnostics(text);
      try {
        await navigator.clipboard.writeText(text);
        setCopied(true);
      } catch {
        // Clipboard access can be refused; the text is on screen either way.
        setCopied(false);
      }
    } catch (error) {
      setDiagnosticsError(errorMessage(error));
    }
  };

  const test = async () => {
    const current = formRef.current;
    if (!current || testPendingRef.current) return;
    const snapshot = { ...current.ai };
    const aiApiKey = credentialMutation(aiApiKeyDraft, removeAiApiKey);
    const token = draftRequests.begin();
    testPendingRef.current = true;
    setTesting(true);
    setDraftStatus(null);
    try {
      const result = await api.testAiWith({ settings: snapshot, aiApiKey });
      if (mountedRef.current && draftRequests.isCurrent(token)) {
        setDraftStatus(result);
      }
    } catch (error) {
      if (mountedRef.current && draftRequests.isCurrent(token)) {
        setDraftStatus({
          ok: false,
          message: errorMessage(error, "The connection test failed."),
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

  const fieldErrors: Partial<Record<NumberFieldKey, string>> = {};
  for (const key of Object.keys(NUMBER_BOUNDS) as NumberFieldKey[]) {
    const raw = rawFields[key];
    if (raw === undefined) continue;
    const parsed = parseBoundedInteger(raw, NUMBER_BOUNDS[key]);
    if (parsed.error) fieldErrors[key] = parsed.error;
  }
  const proxyError = rawFields.liveProxy === undefined ? null : validateProxyUrl(rawFields.liveProxy);
  const hasFieldErrors = Object.keys(fieldErrors).length > 0 || proxyError !== null;

  const setRawField = (key: RawFieldKey, raw: string) =>
    setRawFields((fields) => ({ ...fields, [key]: raw }));

  /** Drop raw text once it is valid so the field shows the normalized value. */
  const settleRawField = (key: RawFieldKey) => {
    setRawFields((fields) => {
      const raw = fields[key];
      if (raw === undefined) return fields;
      if (key in NUMBER_BOUNDS && parseBoundedInteger(raw, NUMBER_BOUNDS[key as NumberFieldKey]).error) {
        return fields;
      }
      if (key === "liveProxy" && validateProxyUrl(raw)) return fields;
      const next = { ...fields };
      delete next[key];
      return next;
    });
  };

  const editNumber = (key: NumberFieldKey, raw: string) => {
    setRawField(key, raw);
    const parsed = parseBoundedInteger(raw, NUMBER_BOUNDS[key]);
    const current = formRef.current ?? form;
    if (parsed.value === null) {
      // Keep the last valid draft value; the inline error blocks saving.
      publishDraft(current);
      return;
    }
    if (key === "maxFileSizeKb") {
      publishDraft({ ...current, scan: { ...current.scan, maxFileSizeKb: parsed.value } });
    } else if (key in LIVE_FIELD_PROP) {
      publishDraft({ ...current, liveScan: { ...current.liveScan, [LIVE_FIELD_PROP[key as LiveNumberFieldKey]]: parsed.value } });
    } else {
      publishDraft({ ...current, ai: { ...current.ai, [key as "timeoutSecs" | "maxTokens" | "contextWindow"]: parsed.value } });
    }
  };

  const editProxy = (raw: string) => {
    setRawField("liveProxy", raw);
    const current = formRef.current ?? form;
    if (validateProxyUrl(raw)) {
      publishDraft(current);
      return;
    }
    publishDraft({ ...current, liveScan: { ...current.liveScan, proxy: raw.trim() || null } });
  };

  const numberInputProps = (key: NumberFieldKey, value: number) => ({
    type: "number",
    inputMode: "numeric" as const,
    min: NUMBER_BOUNDS[key].min,
    max: NUMBER_BOUNDS[key].max,
    value: rawFields[key] ?? String(value),
    "aria-invalid": fieldErrors[key] ? true : undefined,
    onChange: (event: ChangeEvent<HTMLInputElement>) => editNumber(key, event.target.value),
    onBlur: () => settleRawField(key),
  });

  const editList = (key: ListFieldKey, raw: string) => {
    setRawField(key, raw);
    const current = formRef.current ?? form;
    const items = parseLineList(raw);
    if (key === "ignoredDirs") publishDraft({ ...current, scan: { ...current.scan, ignoredDirs: items } });
    else publishDraft({ ...current, agentAllowedFetchHosts: items });
  };

  const statusMessage = draftStatus
    ? `Draft test: ${draftStatus.message}${draftStatus.latencyMs > 0 ? ` (${draftStatus.latencyMs} ms)` : ""}`
    : null;

  const section = findSettingsSection(sectionId).id;
  const numberField = (key: NumberFieldKey, value: number, extra?: { step?: number }) => ({
    ...numberInputProps(key, value),
    ...(extra?.step ? { step: extra.step } : {}),
    className: "!w-28 shrink-0 text-right tabular-nums",
  });

  const credentialRow = (opts: {
    id: string;
    title: string;
    description: string;
    draft: string;
    setDraft: (value: string) => void;
    stored: boolean;
    remove: boolean;
    setRemove: (updater: (value: boolean) => boolean) => void;
    placeholder: string;
    storedPlaceholder: string;
    setRemoveFalse: () => void;
  }) => (
    <SettingsItem title={opts.title} description={opts.description} htmlFor={opts.id} stacked>
      <div className="flex gap-2">
        <Input
          id={opts.id}
          aria-describedby={`${opts.id}-hint`}
          type="password"
          autoComplete="new-password"
          value={opts.draft}
          disabled={opts.remove}
          onChange={(event) => {
            opts.setDraft(event.target.value);
            opts.setRemoveFalse();
            publishCredentialDraft();
          }}
          placeholder={opts.stored ? opts.storedPlaceholder : opts.placeholder}
        />
        {opts.stored && (
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              opts.setRemove((value) => !value);
              opts.setDraft("");
              publishCredentialDraft();
            }}
          >
            {opts.remove ? "Keep" : "Remove"}
          </Button>
        )}
      </div>
    </SettingsItem>
  );

  const general = (
    <>
      <SettingsGroup title="Editor" description="Choose where finding files open. Save to apply this preference.">
        <SettingsItem
          title="Preferred editor"
          description="VS Code must register its vscode URL handler; its command-line launcher is not required. Errors stay visible if the handler is unavailable. Positions use the current saved file, which may have changed since scanning."
          htmlFor="preferred-editor"
        >
          <Select
            id="preferred-editor"
            className="w-60"
            value={form.editor}
            onChange={(event) => update("editor", event.target.value as AppSettings["editor"])}
          >
            <option value="system">System opener (file only)</option>
            <option value="vscode">Visual Studio Code (line and column)</option>
          </Select>
        </SettingsItem>
      </SettingsGroup>
      <SettingsGroup
        title="Appearance"
        description={"Choose the workbench theme. “System” follows the OS colour scheme and updates live when it changes."}
      >
        <SettingsItem title="Theme" description="Applies immediately; it is not part of Save.">
          <div
            role="radiogroup"
            aria-label="Theme"
            className="inline-flex h-9 items-center gap-0.5 rounded-md border border-control-border bg-surface-primary p-[3px] transition-colors hover:border-text-muted"
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
                  className={`inline-flex h-7 items-center gap-1.5 rounded-sm px-2.5 text-[12px] font-medium capitalize transition-colors ${
                    selected
                      ? "bg-accent-subtle text-accent"
                      : "text-text-secondary hover:bg-surface-hover hover:text-text-primary"
                  }`}
                >
                  <Icon size={13} aria-hidden="true" />
                  {preference}
                </button>
              );
            })}
          </div>
        </SettingsItem>
      </SettingsGroup>
    </>
  );

  const usage = (
    <SettingsGroup title="Usage" description="Lifetime AI token and estimated cost totals stored locally.">
      {usageLoading ? (
        <p role="status" className="px-3.5 py-3 text-[12px] text-text-secondary">Loading usage</p>
      ) : usageError ? (
        <div role="status" className="px-3.5 py-3">
          <p className="text-[13px] font-medium text-text-primary">Usage unavailable</p>
          <p className="mt-0.5 text-[12px] text-text-secondary">The local usage summary could not be loaded.</p>
        </div>
      ) : totalUsage && totalUsage.turns > 0 ? (
        <>
          <UsageRow label="Turns" value={totalUsage.turns.toLocaleString()} />
          <UsageRow label="Tokens" value={totalUsage.totalTokens.toLocaleString()} />
          <UsageRow label="Estimated cost" value={`$${totalUsage.costUsd.toFixed(4)}`} />
        </>
      ) : (
        <div role="status" className="px-3.5 py-3">
          <p className="text-[13px] font-medium text-text-primary">No AI usage recorded</p>
          <p className="mt-0.5 text-[12px] text-text-secondary">Usage appears here after an AI-assisted task completes.</p>
        </div>
      )}
    </SettingsGroup>
  );

  const ai = serverMode ? (
    <>
      <SettingsGroup title="AI Engine">
        <SettingsItem
          title="AI features are available in the oxAudit desktop app"
          description="This server does not accept AI requests, so its AI settings cannot be changed here."
        />
      </SettingsGroup>
      {usage}
    </>
  ) : (
    <>
      <SettingsGroup title="AI Engine" description="Configure any OpenAI-compatible endpoint used by assistant features.">
        <SettingsItem title="Enable AI engine" description="Assistant features stay off until this is on.">
          <Switch
            checked={form.ai.enabled}
            onChange={(enabled) => updateAi({ enabled })}
            label="Enable AI engine"
            hideLabel
          />
        </SettingsItem>
        <SettingsItem
          title="Base URL"
          description="Examples include OpenAI, Ollama, LM Studio, vLLM, Groq, and OpenRouter."
          htmlFor="ai-base-url"
          stacked
        >
          <Input
            id="ai-base-url"
            aria-describedby="ai-base-url-hint"
            value={form.ai.baseUrl}
            onChange={(event) => updateAi({ baseUrl: event.target.value })}
            placeholder="https://api.openai.com/v1"
          />
        </SettingsItem>
        <SettingsItem title="Model" htmlFor="ai-model">
          <Input
            id="ai-model"
            className="w-60"
            value={form.ai.model}
            onChange={(event) => updateAi({ model: event.target.value })}
            placeholder="gpt-4o-mini"
          />
        </SettingsItem>
        {credentialRow({
          id: "ai-api-key",
          title: "API key",
          description: removeAiApiKey
            ? "The saved key will be removed when you save."
            : form.credentials.aiApiKey
              ? "A key is stored in your operating system credential manager. Leave blank to keep it."
              : "Stored in your operating system credential manager and sent only to this endpoint.",
          draft: aiApiKeyDraft,
          setDraft: setAiApiKeyDraft,
          stored: form.credentials.aiApiKey,
          remove: removeAiApiKey,
          setRemove: setRemoveAiApiKey,
          setRemoveFalse: () => setRemoveAiApiKey(false),
          placeholder: "sk-…",
          storedPlaceholder: "Stored key unchanged",
        })}
        <SettingsItem
          title="Test connection"
          description="This checks the current draft only. Assistant readiness continues to reflect saved settings."
        >
          <div className="flex flex-wrap items-center justify-end gap-2.5">
            {statusMessage && (
              <span
                role={draftStatus?.ok ? "status" : "alert"}
                className={`inline-flex items-center gap-1.5 text-[12px] ${draftStatus?.ok ? "text-success" : "text-error"}`}
              >
                {draftStatus?.ok ? (
                  <CheckCircle2 size={13} aria-hidden="true" />
                ) : (
                  <XCircle size={13} aria-hidden="true" />
                )}
                {statusMessage}
              </span>
            )}
            <Button
              type="button"
              variant="outline"
              onClick={() => void test()}
              disabled={testing || !form.ai.baseUrl}
            >
              {testing ? (
                <Loader2 size={13} aria-hidden="true" className="animate-spin" />
              ) : (
                <CheckCircle2 size={13} aria-hidden="true" />
              )}
              {testing ? "Testing…" : "Test connection"}
            </Button>
          </div>
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Generation" description="Limits and sampling for assistant requests.">
        <SettingsItem title="Timeout (seconds)" htmlFor="ai-timeout" error={fieldErrors.timeoutSecs}>
          <Input id="ai-timeout" {...numberField("timeoutSecs", form.ai.timeoutSecs)} />
        </SettingsItem>
        <SettingsItem title={`Temperature — ${form.ai.temperature.toFixed(2)}`} htmlFor="ai-temperature">
          <input
            id="ai-temperature"
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={form.ai.temperature}
            onChange={(event) => updateAi({ temperature: Number(event.target.value) })}
            className="h-6 w-40 accent-[var(--accent)]"
          />
        </SettingsItem>
        <SettingsItem title="Max tokens" htmlFor="ai-max-tokens" error={fieldErrors.maxTokens}>
          <Input id="ai-max-tokens" {...numberField("maxTokens", form.ai.maxTokens, { step: 256 })} />
        </SettingsItem>
        <SettingsItem
          title="Context window"
          description="Model input + output capacity. Used for local preflight; check your provider's model documentation."
          htmlFor="ai-context-window"
          error={fieldErrors.contextWindow}
        >
          <Input id="ai-context-window" {...numberField("contextWindow", form.ai.contextWindow, { step: 1024 })} />
        </SettingsItem>
        <SettingsItem title="System prompt" htmlFor="ai-system-prompt" stacked>
          <Textarea
            id="ai-system-prompt"
            value={form.ai.systemPrompt}
            onChange={(event) => updateAi({ systemPrompt: event.target.value })}
            rows={4}
            className="selectable resize-y"
          />
        </SettingsItem>
      </SettingsGroup>

      <SettingsGroup title="Network access">
        <SettingsItem
          title="Allowed fetch hosts"
          description="One host per line. This extends the built-in web-fetch list for advisory sites such as nvd.nist.gov, osv.dev, and github.com. Every model-selected network tool still asks for approval. Web fetches to private, loopback, link-local, or otherwise non-routable addresses are always refused."
          htmlFor="agent-allowed-fetch-hosts"
          stacked
        >
          <Textarea
            id="agent-allowed-fetch-hosts"
            placeholder="psirt.vendor.example"
            value={rawFields.agentAllowedFetchHosts ?? (form.agentAllowedFetchHosts ?? []).join("\n")}
            onChange={(event) => editList("agentAllowedFetchHosts", event.target.value)}
            onBlur={() => settleRawField("agentAllowedFetchHosts")}
            rows={3}
            className="font-mono text-[12px]"
          />
        </SettingsItem>
      </SettingsGroup>
      {usage}
    </>
  );

  const scanDefaults = (
    <SettingsGroup title="Scan Defaults" description="Set the initial scope and limits for new local scans.">
      <SettingsItem title="Secrets scanning" description="Look for credentials and tokens in files.">
        <Switch checked={form.scan.scanSecrets} onChange={(scanSecrets) => update("scan", { ...form.scan, scanSecrets })} label="Secrets scanning" hideLabel />
      </SettingsItem>
      <SettingsItem title="Pattern scanning" description="Run the vulnerability pattern rules.">
        <Switch checked={form.scan.scanVulnerabilities} onChange={(scanVulnerabilities) => update("scan", { ...form.scan, scanVulnerabilities })} label="Pattern scanning" hideLabel />
      </SettingsItem>
      <SettingsItem title="Include .git" description="Scan the contents of the .git directory.">
        <Switch checked={form.scan.includeGit} onChange={(includeGit) => update("scan", { ...form.scan, includeGit })} label="Include .git" hideLabel />
      </SettingsItem>
      <SettingsItem title="Follow in-project symlinks" description="Symlinks that resolve inside the project are followed.">
        <Switch checked={form.scan.followSymlinks} onChange={(followSymlinks) => update("scan", { ...form.scan, followSymlinks })} label="Follow in-project symlinks" hideLabel />
      </SettingsItem>
      <SettingsItem title="Max file size (KB)" htmlFor="scan-max-file-size" error={fieldErrors.maxFileSizeKb}>
        <Input id="scan-max-file-size" {...numberField("maxFileSizeKb", form.scan.maxFileSizeKb)} />
      </SettingsItem>
      <SettingsItem title="Ignored directories" description="Enter one directory name per line." htmlFor="scan-ignored-directories" stacked>
        <Textarea
          id="scan-ignored-directories"
          value={rawFields.ignoredDirs ?? form.scan.ignoredDirs.join("\n")}
          onChange={(event) => editList("ignoredDirs", event.target.value)}
          onBlur={() => settleRawField("ignoredDirs")}
          rows={4}
          className="font-mono text-[12px]"
        />
      </SettingsItem>
    </SettingsGroup>
  );

  const liveScanning = (
    <SettingsGroup
      title="Live scanning"
      description="These limits apply to Template Scan live targets only. Local scans never use them."
    >
      {LIVE_FIELDS.map(({ key, id, label, hint }) => (
        <SettingsItem key={key} title={label} description={hint} htmlFor={id} error={fieldErrors[key]}>
          <Input id={id} {...numberField(key, form.liveScan[LIVE_FIELD_PROP[key]])} />
        </SettingsItem>
      ))}
      <SettingsItem
        title="Proxy (optional)"
        description="An http:// or https:// URL for HTTP templates. Leave empty to connect directly; proxy environment variables are ignored."
        htmlFor="live-proxy"
        error={proxyError ?? undefined}
        stacked
      >
        <Input
          id="live-proxy"
          type="text"
          autoComplete="off"
          spellCheck={false}
          placeholder="http://127.0.0.1:8080"
          value={rawFields.liveProxy ?? form.liveScan.proxy ?? ""}
          onChange={(event) => editProxy(event.target.value)}
          onBlur={() => settleRawField("liveProxy")}
          className="font-mono text-[12px]"
        />
      </SettingsItem>
    </SettingsGroup>
  );

  const dataSources = (
    <SettingsGroup
      title="Data Sources"
      description="Configure credentials used to enrich vulnerability results. Scanning stays on this machine. The optional external scanners (cve-bin-tool, grype) and advisory database refreshes do make network calls. Keys are stored by the operating system credential manager and sent only to the services you configure."
    >
      {credentialRow({
        id: "nvd-api-key",
        title: "NVD API key",
        description: removeNvdApiKey
          ? "The saved key will be removed when you save."
          : form.credentials.nvdApiKey
            ? "A key is stored in your operating system credential manager. Leave blank to keep it."
            : "Optional. Raises the NVD rate limit and is stored in your credential manager.",
        draft: nvdApiKeyDraft,
        setDraft: setNvdApiKeyDraft,
        stored: form.credentials.nvdApiKey,
        remove: removeNvdApiKey,
        setRemove: setRemoveNvdApiKey,
        setRemoveFalse: () => setRemoveNvdApiKey(false),
        placeholder: "Get a key at nvd.nist.gov/developers",
        storedPlaceholder: "Stored key unchanged",
      })}
    </SettingsGroup>
  );

  const binaryScanner = (
    <>
      <SettingsGroup title="Binary Scanning">
        <SettingsItem
          title="Two scanners, either optional"
          description="They see different things: grype reads package metadata and reports fix versions; cve-bin-tool's checkers find components statically linked into stripped binaries. oxAudit invokes copies you install rather than bundling them."
        >
          <span className="flex flex-col items-end gap-0.5 text-[12px]">
            <a href="https://github.com/anchore/grype" target="_blank" rel="noreferrer" className="text-accent underline underline-offset-2">
              grype
            </a>
            <a href="https://github.com/ossf/cve-bin-tool" target="_blank" rel="noreferrer" className="text-accent underline underline-offset-2">
              cve-bin-tool
            </a>
          </span>
        </SettingsItem>
        <SettingsItem
          title="cve-bin-tool runtime"
          description="cve-bin-tool 3.4 cannot bootstrap its CVE database unpatched. The container image carries the fix, so Docker is often the runtime that works. Build it with docker build -t oxaudit/cve-bin-tool:3.4 docker/cve-bin-tool."
          stacked
        >
          <div role="radiogroup" aria-label="cve-bin-tool runtime" className="grid gap-2 sm:grid-cols-3">
            {BINARY_RUNTIMES.map((option) => {
              const selected = (form.binaryScannerRuntime ?? "auto") === option.value;
              return (
                <button
                  key={option.value}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  onClick={() => update("binaryScannerRuntime", option.value)}
                  className={`flex flex-col items-start gap-0.5 rounded-md border px-3 py-2 text-left transition-colors ${
                    selected
                      ? "border-accent-glow bg-accent-subtle"
                      : "border-control-border bg-surface-primary hover:border-text-muted hover:bg-surface-hover"
                  }`}
                >
                  <span className={`text-[12px] font-medium ${selected ? "text-accent" : "text-text-primary"}`}>
                    {option.label}
                  </span>
                  <span className="text-[11px] text-text-muted">{option.hint}</span>
                </button>
              );
            })}
          </div>
        </SettingsItem>
        <SettingsItem
          title="cve-bin-tool path"
          description="Leave empty to find it on PATH, then `python3 -m cve_bin_tool`."
          htmlFor="binary-scanner-path"
          stacked
        >
          <Input
            id="binary-scanner-path"
            aria-describedby="binary-scanner-path-hint"
            value={form.binaryScannerPath ?? ""}
            onChange={(event) => update("binaryScannerPath", event.target.value.trim() || null)}
            placeholder="/opt/homebrew/bin/cve-bin-tool"
            className="font-mono text-[12px]"
          />
        </SettingsItem>
        <SettingsItem title="grype path" description="Leave empty to find it on PATH." htmlFor="grype-path" stacked>
          <Input
            id="grype-path"
            aria-describedby="grype-path-hint"
            value={form.grypePath ?? ""}
            onChange={(event) => update("grypePath", event.target.value.trim() || null)}
            placeholder="/opt/homebrew/bin/grype"
            className="font-mono text-[12px]"
          />
        </SettingsItem>
      </SettingsGroup>
      <p className="px-1 text-[12px] leading-relaxed text-text-muted">
        Binary scanning adds network calls beyond the NVD, OSV and AI endpoints oxAudit contacts on its own:
        cve-bin-tool reaches its own mirror and advisory feeds, and grype fetches its database from Anchore. Set an
        NVD API key under Data sources before the first cve-bin-tool run — unauthenticated, its initial download
        takes hours.
      </p>
    </>
  );

  const diagnosticsSection = (
    <SettingsGroup
      title="Diagnostics"
      description="If a scan fails, this gathers the version, platform, and recent log so a problem can be reproduced. Credentials and your home directory path are removed before it reaches you. Nothing in this report is transmitted automatically — you copy it and choose who sees it."
    >
      <SettingsItem title="Diagnostics report" description="Copies the sanitised report to the clipboard.">
        <div className="flex flex-wrap items-center justify-end gap-2">
          {copied && (
            <span className="text-[11px] text-success" role="status">
              Copied to the clipboard.
            </span>
          )}
          {diagnostics && !copied && (
            <span className="text-[11px] text-text-muted" role="status">
              Ready below — select and copy.
            </span>
          )}
          <Button type="button" variant="outline" onClick={gatherDiagnostics}>
            Copy diagnostics
          </Button>
        </div>
      </SettingsItem>
      {diagnosticsError && (
        <p className="px-3.5 py-2.5 text-[12px] text-error" role="alert">
          Diagnostics could not be gathered: {diagnosticsError}
        </p>
      )}
      {diagnostics && (
        <div className="p-3.5">
          <pre
            className="max-h-64 overflow-auto rounded-md border border-border bg-surface-code p-3 text-[11px] leading-relaxed text-text-secondary"
            aria-label="Diagnostics report"
          >
            {diagnostics}
          </pre>
        </div>
      )}
    </SettingsGroup>
  );

  const about = (
    <>
      <SettingsGroup title="About">
        <SettingsItem title="oxAudit" description="A local-first security scanner. Detection works offline.">
          <span className="font-mono text-[12px] text-text-secondary">v{appVersion}</span>
        </SettingsItem>
      </SettingsGroup>
      <SettingsGroup title="Readiness">
        <SettingsItem
          title="Readiness setup"
          description="Recheck scanner, data-source, and optional AI readiness at any time."
        >
          <Button variant="outline" onClick={requestReadinessWizard}>
            <ShieldCheck size={13} aria-hidden="true" />
            Run readiness setup
          </Button>
        </SettingsItem>
      </SettingsGroup>
    </>
  );

  const pane = {
    general,
    ai,
    "scan-defaults": scanDefaults,
    "live-scanning": liveScanning,
    "data-sources": dataSources,
    "binary-scanner": binaryScanner,
    diagnostics: diagnosticsSection,
    about,
  }[section];

  return (
    <div className="w-full animate-fade-in px-4 pb-10 pt-4 md:px-6 md:pt-6">
      <SettingsHeaderActions
        dirty={dirty}
        saving={saving}
        canSave={!hasFieldErrors}
        saveState={saveState}
        onSave={() => void save()}
        onReset={reset}
      />
      {pane}
    </div>
  );
}

/**
 * Publishes Reset, Save and the save status to the shell header (oxFuzz puts
 * Save on the right of its settings header). Rendered only while a draft
 * exists, so the buttons never appear for a page that has nothing to save.
 */
function SettingsHeaderActions(props: {
  dirty: boolean;
  saving: boolean;
  canSave: boolean;
  saveState: { tone: "success" | "error"; message: string } | null;
  onSave: () => void;
  onReset: () => void;
}): null {
  const { dirty, saving, canSave, saveState } = props;
  const latest = useRef(props);
  useEffect(() => {
    latest.current = props;
  });
  const onSave = useCallback(() => latest.current.onSave(), []);
  const onReset = useCallback(() => latest.current.onReset(), []);
  const actions = useMemo<HeaderAction[]>(() => {
    const list: HeaderAction[] = [];
    if (saveState) {
      list.push({ id: "status", kind: "status", label: "Save status", icon: saveState.tone === "success" ? CheckCircle2 : XCircle, text: saveState.message, tone: saveState.tone, onSelect: () => {} });
    } else if (dirty) {
      list.push({ id: "status", kind: "status", label: "Unsaved changes", icon: Save, text: "Unsaved changes", tone: "warning", onSelect: () => {} });
    }
    list.push({ id: "reset", kind: "button", label: "Reset", text: "Reset", icon: RotateCcw, variant: "outline", onSelect: onReset });
    list.push({
      id: "save",
      kind: "button",
      label: "Save",
      text: saving ? "Saving…" : "Save",
      icon: Save,
      variant: "primary",
      busy: saving,
      disabled: !dirty || saving || !canSave,
      onSelect: onSave,
    });
    return list;
  }, [dirty, saving, canSave, saveState, onSave, onReset]);
  useHeaderActions("settings", actions);
  return null;
}

function UsageRow({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <SettingsItem title={label}>
      <span className="text-[13px] font-semibold tabular-nums text-text-primary">{value}</span>
    </SettingsItem>
  );
}

const BINARY_RUNTIMES = [
  { value: "auto", label: "Auto", hint: "Native if installed, else Docker" },
  { value: "native", label: "Native", hint: "Your own installation" },
  { value: "docker", label: "Docker", hint: "Our image, carries the CVE-database fix" },
] as const;

const THEME_ICON: Record<ThemePreference, typeof Moon> = {
  dark: Moon,
  light: Sun,
  system: Monitor,
};
