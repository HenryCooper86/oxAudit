import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeThemePreference,
  resolveTheme,
  subscribeToSystemTheme,
  type SystemThemeQuery,
} from "../src/lib/theme";
import {
  SerializedSettingsWrites,
  savePersistedThemePreference,
} from "../src/lib/settingsRequests";
import type { AppSettings, SaveSettingsRequest } from "../src/lib/types";

function settings(overrides: Partial<AppSettings> = {}): AppSettings {
  return {
    ai: {
      enabled: false,
      baseUrl: "",
      model: "",
      temperature: 0.2,
      timeoutSecs: 60,
      maxTokens: 2048,
      contextWindow: 128000,
      systemPrompt: "",
    },
    scan: {
      maxFileSizeKb: 1024,
      followSymlinks: false,
      includeGit: false,
      ignoredDirs: [],
      scanSecrets: true,
      scanVulnerabilities: true,
    },
    credentials: { aiApiKey: false, nvdApiKey: false },
    theme: "dark",
    ...overrides,
  };
}

test("an unrecognized stored theme falls back to dark rather than an invalid attribute", () => {
  assert.equal(normalizeThemePreference("light"), "light");
  assert.equal(normalizeThemePreference("system"), "system");
  assert.equal(normalizeThemePreference("solarized"), "dark");
  assert.equal(normalizeThemePreference(undefined), "dark");
  assert.equal(normalizeThemePreference(null), "dark");
  assert.equal(normalizeThemePreference(7), "dark");
});

test("only the system preference tracks the OS colour scheme", () => {
  assert.equal(resolveTheme("system", true), "dark");
  assert.equal(resolveTheme("system", false), "light");
  assert.equal(resolveTheme("light", true), "light");
  assert.equal(resolveTheme("dark", false), "dark");
});

test("system theme changes are observed through whichever matchMedia API exists", () => {
  const observed: boolean[] = [];

  const modern = (() => {
    let listener: ((event: { matches: boolean }) => void) | null = null;
    const query: SystemThemeQuery = {
      matches: true,
      addEventListener: (_type, next) => {
        listener = next;
      },
      removeEventListener: () => {
        listener = null;
      },
    };
    return {
      query,
      emit: (matches: boolean) => listener?.({ matches }),
      subscribed: () => listener !== null,
    };
  })();

  const unsubscribe = subscribeToSystemTheme(modern.query, (dark) => observed.push(dark));
  modern.emit(false);
  modern.emit(true);
  unsubscribe();

  assert.deepEqual(observed, [false, true]);
  assert.equal(modern.subscribed(), false, "unsubscribing must detach the listener");

  // Deprecated addListener/removeListener fallback.
  const legacyCalls: boolean[] = [];
  let legacyListener: ((event: { matches: boolean }) => void) | null = null;
  const legacy: SystemThemeQuery = {
    matches: false,
    addListener: (next) => {
      legacyListener = next;
    },
    removeListener: () => {
      legacyListener = null;
    },
  };
  const detach = subscribeToSystemTheme(legacy, (dark) => legacyCalls.push(dark));
  legacyListener?.({ matches: true });
  detach();

  assert.deepEqual(legacyCalls, [true]);
  assert.equal(legacyListener, null);
});

test("subscribing without matchMedia support is a no-op that still returns a cleanup", () => {
  const unsubscribe = subscribeToSystemTheme(undefined, () => {
    assert.fail("no listener should fire without a media query");
  });
  assert.doesNotThrow(unsubscribe);
});

test("a theme write never persists a snapshot that a queued save has already superseded", async () => {
  const saveRequests = new SerializedSettingsWrites();
  const written: AppSettings[] = [];
  let stored = settings({ theme: "dark" });

  const saveSettings = async ({ settings: next }: SaveSettingsRequest) => {
    written.push(next);
    stored = next;
  };

  // A full save is queued first and changes an unrelated field. The theme
  // write must observe that result, not the snapshot from before it ran.
  const fullSave = saveRequests.run(async () => {
    await saveSettings({
      settings: { ...stored, ai: { ...stored.ai, model: "model-from-full-save" } },
      aiApiKey: { action: "unchanged" },
      nvdApiKey: { action: "unchanged" },
    });
  });

  const themeWrite = savePersistedThemePreference(
    () => stored,
    "light",
    (next) => {
      stored = next;
    },
    { saveRequests, saveSettings },
  );

  await Promise.all([fullSave, themeWrite]);

  assert.equal(written.length, 2);
  assert.equal(stored.theme, "light");
  assert.equal(
    stored.ai.model,
    "model-from-full-save",
    "the theme write must not clobber the save queued ahead of it",
  );
});

test("re-selecting the current theme performs no write", async () => {
  let calls = 0;
  const result = await savePersistedThemePreference(
    () => settings({ theme: "light" }),
    "light",
    () => assert.fail("nothing should be published for a no-op"),
    {
      saveRequests: new SerializedSettingsWrites(),
      saveSettings: async () => {
        calls += 1;
      },
    },
  );

  assert.equal(result, null);
  assert.equal(calls, 0);
});

test("a theme write with no settings loaded is skipped rather than writing a partial file", async () => {
  const result = await savePersistedThemePreference(
    () => null,
    "light",
    () => assert.fail("nothing should be published without loaded settings"),
    {
      saveRequests: new SerializedSettingsWrites(),
      saveSettings: async () => assert.fail("no write should be attempted"),
    },
  );

  assert.equal(result, null);
});
