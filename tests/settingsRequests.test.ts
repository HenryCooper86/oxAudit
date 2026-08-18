import assert from "node:assert/strict";
import test from "node:test";
import { LatestRequestQueue } from "../src/lib/latestRequest";
import {
  loadingAiReadiness,
  publishPersistedAiReadiness,
  publishSavedSettingsSnapshot,
  unavailableAiReadiness,
  type AiReadiness,
} from "../src/lib/settingsRequests";
import type { AiStatus, AppSettings } from "../src/lib/types";

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function settings(baseUrl: string, enabled = true): AppSettings {
  return {
    ai: {
      enabled,
      baseUrl,
      apiKey: "key",
      model: "model",
      temperature: 0.2,
      timeoutSecs: 120,
      maxTokens: 2048,
      systemPrompt: "prompt",
    },
    scan: {
      maxFileSizeKb: 1024,
      followSymlinks: false,
      includeGit: false,
      ignoredDirs: [],
      scanSecrets: true,
      scanVulnerabilities: true,
    },
    nvdApiKey: null,
    theme: "dark",
  };
}

const readyStatus: AiStatus = {
  ok: true,
  message: "ready",
  model: "model",
  latencyMs: 1,
};

test("a newly persisted configured snapshot immediately replaces stale ready state with versioned checking", async () => {
  const requests = new LatestRequestQueue();
  const check = deferred<AiStatus>();
  const published: AiReadiness[] = [];
  const token = requests.begin();

  const completion = publishPersistedAiReadiness(
    settings("https://new.example/v1"),
    token,
    (state) => published.push(state),
    { requests, testAi: () => check.promise },
  );

  assert.deepEqual(published, [
    { status: "checking", version: token.generation },
  ]);

  check.resolve(readyStatus);
  await completion;
  assert.deepEqual(published.at(-1), {
    status: "ready",
    version: token.generation,
  });
});

test("only the latest persisted snapshot check may publish ready or offline", async () => {
  const requests = new LatestRequestQueue();
  const first = deferred<AiStatus>();
  const second = deferred<AiStatus>();
  const published: AiReadiness[] = [];

  const firstToken = requests.begin();
  const firstCompletion = publishPersistedAiReadiness(
    settings("https://first.example/v1"),
    firstToken,
    (state) => published.push(state),
    { requests, testAi: () => first.promise },
  );
  const secondToken = requests.begin();
  const secondCompletion = publishPersistedAiReadiness(
    settings("https://second.example/v1"),
    secondToken,
    (state) => published.push(state),
    { requests, testAi: () => second.promise },
  );

  second.resolve({ ...readyStatus, ok: false });
  await secondCompletion;
  first.resolve(readyStatus);
  await firstCompletion;

  assert.deepEqual(published, [
    { status: "checking", version: firstToken.generation },
    { status: "checking", version: secondToken.generation },
    { status: "offline", version: secondToken.generation },
  ]);
});

test("loading, unavailable, and unconfigured remain distinct readiness states", async () => {
  const requests = new LatestRequestQueue();
  const token = requests.begin();
  const published: AiReadiness[] = [];

  await publishPersistedAiReadiness(
    settings("", false),
    token,
    (state) => published.push(state),
    {
      requests,
      testAi: async () => {
        assert.fail("unconfigured settings must not test an endpoint");
      },
    },
  );

  assert.deepEqual(loadingAiReadiness(token), {
    status: "loading",
    version: token.generation,
  });
  assert.deepEqual(unavailableAiReadiness(token), {
    status: "unavailable",
    version: token.generation,
  });
  assert.deepEqual(published, [
    { status: "unconfigured", version: token.generation },
  ]);
});

test("a superseded save completion cannot publish settings or readiness", async () => {
  const requests = new LatestRequestQueue();
  const save = deferred<void>();
  const published: string[] = [];
  const olderToken = requests.begin();

  const olderSave = (async () => {
    await save.promise;
    return publishSavedSettingsSnapshot(
      settings("https://older.example/v1"),
      olderToken,
      (saved) => published.push(`settings:${saved.ai.baseUrl}`),
      (readiness) => published.push(`readiness:${readiness.status}`),
      {
        requests,
        testAi: async () => {
          assert.fail("a stale save must not test its endpoint");
        },
      },
    );
  })();

  requests.begin();
  save.resolve(undefined);

  assert.equal(await olderSave, null);
  assert.deepEqual(published, []);
});

test("a current saved snapshot publishes checking before settings and versions its completion", async () => {
  const requests = new LatestRequestQueue();
  const check = deferred<AiStatus>();
  const published: string[] = [];
  const token = requests.begin();
  const snapshot = settings("https://saved.example/v1");

  const readiness = publishSavedSettingsSnapshot(
    snapshot,
    token,
    (saved) => published.push(`settings:${saved.ai.baseUrl}`),
    (state) => published.push(`readiness:${state.status}:${state.version}`),
    { requests, testAi: () => check.promise },
  );

  assert.notEqual(readiness, null);
  assert.deepEqual(published, [
    `readiness:checking:${token.generation}`,
    "settings:https://saved.example/v1",
  ]);

  check.resolve(readyStatus);
  await readiness;
  assert.deepEqual(published.at(-1), `readiness:ready:${token.generation}`);
});
