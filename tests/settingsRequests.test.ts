import assert from "node:assert/strict";
import test from "node:test";
import { LatestRequestQueue } from "../src/lib/latestRequest";
import {
  loadingAiReadiness,
  publishPersistedAiReadiness,
  publishSavedSettingsSnapshot,
  savePersistedSettingsSnapshot,
  SerializedSettingsWrites,
  unavailableAiReadiness,
  type AiReadiness,
} from "../src/lib/settingsRequests";
import type { AiStatus, AppSettings } from "../src/lib/types";

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
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
      contextWindow: 128000,
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

test("overlapping successful saves publish every authoritative native snapshot in write order", async () => {
  const requests = new LatestRequestQueue();
  const saveRequests = new SerializedSettingsWrites();
  const olderNativeSave = deferred<void>();
  const newerNativeSave = deferred<void>();
  const olderStarted = deferred<void>();
  const newerStarted = deferred<void>();
  const olderCheck = deferred<AiStatus>();
  const newerCheck = deferred<AiStatus>();
  const checks = [olderCheck, newerCheck];
  let checkIndex = 0;
  const writes: string[] = [];
  const published: string[] = [];
  const saveSettings = (snapshot: AppSettings) => {
    writes.push(snapshot.ai.baseUrl);
    if (snapshot.ai.baseUrl.includes("older")) {
      olderStarted.resolve(undefined);
      return olderNativeSave.promise;
    }
    newerStarted.resolve(undefined);
    return newerNativeSave.promise;
  };

  const olderSave = savePersistedSettingsSnapshot(
    settings("https://older.example/v1"),
    (saved) => published.push(`settings:${saved.ai.baseUrl}`),
    (readiness) => published.push(`readiness:${readiness.status}`),
    {
      requests,
      saveRequests,
      saveSettings,
      testAi: () => checks[checkIndex++].promise,
    },
  );
  await olderStarted.promise;
  const newerSave = savePersistedSettingsSnapshot(
    settings("https://newer.example/v1"),
    (saved) => published.push(`settings:${saved.ai.baseUrl}`),
    (readiness) => published.push(`readiness:${readiness.status}`),
    {
      requests,
      saveRequests,
      saveSettings,
      testAi: () => checks[checkIndex++].promise,
    },
  );

  assert.deepEqual(writes, ["https://older.example/v1"]);
  olderNativeSave.resolve(undefined);
  const olderPublication = await olderSave;
  await newerStarted.promise;
  const publishedAfterOlderWrite = [...published];

  newerNativeSave.resolve(undefined);
  const newerPublication = await newerSave;

  olderCheck.resolve(readyStatus);
  newerCheck.resolve(readyStatus);
  await olderPublication?.readiness;
  await newerPublication?.readiness;
  assert.notEqual(olderPublication, null);
  assert.notEqual(newerPublication, null);
  assert.deepEqual(writes, [
    "https://older.example/v1",
    "https://newer.example/v1",
  ]);
  assert.deepEqual(publishedAfterOlderWrite, [
    "readiness:checking",
    "settings:https://older.example/v1",
  ]);
  assert.deepEqual(published.slice(0, 4), [
    "readiness:checking",
    "settings:https://older.example/v1",
    "readiness:checking",
    "settings:https://newer.example/v1",
  ]);
  assert.equal(checkIndex, 2);
  assert.equal(published.at(-1), "readiness:ready");
  assert.equal(
    published.filter((entry) => entry === "readiness:ready").length,
    1,
    "only the latest successful snapshot's readiness completion may publish",
  );
});

test("an older successful save remains store-visible when a newer save fails", async () => {
  const requests = new LatestRequestQueue();
  const saveRequests = new SerializedSettingsWrites();
  const olderNativeSave = deferred<void>();
  const newerNativeSave = deferred<void>();
  const olderStarted = deferred<void>();
  const olderCheck = deferred<AiStatus>();
  const writes: string[] = [];
  let storeSnapshot = settings("https://before.example/v1");
  const readiness: AiReadiness[] = [];
  const saveSettings = (snapshot: AppSettings) => {
    writes.push(snapshot.ai.baseUrl);
    if (snapshot.ai.baseUrl.includes("older")) {
      olderStarted.resolve(undefined);
      return olderNativeSave.promise;
    }
    return newerNativeSave.promise;
  };

  const older = savePersistedSettingsSnapshot(
    settings("https://older.example/v1"),
    (saved) => {
      storeSnapshot = saved;
    },
    (state) => readiness.push(state),
    { requests, saveRequests, saveSettings, testAi: () => olderCheck.promise },
  );
  await olderStarted.promise;
  const newer = savePersistedSettingsSnapshot(
    settings("https://newer.example/v1"),
    (saved) => {
      storeSnapshot = saved;
    },
    (state) => readiness.push(state),
    { requests, saveRequests, saveSettings, testAi: () => olderCheck.promise },
  );

  olderNativeSave.resolve(undefined);
  const olderPublication = await older;
  const snapshotAfterOlderWrite = storeSnapshot.ai.baseUrl;

  newerNativeSave.reject(new Error("disk full"));
  await assert.rejects(newer, /disk full/);

  olderCheck.resolve(readyStatus);
  await olderPublication?.readiness;
  assert.notEqual(olderPublication, null);
  assert.equal(snapshotAfterOlderWrite, "https://older.example/v1");
  assert.deepEqual(writes, [
    "https://older.example/v1",
    "https://newer.example/v1",
  ]);
  assert.equal(storeSnapshot.ai.baseUrl, "https://older.example/v1");
  assert.deepEqual(readiness.map((state) => state.status), ["checking", "ready"]);
});

test("a failed older save cannot prevent a newer successful snapshot publication", async () => {
  const requests = new LatestRequestQueue();
  const saveRequests = new SerializedSettingsWrites();
  const olderNativeSave = deferred<void>();
  const newerNativeSave = deferred<void>();
  const olderStarted = deferred<void>();
  const newerCheck = deferred<AiStatus>();
  const writes: string[] = [];
  const published: string[] = [];
  const saveSettings = (snapshot: AppSettings) => {
    writes.push(snapshot.ai.baseUrl);
    if (snapshot.ai.baseUrl.includes("older")) {
      olderStarted.resolve(undefined);
      return olderNativeSave.promise;
    }
    return newerNativeSave.promise;
  };

  const older = savePersistedSettingsSnapshot(
    settings("https://older.example/v1"),
    (saved) => published.push(`settings:${saved.ai.baseUrl}`),
    (state) => published.push(`readiness:${state.status}`),
    { requests, saveRequests, saveSettings, testAi: () => newerCheck.promise },
  );
  await olderStarted.promise;
  const newer = savePersistedSettingsSnapshot(
    settings("https://newer.example/v1"),
    (saved) => published.push(`settings:${saved.ai.baseUrl}`),
    (state) => published.push(`readiness:${state.status}`),
    { requests, saveRequests, saveSettings, testAi: () => newerCheck.promise },
  );

  olderNativeSave.reject(new Error("first write failed"));
  const olderResult = await older.then(
    () => "fulfilled",
    (error: unknown) => String(error),
  );
  newerNativeSave.resolve(undefined);
  const publication = await newer;
  assert.match(olderResult, /first write failed/);
  assert.notEqual(publication, null);
  assert.deepEqual(writes, [
    "https://older.example/v1",
    "https://newer.example/v1",
  ]);
  assert.deepEqual(published, [
    "readiness:checking",
    "settings:https://newer.example/v1",
  ]);

  newerCheck.resolve(readyStatus);
  await publication?.readiness;
  assert.equal(published.at(-1), "readiness:ready");
});

test("a save started by an unmounted Settings page still publishes before a remounted page's failed save", async () => {
  const requests = new LatestRequestQueue();
  const saveRequests = new SerializedSettingsWrites();
  const firstWrite = deferred<void>();
  const secondWrite = deferred<void>();
  const firstStarted = deferred<void>();
  const firstCheck = deferred<AiStatus>();
  let storeSnapshot = settings("https://before.example/v1");
  const storeReadiness: AiReadiness[] = [];
  const saveSettings = (snapshot: AppSettings) => {
    if (snapshot.ai.baseUrl.includes("first")) {
      firstStarted.resolve(undefined);
      return firstWrite.promise;
    }
    return secondWrite.promise;
  };
  const publishSettings = (saved: AppSettings) => {
    storeSnapshot = saved;
  };
  const publishReadiness = (state: AiReadiness) => storeReadiness.push(state);

  const fromUnmountedPage = savePersistedSettingsSnapshot(
    settings("https://first.example/v1"),
    publishSettings,
    publishReadiness,
    { requests, saveRequests, saveSettings, testAi: () => firstCheck.promise },
  );
  await firstStarted.promise;
  const fromRemountedPage = savePersistedSettingsSnapshot(
    settings("https://second.example/v1"),
    publishSettings,
    publishReadiness,
    { requests, saveRequests, saveSettings, testAi: () => firstCheck.promise },
  );

  firstWrite.resolve(undefined);
  const firstPublication = await fromUnmountedPage;
  const snapshotAfterFirstWrite = storeSnapshot.ai.baseUrl;
  secondWrite.reject(new Error("remounted write failed"));
  await assert.rejects(fromRemountedPage, /remounted write failed/);
  assert.equal(snapshotAfterFirstWrite, "https://first.example/v1");
  assert.equal(storeSnapshot.ai.baseUrl, "https://first.example/v1");

  firstCheck.resolve(readyStatus);
  await firstPublication?.readiness;
  assert.deepEqual(storeReadiness.map((state) => state.status), [
    "checking",
    "ready",
  ]);
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

test("a failed save does not invalidate the in-flight readiness check for the persisted snapshot", async () => {
  const requests = new LatestRequestQueue();
  const saveRequests = new SerializedSettingsWrites();
  const oldCheck = deferred<AiStatus>();
  const published: AiReadiness[] = [];
  const persistedToken = requests.begin();
  const oldCompletion = publishPersistedAiReadiness(
    settings("https://persisted.example/v1"),
    persistedToken,
    (state) => published.push(state),
    { requests, testAi: () => oldCheck.promise },
  );

  await assert.rejects(
    savePersistedSettingsSnapshot(
      settings("https://candidate.example/v1"),
      () => assert.fail("failed settings must not publish"),
      () => assert.fail("failed settings must not publish readiness"),
      {
        requests,
        saveRequests,
        saveSettings: async () => {
          throw new Error("disk full");
        },
        testAi: async () => {
          assert.fail("failed settings must not test their endpoint");
        },
      },
    ),
    /disk full/,
  );
  oldCheck.resolve(readyStatus);
  await oldCompletion;

  assert.deepEqual(published, [
    { status: "checking", version: persistedToken.generation },
    { status: "ready", version: persistedToken.generation },
  ]);
});
