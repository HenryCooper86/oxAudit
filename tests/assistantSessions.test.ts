import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  loadLatestSessionMessages,
  resolveRuntimeProject,
} from "../src/lib/assistantSessions";
import { LatestRequestQueue } from "../src/lib/latestRequest";
import type { StoredMessage } from "../src/lib/types";

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

function message(id: string): StoredMessage {
  return {
    id,
    role: "assistant",
    content: id,
    at: "2026-08-18T00:00:00.000Z",
  };
}

test("a delayed older session load cannot replace the latest selected transcript", async () => {
  const requests = new LatestRequestQueue();
  const older = deferred<StoredMessage[]>();
  const newer = deferred<StoredMessage[]>();

  const olderToken = requests.begin();
  const olderLoad = loadLatestSessionMessages(
    requests,
    olderToken,
    () => older.promise,
  );
  const newerToken = requests.begin();
  const newerLoad = loadLatestSessionMessages(
    requests,
    newerToken,
    () => newer.promise,
  );

  newer.resolve([message("newer")]);
  assert.deepEqual(await newerLoad, {
    current: true,
    value: [message("newer")],
  });

  older.resolve([message("older")]);
  assert.deepEqual(await olderLoad, { current: false });
});

test("an unavailable historic project keeps the transcript outcome and clears only runtime context", async () => {
  const calls: Array<string | null> = [];
  const outcome = await resolveRuntimeProject(
    "/moved/project",
    async (path) => {
      calls.push(path);
      if (path) throw new Error("not a directory");
    },
  );

  assert.deepEqual(calls, ["/moved/project", null]);
  assert.deepEqual(outcome, {
    runtimePath: null,
    unavailablePath: "/moved/project",
    warning: "Project is unavailable: Error: not a directory",
  });
});

test("a standalone session explicitly clears runtime context without changing persistence", async () => {
  const calls: Array<string | null> = [];
  const outcome = await resolveRuntimeProject(null, async (path) => {
    calls.push(path);
  });

  assert.deepEqual(calls, [null]);
  assert.deepEqual(outcome, {
    runtimePath: null,
    unavailablePath: null,
    warning: null,
  });
});

test("a delayed failed activation cannot clear a newer runtime project", async () => {
  const oldFailure = deferred<void>();
  let runtimeProject: string | null = null;
  const setActiveProject = async (path: string | null) => {
    if (path === "/old/project") {
      await oldFailure.promise;
      throw new Error("old project disappeared");
    }
    runtimeProject = path;
  };

  const older = resolveRuntimeProject("/old/project", setActiveProject);
  const newer = resolveRuntimeProject("/new/project", setActiveProject);
  oldFailure.resolve(undefined);

  await Promise.all([older, newer]);
  assert.equal(runtimeProject, "/new/project");
});

test("a delayed older valid activation cannot overwrite a newer runtime project", async () => {
  const oldCompletion = deferred<void>();
  let runtimeProject: string | null = null;
  const setActiveProject = async (path: string | null) => {
    if (path === "/old/project") {
      await oldCompletion.promise;
    }
    runtimeProject = path;
  };

  const older = resolveRuntimeProject("/old/project", setActiveProject);
  const newer = resolveRuntimeProject("/new/project", setActiveProject);
  oldCompletion.resolve(undefined);

  await Promise.all([older, newer]);
  assert.equal(runtimeProject, "/new/project");
});

test("a queued runtime mutation is skipped when a newer page activation supersedes it", async () => {
  const sourceStarted = deferred<void>();
  const sourceCompletion = deferred<void>();
  const calls: Array<string | null> = [];
  const setActiveProject = async (path: string | null) => {
    calls.push(path);
    if (path === "/source/project") {
      sourceStarted.resolve(undefined);
      await sourceCompletion.promise;
    }
  };

  const source = resolveRuntimeProject("/source/project", setActiveProject);
  await sourceStarted.promise;
  const dependency = resolveRuntimeProject("/dependency/project", setActiveProject);
  const assistant = resolveRuntimeProject("/assistant/project", setActiveProject);

  sourceCompletion.resolve(undefined);
  const outcomes = await Promise.all([source, dependency, assistant]);

  assert.deepEqual(calls, ["/source/project", "/assistant/project"]);
  assert.deepEqual(outcomes.map((outcome) => outcome.runtimePath), [
    "/assistant/project",
    "/assistant/project",
    "/assistant/project",
  ]);
});

test("dependent work waits until a newer activation repairs an older in-flight success", async () => {
  const sourceCompletion = deferred<void>();
  const assistantStarted = deferred<void>();
  const assistantCompletion = deferred<void>();
  const calls: Array<string | null> = [];
  let sourceSettled = false;
  let runtimeProject: string | null = null;
  const setActiveProject = async (path: string | null) => {
    calls.push(path);
    if (path === "/source/project") await sourceCompletion.promise;
    if (path === "/assistant/project") {
      assistantStarted.resolve(undefined);
      await assistantCompletion.promise;
    }
    runtimeProject = path;
  };

  const source = resolveRuntimeProject("/source/project", setActiveProject).then(
    (outcome) => {
      sourceSettled = true;
      return outcome;
    },
  );
  const assistant = resolveRuntimeProject("/assistant/project", setActiveProject);

  sourceCompletion.resolve(undefined);
  await assistantStarted.promise;
  const callsWhileLatestPending = [...calls];
  const sourceSettledWhileLatestPending = sourceSettled;
  const runtimeWhileLatestPending = runtimeProject;

  assistantCompletion.resolve(undefined);
  const [sourceOutcome, assistantOutcome] = await Promise.all([source, assistant]);
  assert.deepEqual(callsWhileLatestPending, [
    "/source/project",
    "/assistant/project",
  ]);
  assert.equal(sourceSettledWhileLatestPending, false);
  assert.equal(runtimeWhileLatestPending, "/source/project");
  assert.equal(sourceSettled, true);
  assert.equal(runtimeProject, "/assistant/project");
  assert.equal(sourceOutcome.runtimePath, "/assistant/project");
  assert.equal(assistantOutcome.runtimePath, "/assistant/project");
});

test("a stale rejected activation never issues a fallback clear after a newer request", async () => {
  const sourceFailure = deferred<void>();
  const assistantStarted = deferred<void>();
  const assistantCompletion = deferred<void>();
  const calls: Array<string | null> = [];
  const setActiveProject = async (path: string | null) => {
    calls.push(path);
    if (path === "/source/project") {
      await sourceFailure.promise;
      throw new Error("source project disappeared");
    }
    if (path === "/assistant/project") {
      assistantStarted.resolve(undefined);
      await assistantCompletion.promise;
    }
  };

  const source = resolveRuntimeProject("/source/project", setActiveProject);
  const assistant = resolveRuntimeProject("/assistant/project", setActiveProject);
  sourceFailure.resolve(undefined);
  await assistantStarted.promise;
  const callsBeforeLatestSettled = [...calls];
  assistantCompletion.resolve(undefined);
  await Promise.all([source, assistant]);
  assert.deepEqual(callsBeforeLatestSettled, ["/source/project", "/assistant/project"]);
  assert.deepEqual(calls, ["/source/project", "/assistant/project"]);
});

test("dependency activation followed by standalone Assistant clears only the latest runtime context", async () => {
  const dependencyCompletion = deferred<void>();
  const calls: Array<string | null> = [];
  let runtimeProject: string | null = "/previous/project";
  const setActiveProject = async (path: string | null) => {
    calls.push(path);
    if (path === "/dependency/project") await dependencyCompletion.promise;
    runtimeProject = path;
  };

  const dependency = resolveRuntimeProject("/dependency/project", setActiveProject);
  const standalone = resolveRuntimeProject(null, setActiveProject);
  dependencyCompletion.resolve(undefined);
  const [dependencyOutcome, standaloneOutcome] = await Promise.all([
    dependency,
    standalone,
  ]);

  assert.deepEqual(calls, ["/dependency/project", null]);
  assert.equal(runtimeProject, null);
  assert.equal(dependencyOutcome.runtimePath, null);
  assert.equal(standaloneOutcome.runtimePath, null);
});

function pageSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}

function functionBody(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.notEqual(startIndex, -1, `missing function start: ${start}`);
  assert.notEqual(endIndex, -1, `missing function end: ${end}`);
  return source.slice(startIndex, endIndex);
}

test("Assistant, Source, and Dependency pages route every runtime mutation through the global coordinator", () => {
  const assistant = pageSource("../src/pages/Assistant.tsx");
  const source = pageSource("../src/pages/SourceScan.tsx");
  const dependency = pageSource("../src/pages/DepsScan.tsx");

  for (const [name, page, expectedCalls] of [
    ["Assistant", assistant, 1],
    ["Source", source, 3],
    ["Dependency", dependency, 3],
  ] as const) {
    assert.match(
      page,
      /import\s*\{[^}]*\bresolveRuntimeProject\b[^}]*\}\s*from\s*"\.\.\/lib\/assistantSessions"/,
    );
    assert.equal(page.match(/resolveRuntimeProject\(/g)?.length, expectedCalls, name);
    assert.doesNotMatch(page, /api\.setActiveProject\s*\(/, name);
  }
});

test("Source and Dependency dependent work awaits coordinator settlement before native work", () => {
  const source = pageSource("../src/pages/SourceScan.tsx");
  const dependency = pageSource("../src/pages/DepsScan.tsx");
  const sourceRun = functionBody(
    source,
    "const runScan = async (ignoreInvalidPolicy = false) =>",
    "const cancel = async",
  );
  const dependencyDiscovery = functionBody(
    dependency,
    "const findLockfiles = async () =>",
    "const run = async () =>",
  );
  const dependencyRun = functionBody(
    dependency,
    "const run = async () =>",
    "const openReference = async",
  );

  assert.ok(sourceRun.indexOf("await resolveRuntimeProject") < sourceRun.indexOf("api.scanProject"));
  assert.ok(
    dependencyDiscovery.indexOf("await resolveRuntimeProject") <
      dependencyDiscovery.indexOf("api.findLockfiles"),
  );
  assert.ok(
    dependencyRun.indexOf("await resolveRuntimeProject") <
      dependencyRun.indexOf("api.scanDependencies"),
  );
});
