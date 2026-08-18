import assert from "node:assert/strict";
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
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
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
