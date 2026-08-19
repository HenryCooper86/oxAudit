import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { streamChat } from "../src/lib/aiEvents";

type Callback = (event: { id: number; event: string; payload: unknown }) => void;

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  assert.fail("condition was not reached");
}

class TauriEventHarness {
  private callbackId = 0;
  private eventId = 0;
  private callbacks = new Map<number, Callback>();
  private listeners = new Map<number, { event: string; callbackId: number }>();
  readonly commands: Array<{ command: string; args: Record<string, unknown> }> = [];
  readonly unregistered: number[] = [];
  streamStart = deferred<{ runId: string }>();
  delayFirstListener = false;
  cancelError: Error | null = null;
  private firstListener = deferred<number>();

  install(): void {
    const target = globalThis as typeof globalThis & {
      window: typeof globalThis;
      __TAURI_INTERNALS__: {
        transformCallback: (callback: Callback) => number;
        unregisterCallback: (id: number) => void;
        invoke: (command: string, args: Record<string, unknown>) => Promise<unknown>;
      };
      __TAURI_EVENT_PLUGIN_INTERNALS__: {
        unregisterListener: (event: string, eventId: number) => void;
      };
    };
    target.window = target;
    target.__TAURI_INTERNALS__ = {
      transformCallback: (callback) => {
        const id = ++this.callbackId;
        this.callbacks.set(id, callback);
        return id;
      },
      unregisterCallback: (id) => {
        this.callbacks.delete(id);
      },
      invoke: async (command, args) => {
        this.commands.push({ command, args });
        if (command === "plugin:event|listen") {
          const id = ++this.eventId;
          this.listeners.set(id, {
            event: String(args.event),
            callbackId: Number(args.handler),
          });
          if (this.delayFirstListener && id === 1) return this.firstListener.promise;
          return id;
        }
        if (command === "stream_chat") return this.streamStart.promise;
        if (command === "cancel_chat" && this.cancelError) throw this.cancelError;
        return undefined;
      },
    };
    target.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
      unregisterListener: (_event, eventId) => {
        this.unregistered.push(eventId);
        this.listeners.delete(eventId);
      },
    };
  }

  resolveFirstListener(): void {
    this.firstListener.resolve(1);
  }

  emit(event: string, payload: unknown): void {
    for (const [id, listener] of this.listeners) {
      if (listener.event !== event) continue;
      this.callbacks.get(listener.callbackId)?.({ id, event, payload });
    }
  }

  commandCount(command: string): number {
    return this.commands.filter((entry) => entry.command === command).length;
  }
}

let harness: TauriEventHarness;

beforeEach(() => {
  harness = new TauriEventHarness();
  harness.install();
});

afterEach(() => {
  delete (globalThis as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
  delete (globalThis as { __TAURI_EVENT_PLUGIN_INTERNALS__?: unknown })
    .__TAURI_EVENT_PLUGIN_INTERNALS__;
});

test("disposing after native launch requests backend cancellation and releases every listener", async () => {
  const handle = streamChat({ messages: [], conversationId: "session-a" }, {});
  await waitFor(
    () =>
      harness.commandCount("plugin:event|listen") === 4 &&
      harness.commandCount("stream_chat") === 1,
  );

  handle.dispose();
  assert.equal(harness.unregistered.length, 4, "dispose must synchronously release listeners");

  harness.streamStart.resolve({ runId: handle.runId });
  await handle.finished;

  assert.equal(
    harness.commandCount("cancel_chat"),
    1,
    "an unmounted Assistant must not leave the native run alive",
  );
});

test("explicit cancel before command acknowledgement reaches the matching native run", async () => {
  const handle = streamChat({ messages: [], conversationId: "session-b" }, {});
  await waitFor(() => harness.commandCount("stream_chat") === 1);
  const cancellation = handle.cancel();
  harness.streamStart.resolve({ runId: handle.runId });

  await cancellation;

  const cancellationCall = harness.commands.find(
    (entry) => entry.command === "cancel_chat",
  );
  assert.deepEqual(cancellationCall?.args, { runId: handle.runId });
  harness.emit("ai://error", {
    runId: handle.runId,
    message: "AI request cancelled",
  });
  await handle.finished;
  assert.equal(harness.unregistered.length, 4);
});

test("a listener that registers after disposal is immediately released and no run launches", async () => {
  harness.delayFirstListener = true;
  const handle = streamChat({ messages: [], conversationId: "session-c" }, {});

  handle.dispose();
  harness.resolveFirstListener();
  await handle.finished;

  assert.deepEqual(harness.unregistered, [1]);
  assert.equal(harness.commandCount("stream_chat"), 0);
  assert.equal(harness.commandCount("cancel_chat"), 0);
});

test("foreign run events are ignored and only the matching terminal event cleans up", async () => {
  const deltas: string[] = [];
  let done = 0;
  const handle = streamChat(
    { messages: [], conversationId: "session-d" },
    {
      onDelta: (content) => deltas.push(content),
      onDone: () => {
        done += 1;
      },
    },
  );
  await waitFor(() => harness.commandCount("stream_chat") === 1);
  harness.streamStart.resolve({ runId: handle.runId });
  await waitFor(() => harness.commandCount("stream_chat") === 1);

  harness.emit("ai://event", {
    runId: "another-run",
    type: "delta",
    content: "wrong",
  });
  harness.emit("ai://event", {
    runId: handle.runId,
    type: "delta",
    content: "right",
  });
  harness.emit("ai://done", {
    runId: "another-run",
    content: "wrong",
    model: null,
    usage: null,
  });

  assert.deepEqual(deltas, ["right"]);
  assert.equal(done, 0);
  assert.equal(harness.unregistered.length, 0);

  harness.emit("ai://done", {
    runId: handle.runId,
    content: "done",
    model: null,
    usage: null,
  });
  await handle.finished;

  assert.equal(done, 1);
  assert.equal(harness.unregistered.length, 4);
});

test("stream command rejection reports once and releases every listener", async () => {
  const errors: string[] = [];
  const handle = streamChat(
    { messages: [], conversationId: "session-e" },
    { onError: (message) => errors.push(message) },
  );
  await waitFor(() => harness.commandCount("stream_chat") === 1);

  harness.streamStart.reject(new Error("native invoke failed"));
  await handle.finished;

  assert.deepEqual(errors, ["Error: native invoke failed"]);
  assert.equal(harness.unregistered.length, 4);
  assert.equal(harness.commandCount("cancel_chat"), 0);
});

test("disposal settles cleanly even when native cancellation rejects", async () => {
  harness.cancelError = new Error("cancel transport failed");
  const handle = streamChat(
    { messages: [], conversationId: "session-f" },
    {},
  );
  await waitFor(() => harness.commandCount("stream_chat") === 1);
  harness.streamStart.resolve({ runId: handle.runId });

  handle.dispose();
  await handle.finished;

  assert.equal(harness.commandCount("cancel_chat"), 1);
  assert.equal(harness.unregistered.length, 4);
});

test("a steer event is routed only to the run that owns it", async () => {
  const mine: string[] = [];
  const handle = streamChat({ messages: [], conversationId: "session-steer" }, {
    onSteer: (text) => mine.push(text),
  });
  await waitFor(() => harness.commandCount("stream_chat") === 1);
  harness.streamStart.resolve({ runId: handle.runId });
  await waitFor(() => harness.commandCount("plugin:event|listen") === 4);

  harness.emit("ai://event", {
    runId: "some-other-run",
    type: "steer",
    text: "meant for a different turn",
  });
  harness.emit("ai://event", {
    runId: handle.runId,
    type: "steer",
    text: "check the auth module instead",
  });

  await waitFor(() => mine.length === 1);
  assert.deepEqual(mine, ["check the auth module instead"]);

  harness.emit("ai://done", {
    runId: handle.runId,
    content: "done",
    model: null,
    usage: null,
  });
  await handle.finished;
});

test("steer events stop being delivered once the run has settled", async () => {
  const seen: string[] = [];
  const handle = streamChat({ messages: [], conversationId: "session-late" }, {
    onSteer: (text) => seen.push(text),
  });
  await waitFor(() => harness.commandCount("stream_chat") === 1);
  harness.streamStart.resolve({ runId: handle.runId });
  await waitFor(() => harness.commandCount("plugin:event|listen") === 4);

  harness.emit("ai://done", {
    runId: handle.runId,
    content: "answered",
    model: null,
    usage: null,
  });
  await handle.finished;

  harness.emit("ai://event", {
    runId: handle.runId,
    type: "steer",
    text: "too late",
  });

  assert.deepEqual(seen, [], "a settled run must not surface further steers");
});

test("a todos event carries the whole list so the panel never rebuilds state from operations", async () => {
  const snapshots: unknown[] = [];
  const handle = streamChat({ messages: [], conversationId: "session-todo" }, {
    onTodos: (items) => snapshots.push(items),
  });
  await waitFor(() => harness.commandCount("stream_chat") === 1);
  harness.streamStart.resolve({ runId: handle.runId });
  await waitFor(() => harness.commandCount("plugin:event|listen") === 4);

  harness.emit("ai://event", {
    runId: handle.runId,
    type: "todos",
    items: [{ id: 1, text: "enumerate inputs", status: "pending" }],
  });
  harness.emit("ai://event", {
    runId: handle.runId,
    type: "todos",
    items: [
      { id: 1, text: "enumerate inputs", status: "done" },
      { id: 2, text: "trace to sinks", status: "pending" },
    ],
  });

  await waitFor(() => snapshots.length === 2);
  assert.deepEqual(snapshots[1], [
    { id: 1, text: "enumerate inputs", status: "done" },
    { id: 2, text: "trace to sinks", status: "pending" },
  ]);

  harness.emit("ai://done", {
    runId: handle.runId,
    content: "",
    model: null,
    usage: null,
  });
  await handle.finished;
});
