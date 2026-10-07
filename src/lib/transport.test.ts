import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * The server transport is loaded fresh per test: `serverMode` is decided at
 * import time from window globals, so each scenario re-imports the module.
 */
async function loadTransport(serverMode: boolean) {
  vi.resetModules();
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    configurable: true,
    get: () => (serverMode ? undefined : { present: true }),
  });
  window.OXAUDIT_SERVER = serverMode;
  window.localStorage.clear();
  return import("./transport");
}

describe("the server transport", () => {
  const originalFetch = globalThis.fetch;

  class TestEventSource extends EventTarget {
    static CLOSED = 2;
    static instances: TestEventSource[] = [];
    readyState = 1;
    onerror: (() => void) | null = null;
    constructor(readonly url: string) {
      super();
      TestEventSource.instances.push(this);
    }
    close() { this.readyState = TestEventSource.CLOSED; }
    emit(name: string, payload: unknown) {
      this.dispatchEvent(new MessageEvent(name, { data: JSON.stringify(payload) }));
    }
  }

  function eventSources() {
    TestEventSource.instances = [];
    vi.stubGlobal("EventSource", TestEventSource);
    return TestEventSource.instances;
  }

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.unstubAllGlobals();
  });

  it("stays on the desktop transport when Tauri internals are present", async () => {
    const transport = await loadTransport(false);
    expect(transport.serverMode).toBe(false);
  });

  it("switches on when the server flag is served and no Tauri runtime exists", async () => {
    const transport = await loadTransport(true);
    expect(transport.serverMode).toBe(true);
  });

  it("unwraps a successful invoke envelope", async () => {
    const transport = await loadTransport(true);
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true, data: [1, 2, 3] }), { status: 200 }),
    );
    await expect(transport.httpInvoke("list_compiled_grammars")).resolves.toEqual([1, 2, 3]);
  });

  it("throws the command's structured error, matching desktop invoke rejections", async () => {
    const transport = await loadTransport(true);
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: false,
          error: { code: "notFound", message: "missing", detail: null, retryable: false },
        }),
        { status: 200 },
      ),
    );
    await expect(transport.httpInvoke("load_source_run")).rejects.toMatchObject({
      code: "notFound",
    });
  });

  it("fires the unauthorized listeners and names the token on a 401", async () => {
    const transport = await loadTransport(true);
    globalThis.fetch = vi.fn().mockResolvedValue(new Response("", { status: 401 }));
    const listener = vi.fn();
    transport.onUnauthorized(listener);
    transport.setServerToken("stale-token");
    await expect(transport.httpInvoke("quality_status")).rejects.toMatchObject({
      code: "credentialUnavailable",
    });
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("keeps other subscribers connected when an unsubscribe is called twice", async () => {
    const transport = await loadTransport(true);
    const sources = eventSources();
    const first = transport.sseListen("scan://progress", () => {});
    const received: unknown[] = [];
    const second = transport.sseListen("run://event", ({ payload }) => received.push(payload));
    first();
    first();
    expect(sources[0].readyState).toBe(1);
    sources[0].emit("run://event", { phase: "completed" });
    expect(received).toEqual([{ phase: "completed" }]);
    second();
    expect(sources[0].readyState).toBe(TestEventSource.CLOSED);
  });

  it("reconnects existing event subscriptions with an updated token", async () => {
    const transport = await loadTransport(true);
    const sources = eventSources();
    transport.setServerToken("old-token");
    const received: unknown[] = [];
    const release = transport.sseListen("scan://progress", ({ payload }) => received.push(payload));
    transport.setServerToken("new+token");
    expect(sources).toHaveLength(2);
    expect(sources[0].readyState).toBe(TestEventSource.CLOSED);
    expect(sources[1].url).toBe("/api/events?token=new%2Btoken");
    sources[1].emit("scan://progress", { phase: "completed" });
    expect(received).toEqual([{ phase: "completed" }]);
    release();
  });
});
