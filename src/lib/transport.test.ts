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
    onopen: (() => void) | null = null;
    onerror: (() => void) | null = null;
    constructor(readonly url: string) {
      super();
      TestEventSource.instances.push(this);
    }
    close() { this.readyState = TestEventSource.CLOSED; }
    open() { this.readyState = 1; this.onopen?.(); }
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

  it("can start and authenticate when browser storage is unavailable", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new DOMException("Blocked", "SecurityError"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Full", "QuotaExceededError"); });
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new DOMException("Blocked", "SecurityError"); });
    const transport = await loadTransport(true);
    expect(transport.serverToken()).toBe("");
    transport.setServerToken("session-token");
    globalThis.fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true, data: 42 })));
    await expect(transport.httpInvoke("quality_status")).resolves.toBe(42);
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({
      headers: expect.objectContaining({ authorization: "Bearer session-token" }),
    }));
    transport.setServerToken("");
    expect(transport.serverToken()).toBe("");
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

  it("an old request's 401 cannot reject a newly entered token", async () => {
    const transport = await loadTransport(true);
    let respond!: (response: Response) => void;
    globalThis.fetch = vi.fn().mockReturnValue(new Promise((resolve) => { respond = resolve; }));
    const rejected = vi.fn();
    transport.onUnauthorized(rejected);
    transport.setServerToken("old-token");
    const request = transport.httpInvoke("quality_status");
    const failure = expect(request).rejects.toMatchObject({ code: "credentialUnavailable" });
    transport.setServerToken("new-token");
    respond(new Response("", { status: 401 }));
    await failure;
    expect(rejected).not.toHaveBeenCalled();
    expect(transport.serverToken()).toBe("new-token");
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

  it("reconciles after retries but does not call the first connection a reconnect", async () => {
    const transport = await loadTransport(true);
    const sources = eventSources();
    const recovery: unknown[] = [];
    const release = transport.sseListen("transport://reconnected", ({ payload }) => recovery.push(payload));
    sources[0].open();
    expect(recovery).toEqual([]);
    sources[0].readyState = 0;
    sources[0].onerror?.();
    sources[0].open();
    expect(recovery).toEqual([expect.objectContaining({
      reason: "retry", connectionId: 1, occurredAt: expect.any(String),
    })]);
    release();
  });

  it("reports dropped frames without requiring a subscriber to the backend hub event", async () => {
    const transport = await loadTransport(true);
    const sources = eventSources();
    const recovery: unknown[] = [];
    const release = transport.sseListen("transport://lagged", ({ payload }) => recovery.push(payload));
    sources[0].emit("hub://lagged", { missed: 87 });
    sources[0].emit("hub://lagged", { missed: "unknown" });
    expect(recovery).toEqual([
      expect.objectContaining({ connectionId: 1, occurredAt: expect.any(String), missedEvents: 87 }),
      expect.objectContaining({ connectionId: 1, occurredAt: expect.any(String), missedEvents: null }),
    ]);
    release();
  });

  it("reports stream replacement after token rotation and ignores stale stream recovery", async () => {
    const transport = await loadTransport(true);
    const sources = eventSources();
    const reconnected: unknown[] = [];
    const lagged: unknown[] = [];
    const release = transport.sseListen("transport://reconnected", ({ payload }) => reconnected.push(payload));
    const releaseLag = transport.sseListen("transport://lagged", ({ payload }) => lagged.push(payload));
    sources[0].open();
    transport.setServerToken("replacement-token");
    sources[0].open();
    sources[0].emit("hub://lagged", { missed: 3 });
    expect(reconnected).toEqual([]);
    expect(lagged).toEqual([]);
    sources[1].open();
    expect(reconnected).toEqual([expect.objectContaining({ reason: "replacement", connectionId: 2 })]);
    release();
    releaseLag();
  });
});
