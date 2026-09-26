import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
});
