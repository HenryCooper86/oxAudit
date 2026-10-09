/**
 * Transport detection and the HTTP/SSE transport for the headless server.
 *
 * The desktop app talks to its engine through Tauri's `invoke` and event
 * system. The headless server serves the same frontend from the same port
 * as its API, so here the same `api.*` calls go over fetch, and the same
 * event subscriptions ride one SSE stream — the page code does not know
 * the difference.
 *
 * Detection: in a Tauri webview the runtime injects
 * `window.__TAURI_INTERNALS__`. The server injects `/env.js`, which sets
 * `window.OXAUDIT_SERVER = true`. Both signals must agree that this is a
 * browser before the transport switches, so a plain vite dev session
 * (neither signal) keeps the desktop behavior and the test harness stays
 * on the mocked Tauri path.
 */

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
    OXAUDIT_SERVER?: boolean;
  }
}

export const serverMode: boolean =
  typeof window !== "undefined" &&
  !window.__TAURI_INTERNALS__ &&
  window.OXAUDIT_SERVER === true;

const TOKEN_KEY = "oxaudit-server-token";

let storedToken = "";
if (serverMode) {
  try {
    storedToken = localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    // Storage restrictions must not prevent connecting for this session.
  }
}

type UnauthorizedListener = () => void;
const unauthorizedListeners = new Set<UnauthorizedListener>();

/** Called when any API call is rejected for a missing/invalid token. */
export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

export function serverToken(): string {
  return storedToken;
}

export function setServerToken(token: string): void {
  const previousToken = storedToken;
  storedToken = token.trim();
  try {
    if (storedToken) localStorage.setItem(TOKEN_KEY, storedToken);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    // Keep the in-memory token when persistence is unavailable.
  }
  if (source && previousToken !== storedToken) {
    source.close();
    source = null;
    ensureSource();
  }
}

/**
 * The invoke replacement for server mode. Errors arrive as the same shapes
 * the desktop's invoke rejects with — either the command's structured
 * `CommandError` or a plain string — so `normalizeCommandError` downstream
 * needs no changes.
 */
export async function httpInvoke<T>(cmd: string, args?: unknown): Promise<T> {
  const requestedToken = storedToken;
  const response = await fetch(`/api/invoke/${encodeURIComponent(cmd)}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(requestedToken ? { authorization: `Bearer ${requestedToken}` } : {}),
    },
    body: JSON.stringify(args ?? {}),
  });
  if (response.status === 401) {
    if (requestedToken === storedToken) {
      unauthorizedListeners.forEach((listener) => listener());
    }
    throw {
      code: "credentialUnavailable",
      message: "This server requires an access token.",
      detail: null,
      retryable: false,
    };
  }
  if (!response.ok) {
    throw `The server returned ${response.status}.`;
  }
  const body = (await response.json()) as
    | { ok: true; data: T }
    | { ok: false; error: unknown };
  if (!body.ok) throw body.error;
  return body.data;
}

/**
 * The listen replacement for server mode: one shared EventSource carries
 * every event as `{event, payload}` SSE frames; subscribers filter by name,
 * exactly like the desktop's per-event channels.
 */
type Handler = (event: { payload: unknown }) => void;
const eventListeners = new Map<string, Set<Handler>>();
let source: EventSource | null = null;
let sourceRefcount = 0;
let connectionSequence = 0;
let hasConnected = false;

export interface TransportReconnectedPayload {
  /** Identifies the current EventSource, including automatic retries. */
  connectionId: number;
  occurredAt: string;
  reason: "retry" | "replacement";
}

export interface TransportLaggedPayload {
  connectionId: number;
  occurredAt: string;
  /** Null when the server's count cannot be represented reliably. */
  missedEvents: number | null;
}

function emit(event: string, payload: unknown): void {
  for (const listener of eventListeners.get(event) ?? []) listener({ payload });
}

function parseFrame(message: Event): unknown {
  const frame = message as MessageEvent<string>;
  try {
    return JSON.parse(frame.data);
  } catch {
    return frame.data;
  }
}

function listenForEvent(src: EventSource, event: string): void {
  src.addEventListener(event, (message) => {
    if (source === src) emit(event, parseFrame(message));
  });
}

function ensureSource(): EventSource {
  if (source && source.readyState !== EventSource.CLOSED) return source;
  const token = encodeURIComponent(storedToken);
  const created = new EventSource(`/api/events${token ? `?token=${token}` : ""}`);
  source = created;
  const connectionId = ++connectionSequence;
  let opened = false;
  // Recovery names are local transport events, never server subscriptions.
  for (const event of eventListeners.keys()) {
    if (!event.startsWith("transport://")) listenForEvent(created, event);
  }
  created.addEventListener("hub://lagged", (message) => {
    if (source !== created) return;
    const frame = parseFrame(message);
    const missed = frame && typeof frame === "object" && "missed" in frame ? frame.missed : null;
    emit("transport://lagged", {
      connectionId,
      occurredAt: new Date().toISOString(),
      missedEvents: typeof missed === "number" && Number.isSafeInteger(missed) && missed >= 0 ? missed : null,
    } satisfies TransportLaggedPayload);
  });
  created.onopen = () => {
    if (source !== created) return;
    if (hasConnected) {
      emit("transport://reconnected", {
        connectionId,
        occurredAt: new Date().toISOString(),
        reason: opened ? "retry" : "replacement",
      } satisfies TransportReconnectedPayload);
    }
    opened = true;
    hasConnected = true;
  };
  created.onerror = () => {
    // EventSource retries on its own; a 401 stops it for good, so surface
    // the token gate.
    if (source === created && created.readyState === EventSource.CLOSED) {
      unauthorizedListeners.forEach((listener) => listener());
    }
  };
  return source;
}

export function sseListen<T>(
  event: string,
  handler: (event: { payload: T }) => void,
): () => void {
  const src = ensureSource();
  sourceRefcount += 1;
  let set = eventListeners.get(event);
  if (!set) {
    set = new Set();
    eventListeners.set(event, set);
    if (!event.startsWith("transport://")) listenForEvent(src, event);
  }
  const entry: Handler = (message) => handler(message as { payload: T });
  set.add(entry);
  return () => {
    if (!set!.delete(entry)) return;
    sourceRefcount -= 1;
    if (sourceRefcount === 0) {
      source?.close();
      source = null;
      eventListeners.clear();
    }
  };
}
