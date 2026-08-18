import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { api } from "./api";
import type {
  AiDonePayload,
  AiStreamEvent,
  AskQuestion,
  ChatRequest,
  Usage,
} from "./types";

export interface StreamHandlers {
  onStarted?: (runId: string) => void;
  onDelta?: (content: string) => void;
  onReasoning?: (content: string) => void;
  onUsage?: (usage: Usage) => void;
  onToolStart?: (tc: { toolCallId: string; name: string; arguments: string }) => void;
  onToolResult?: (tr: {
    toolCallId: string;
    name: string;
    success: boolean;
    durationMs: number;
    resultPreview: string;
  }) => void;
  onPermissionRequest?: (p: { requestId: string; tool: string; arguments: string }) => void;
  onAskUser?: (a: { requestId: string; questions: AskQuestion[] }) => void;
  onDone?: (payload: AiDonePayload) => void;
  onError?: (message: string) => void;
}

export interface StreamHandle {
  /** Client-owned identity, available before listener setup or command invoke. */
  runId: string;
  /** Settles after a matching terminal event, invoke failure, or disposal. */
  finished: Promise<void>;
  /** Waits for backend registration before sending cancellation. */
  cancel: () => Promise<void>;
  /** Stops delivery and tears down this run's listeners. */
  dispose: () => void;
}

/**
 * Start a streaming agent turn: subscribes to the `ai://*` event bus, invokes
 * the `stream_chat` command, and routes events to the handlers. The returned
 * handle exposes the client-owned run id immediately. All listeners are torn
 * down when this run settles (matching done/error, invoke rejection, disposal).
 */
export function streamChat(req: ChatRequest, h: StreamHandlers): StreamHandle {
  const runId = crypto.randomUUID();
  const unlisteners: UnlistenFn[] = [];
  let disposed = false;
  let settled = false;
  let resolveTerminal!: () => void;
  let resolveSetup!: (ready: boolean) => void;
  const terminal = new Promise<void>((resolve) => {
    resolveTerminal = resolve;
  });
  const setup = new Promise<boolean>((resolve) => {
    resolveSetup = resolve;
  });

  const cleanup = () => {
    while (unlisteners.length > 0) {
      try {
        unlisteners.pop()?.();
      } catch {
        /* Listener cleanup is best-effort and idempotent. */
      }
    }
  };

  const settle = (callback?: () => void) => {
    if (disposed || settled) return;
    settled = true;
    try {
      callback?.();
    } finally {
      cleanup();
      resolveTerminal();
    }
  };

  const reportError = (error: unknown) => {
    settle(() => h.onError?.(String(error)));
  };

  const dispatch = (callback: () => void) => {
    if (disposed || settled) return;
    try {
      callback();
    } catch (error) {
      reportError(error);
    }
  };

  const register = async <T>(
    event: string,
    callback: (payload: T) => void,
  ): Promise<boolean> => {
    const unlisten = await listen<T>(event, ({ payload }) => callback(payload));
    if (disposed || settled) {
      unlisten();
      return false;
    }
    unlisteners.push(unlisten);
    return true;
  };

  const launch = (async () => {
    let ready = false;
    try {
      if (
        !(await register<{ runId: string }>("ai://started", (payload) => {
          if (payload.runId === runId) dispatch(() => h.onStarted?.(runId));
        }))
      ) {
        return;
      }
      if (
        !(await register<AiStreamEvent>("ai://event", (ev) => {
          if (ev.runId !== runId) return;
          dispatch(() => {
            switch (ev.type) {
              case "delta":
                h.onDelta?.(ev.content);
                break;
              case "reasoning":
                h.onReasoning?.(ev.content);
                break;
              case "usage":
                h.onUsage?.(ev.usage);
                break;
              case "tool_start":
                h.onToolStart?.({
                  toolCallId: ev.toolCallId,
                  name: ev.name,
                  arguments: ev.arguments,
                });
                break;
              case "tool_result":
                h.onToolResult?.({
                  toolCallId: ev.toolCallId,
                  name: ev.name,
                  success: ev.success,
                  durationMs: ev.durationMs,
                  resultPreview: ev.resultPreview,
                });
                break;
              case "permission_request":
                h.onPermissionRequest?.({
                  requestId: ev.requestId,
                  tool: ev.tool,
                  arguments: ev.arguments,
                });
                break;
              case "ask_user":
                h.onAskUser?.({
                  requestId: ev.requestId,
                  questions: ev.questions,
                });
                break;
            }
          });
        }))
      ) {
        return;
      }
      if (
        !(await register<AiDonePayload>("ai://done", (payload) => {
          if (payload.runId === runId) settle(() => h.onDone?.(payload));
        }))
      ) {
        return;
      }
      if (
        !(await register<{ runId: string; message: string }>(
          "ai://error",
          (payload) => {
            if (payload.runId === runId) {
              settle(() => h.onError?.(payload.message));
            }
          },
        ))
      ) {
        return;
      }

      const started = await api.streamChat(req, runId);
      if (started.runId !== runId) {
        throw new Error("AI stream started with an unexpected run id");
      }
      ready = true;
    } catch (error) {
      if (!disposed) reportError(error);
    } finally {
      resolveSetup(ready);
    }
  })();

  const dispose = () => {
    if (disposed) return;
    disposed = true;
    settled = true;
    cleanup();
    resolveTerminal();
  };

  return {
    runId,
    finished: Promise.all([launch, terminal]).then(() => undefined),
    cancel: async () => {
      const ready = await setup;
      if (ready && !disposed && !settled) await api.cancelChat(runId);
    },
    dispose,
  };
}
