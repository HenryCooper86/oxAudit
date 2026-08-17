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

/**
 * Start a streaming agent turn: subscribes to the `ai://*` event bus, invokes
 * the `stream_chat` command, and routes events to the handlers. All listeners
 * are torn down when the turn settles (done/error/invoke rejection).
 */
export async function streamChat(req: ChatRequest, h: StreamHandlers): Promise<void> {
  const unlisteners: UnlistenFn[] = [];
  const track = (p: Promise<UnlistenFn>) => p.then((f) => unlisteners.push(f));

  track(
    listen<{ runId: string }>("ai://started", (e) => h.onStarted?.(e.payload.runId)),
  );
  track(
    listen<AiStreamEvent>("ai://event", (e) => {
      const ev = e.payload;
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
    }),
  );
  track(
    listen<AiDonePayload>("ai://done", (e) => h.onDone?.(e.payload)),
  );
  track(
    listen<{ runId: string; message: string }>("ai://error", (e) => h.onError?.(e.payload.message)),
  );

  try {
    await api.streamChat(req);
  } catch (e) {
    h.onError?.(String(e));
  } finally {
    unlisteners.forEach((f) => f());
  }
}
