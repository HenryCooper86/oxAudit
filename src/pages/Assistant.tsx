import { useEffect, useRef, useState } from "react";
import {
  Ban,
  Bot,
  ClipboardPaste,
  Loader2,
  Plus,
  Send,
  Sparkles,
  Trash2,
  User,
} from "lucide-react";
import { TopBar } from "../components/TopBar";
import { ThinkingCard } from "../components/chat/ThinkingCard";
import { ToolCallCard } from "../components/chat/ToolCallCard";
import { ApprovalModal } from "../components/chat/ApprovalModal";
import { AskUserModal } from "../components/chat/AskUserModal";
import { SessionSidebar } from "../components/chat/SessionSidebar";
import { api } from "../lib/api";
import { streamChat } from "../lib/aiEvents";
import { useAppStore, useToastStore } from "../lib/stores";
import type {
  AskQuestion,
  ChatMessage,
  SessionInfo,
  StoredMessage,
  ToolRecord,
  Usage,
  UsageSummary,
} from "../lib/types";
import Markdown from "react-markdown";

const SUGGESTIONS = [
  "Explain the difference between stored, reflected and DOM XSS with code examples.",
  "I found a `pickle.loads()` call on untrusted input — how do I fix it?",
  "Scan this project's source for vulnerabilities and summarize the worst findings.",
  "What should I check when triaging a reported SQL injection in a Java app?",
];

interface UiMessage {
  role: "user" | "assistant";
  content: string;
  tools?: ToolRecord[];
}

interface StreamingState {
  text: string;
  reasoning: string;
  thinking: boolean;
}

interface PermissionPrompt {
  requestId: string;
  tool: string;
  arguments: string;
}

interface AskPrompt {
  requestId: string;
  questions: AskQuestion[];
}

export function AssistantPage() {
  const aiReady = useAppStore((s) => s.aiReady);
  const activeProject = useAppStore((s) => s.activeProject);
  const setActiveProjectStore = useAppStore((s) => s.setActiveProject);
  const push = useToastStore((s) => s.push);

  const [messages, setMessages] = useState<UiMessage[]>([]);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [streaming, setStreaming] = useState<StreamingState>({
    text: "",
    reasoning: "",
    thinking: false,
  });
  const [model, setModel] = useState<string | null>(null);
  const [convUsage, setConvUsage] = useState<UsageSummary | null>(null);
  const [contextOpen, setContextOpen] = useState(false);
  const [contextText, setContextText] = useState("");
  const [permission, setPermission] = useState<PermissionPrompt | null>(null);
  const [askUser, setAskUser] = useState<AskPrompt | null>(null);

  const conversationId = useRef<string>(crypto.randomUUID());
  const runIdRef = useRef<string | null>(null);
  const settledRef = useRef(false);
  const turnToolsRef = useRef<Map<string, ToolRecord>>(new Map());
  const [toolRecords, setToolRecords] = useState<ToolRecord[]>([]);
  const streamingRef = useRef(streaming);
  streamingRef.current = streaming;
  const bottomRef = useRef<HTMLDivElement>(null);

  const refreshUsage = () => {
    api
      .getConversationUsage(conversationId.current)
      .then(setConvUsage)
      .catch(() => undefined);
  };

  const updateSessionInfo = (info: SessionInfo) => {
    setSessions((list) =>
      [...list.filter((s) => s.id !== info.id), info].sort((a, b) =>
        b.updatedAt.localeCompare(a.updatedAt),
      ),
    );
  };

  const loadSession = async (id: string) => {
    const msgs = await api.sessionGetMessages(id);
    setMessages(msgs.map((m) => ({ role: m.role, content: m.content, tools: m.tools })));
    conversationId.current = id;
    setActiveSessionId(id);
    const info = sessions.find((s) => s.id === id);
    if (info?.projectPath) {
      api.setActiveProject(info.projectPath).catch(() => undefined);
      setActiveProjectStore(info.projectPath);
    }
    refreshUsage();
  };

  const createNewChat = async () => {
    try {
      const s = await api.sessionCreate(null, activeProject);
      setSessions((list) => [s, ...list]);
      setMessages([]);
      setConvUsage(null);
      setModel(null);
      conversationId.current = s.id;
      setActiveSessionId(s.id);
    } catch (e) {
      push("error", String(e));
    }
  };

  // load persisted sessions on mount: resume most recent, else create one
  useEffect(() => {
    (async () => {
      try {
        const list = await api.sessionList();
        setSessions(list);
        if (list.length > 0) {
          const msgs = await api.sessionGetMessages(list[0].id);
          setMessages(msgs.map((m) => ({ role: m.role, content: m.content, tools: m.tools })));
          conversationId.current = list[0].id;
          setActiveSessionId(list[0].id);
          if (list[0].projectPath) {
            api.setActiveProject(list[0].projectPath).catch(() => undefined);
            setActiveProjectStore(list[0].projectPath);
          }
          refreshUsage();
        } else {
          await createNewChat();
        }
      } catch {
        await createNewChat();
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, busy, streaming.text, toolRecords]);

  const upsertTool = (rec: ToolRecord) => {
    turnToolsRef.current.set(rec.toolCallId, rec);
    setToolRecords(Array.from(turnToolsRef.current.values()));
  };

  const finalize = (content: string, modelName: string | null, usage: Usage | null) => {
    if (settledRef.current) return;
    settledRef.current = true;
    const tools = Array.from(turnToolsRef.current.values());
    setMessages((m) => [...m, { role: "assistant", content, tools: tools.length ? tools : undefined }]);
    setModel(modelName);
    setBusy(false);
    setStreaming({ text: "", reasoning: "", thinking: false });
    setToolRecords([]);
    turnToolsRef.current.clear();
    runIdRef.current = null;
    if (usage) refreshUsage();
    // persist the assistant message (tools included) to the session transcript
    if (activeSessionId) {
      const stored: StoredMessage = {
        id: crypto.randomUUID(),
        role: "assistant",
        content,
        tools: tools.length ? tools : undefined,
        model: modelName,
        at: new Date().toISOString(),
      };
      api
        .sessionAppend(activeSessionId, stored)
        .then(updateSessionInfo)
        .catch(() => undefined);
    }
  };

  const send = async (text?: string) => {
    const content = (text ?? input).trim();
    if (!content || busy || !activeSessionId) return;
    const history: ChatMessage[] = messages.map((m) => ({ role: m.role, content: m.content }));
    const next: ChatMessage[] = [...history, { role: "user", content }];
    setMessages([...messages, { role: "user", content }]);
    setInput("");
    setBusy(true);
    settledRef.current = false;
    turnToolsRef.current.clear();
    setToolRecords([]);
    setStreaming({ text: "", reasoning: "", thinking: false });

    // persist the user message first so an interruption never loses it
    const stored: StoredMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content,
      at: new Date().toISOString(),
    };
    api
      .sessionAppend(activeSessionId, stored)
      .then(updateSessionInfo)
      .catch(() => undefined);

    await streamChat(
      { messages: next, conversationId: conversationId.current },
      {
        onStarted: (runId) => {
          runIdRef.current = runId;
        },
        onDelta: (c) =>
          setStreaming((s) => ({ ...s, text: s.text + c, thinking: false })),
        onReasoning: (c) =>
          setStreaming((s) => ({ ...s, reasoning: s.reasoning + c, thinking: true })),
        onUsage: () => undefined,
        onToolStart: (tc) =>
          upsertTool({
            toolCallId: tc.toolCallId,
            name: tc.name,
            arguments: tc.arguments,
            status: "running",
            durationMs: null,
            resultPreview: null,
          }),
        onToolResult: (tr) => {
          const prev = turnToolsRef.current.get(tr.toolCallId);
          upsertTool({
            toolCallId: tr.toolCallId,
            name: prev?.name ?? tr.name,
            arguments: prev?.arguments ?? "",
            status: tr.success ? "success" : "error",
            durationMs: tr.durationMs,
            resultPreview: tr.resultPreview,
          });
        },
        onPermissionRequest: (p) => setPermission(p),
        onAskUser: (a) => setAskUser(a),
        onDone: (payload) => finalize(payload.content, payload.model, payload.usage),
        onError: (message) => {
          if (settledRef.current) return;
          const partial = streamingRef.current.text.trim();
          const tools = Array.from(turnToolsRef.current.values());
          settledRef.current = true;
          setBusy(false);
          runIdRef.current = null;
          setToolRecords([]);
          turnToolsRef.current.clear();
          if (partial || tools.length) {
            setMessages((m) => [
              ...m,
              {
                role: "assistant",
                content: partial
                  ? `${partial}\n\n_— interrupted (${message})_`
                  : `_— interrupted (${message})_`,
                tools: tools.length ? tools : undefined,
              },
            ]);
            setStreaming({ text: "", reasoning: "", thinking: false });
          } else {
            setStreaming({ text: "", reasoning: "", thinking: false });
            if (!message.toLowerCase().includes("cancelled")) {
              push("error", message);
            }
          }
        },
      },
    );
  };

  const cancel = async () => {
    if (runIdRef.current) {
      try {
        await api.cancelChat(runIdRef.current);
      } catch {
        /* ignore */
      }
    }
  };

  const addContext = () => {
    if (!contextText.trim()) return;
    const note =
      "[Context attached by user — treat the following as additional source material for your analysis]\n\n```\n" +
      contextText +
      "\n```";
    setMessages([...messages, { role: "user", content: note }]);
    setContextText("");
    setContextOpen(false);
  };

  const showThinking = streaming.thinking || streaming.reasoning.trim().length > 0;

  return (
    <div className="flex h-full overflow-hidden">
      <SessionSidebar
        sessions={sessions}
        activeId={activeSessionId}
        busy={busy}
        onSelect={(id) => {
          if (id !== activeSessionId && !busy) {
            loadSession(id).catch(() => undefined);
          }
        }}
        onCreate={() => {
          if (!busy) createNewChat();
        }}
        onRename={(id, title) => {
          api
            .sessionRename(id, title)
            .then(() => {
              const info = sessions.find((s) => s.id === id);
              if (info) updateSessionInfo({ ...info, title, autoTitle: false });
            })
            .catch(() => undefined);
        }}
        onDelete={async (id) => {
          await api.sessionDelete(id).catch(() => undefined);
          setSessions((list) => list.filter((s) => s.id !== id));
          if (id === activeSessionId) {
            createNewChat();
          }
        }}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
        title="AI Assistant"
        subtitle={
          aiReady === null
            ? "AI not configured — enable it in Settings"
            : aiReady
              ? "OpenAI-compatible endpoint connected · agent tools active"
              : "Endpoint unreachable — check Settings"
        }
        actions={
          <>
            {model && (
              <span className="rounded border border-ink-600 bg-ink-850 px-2 py-1 font-mono text-[10px] text-slate-400">
                {model}
              </span>
            )}
            <button
              onClick={() => setContextOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-xs text-slate-300 hover:border-ink-500"
            >
              <ClipboardPaste size={13} /> Attach context
            </button>
            <button
              onClick={async () => {
                setMessages([]);
                setConvUsage(null);
                setModel(null);
                setToolRecords([]);
                turnToolsRef.current.clear();
                if (activeSessionId) {
                  await api.sessionTruncate(activeSessionId, 0).catch(() => undefined);
                  const info = sessions.find((s) => s.id === activeSessionId);
                  if (info) updateSessionInfo({ ...info, messageCount: 0 });
                }
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-ink-600 bg-ink-850 px-3 py-1.5 text-xs text-slate-400 hover:border-red-500/40 hover:text-red-300"
            >
              <Trash2 size={13} /> Clear
            </button>
          </>
        }
      />

      <div className="mx-auto flex w-full max-w-3xl flex-1 flex-col overflow-y-auto px-6 py-5">
        {messages.length === 0 && !busy && (
          <div className="flex flex-1 flex-col items-center justify-center gap-5 pb-10">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-teal-500 to-emerald-600 shadow-xl shadow-teal-900/40">
              <Bot size={26} className="text-ink-950" />
            </div>
            <div className="text-center">
              <h2 className="text-base font-bold text-slate-100">Ask your security copilot</h2>
              <p className="mx-auto mt-1 max-w-sm text-xs leading-relaxed text-slate-500">
                The agent can read files, grep and scan the active project, look up CVEs and
                OSV advisories, and fetch web pages — all permission-gated. Responses stream
                in live, with tools and thinking shown as they happen.
              </p>
            </div>
            <div className="grid w-full max-w-lg gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  disabled={busy}
                  className="rounded-lg border border-ink-700 bg-ink-850 px-3.5 py-2.5 text-left text-xs text-slate-400 transition-colors hover:border-teal-500/40 hover:text-slate-200 disabled:opacity-40"
                >
                  <Sparkles size={11} className="mr-1.5 inline text-teal-400" />
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="space-y-4">
          {messages.map((m, i) => (
            <div key={i} className={`flex gap-2.5 ${m.role === "user" ? "justify-end" : ""}`}>
              {m.role !== "user" && (
                <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-teal-500 to-emerald-600">
                  <Bot size={14} className="text-ink-950" />
                </div>
              )}
              <div className="min-w-0 max-w-[85%] flex-1">
                {m.tools && m.tools.length > 0 && (
                  <div className="mb-1.5 space-y-1">
                    {m.tools.map((t) => (
                      <ToolCallCard key={t.toolCallId} record={t} />
                    ))}
                  </div>
                )}
                <div
                  className={`rounded-xl px-4 py-3 text-xs ${
                    m.role === "user"
                      ? "ml-auto rounded-tr-sm bg-teal-500/15 text-slate-200"
                      : "selectable md-body rounded-tl-sm border border-ink-700 bg-ink-850 text-slate-300"
                  }`}
                >
                  {m.role === "user" ? (
                    <div className="whitespace-pre-wrap leading-relaxed">{m.content}</div>
                  ) : (
                    <Markdown>{m.content}</Markdown>
                  )}
                </div>
              </div>
              {m.role === "user" && (
                <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-ink-750">
                  <User size={14} className="text-slate-400" />
                </div>
              )}
            </div>
          ))}

          {busy && (
            <div className="flex gap-2.5">
              <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-teal-500 to-emerald-600">
                <Bot size={14} className="text-ink-950" />
              </div>
              <div className="min-w-0 max-w-[85%] flex-1">
                {toolRecords.length > 0 && (
                  <div className="mb-1.5 space-y-1">
                    {toolRecords.map((t) => (
                      <ToolCallCard key={t.toolCallId} record={t} />
                    ))}
                  </div>
                )}
                {showThinking && (
                  <ThinkingCard text={streaming.reasoning} streaming={streaming.thinking} />
                )}
                {streaming.text && (
                  <div className="selectable md-body rounded-tl-sm rounded-xl border border-ink-700 bg-ink-850 px-4 py-3 text-xs text-slate-300">
                    <Markdown>{streaming.text}</Markdown>
                    <span className="ml-0.5 inline-block h-3.5 w-[7px] animate-pulse rounded-[2px] bg-teal-400 align-middle" />
                  </div>
                )}
                {!streaming.text && toolRecords.length === 0 && (
                  <div className="flex items-center gap-2 rounded-xl border border-ink-700 bg-ink-850 px-4 py-3 text-xs text-slate-500">
                    <Loader2 size={14} className="animate-spin" />
                    {showThinking ? "Reasoning…" : "Waiting for response…"}
                  </div>
                )}
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>
      </div>

      <div className="border-t border-ink-800 bg-ink-900/80 px-6 py-4 backdrop-blur">
        <div className="mx-auto flex w-full max-w-3xl items-center gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                send();
              }
            }}
            placeholder="Ask about a vulnerability, CVE, exploit pattern, or ask the agent to scan the project…"
            className="selectable flex-1 rounded-lg border border-ink-600 bg-ink-950 px-3.5 py-2.5 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
          />
          {busy ? (
            <button
              onClick={cancel}
              title="Cancel response"
              className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20"
            >
              <Ban size={16} />
            </button>
          ) : (
            <button
              onClick={() => send()}
              disabled={!input.trim() || busy || aiReady !== true}
              className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 text-ink-950 shadow-lg shadow-teal-900/30 transition-opacity hover:opacity-90 disabled:opacity-40"
            >
              <Send size={16} />
            </button>
          )}
        </div>
        <div className="mx-auto mt-1.5 flex max-w-3xl items-center justify-between text-[10px] text-slate-600">
          <span>Enter to send · Shift+Enter for newline · agent tools active</span>
          {convUsage && (
            <span className="tabular-nums">
              {model ? `${model} · ` : ""}
              {(convUsage.totalTokens / 1000).toFixed(1)}k tokens · $
              {convUsage.costUsd.toFixed(4)}
            </span>
          )}
        </div>
      </div>

      {permission && (
        <ApprovalModal
          tool={permission.tool}
          argumentsPreview={permission.arguments}
          onDecide={(approve) => {
            api.respondPermission(permission.requestId, approve).catch(() => undefined);
            setPermission(null);
          }}
        />
      )}

      {askUser && (
        <AskUserModal
          requestId={askUser.requestId}
          questions={askUser.questions}
          onClose={() => setAskUser(null)}
        />
      )}

      {contextOpen && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-6" onClick={() => setContextOpen(false)}>
          <div className="w-full max-w-xl rounded-xl border border-ink-600 bg-ink-850 p-5" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                <Plus size={15} className="text-teal-400" /> Attach code / context
              </h3>
              <button onClick={() => setContextOpen(false)} className="text-slate-500 hover:text-slate-300">
                ✕
              </button>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Paste code, configs, error logs or advisory text. It will be sent as a user message the model treats as source material.
            </p>
            <textarea
              value={contextText}
              onChange={(e) => setContextText(e.target.value)}
              rows={8}
              placeholder="Paste here…"
              className="selectable mt-3 w-full resize-none rounded-lg border border-ink-600 bg-ink-950 px-3 py-2 font-mono text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-teal-500/60"
            />
            <button
              onClick={addContext}
              disabled={!contextText.trim()}
              className="mt-3 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-teal-500 to-emerald-500 px-4 py-2 text-xs font-bold text-ink-950 hover:opacity-90 disabled:opacity-40"
            >
              <ClipboardPaste size={13} /> Attach to conversation
            </button>
          </div>
        </div>
      )}
      </div>
    </div>
  );
}
