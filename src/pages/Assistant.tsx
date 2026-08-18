import { useEffect, useRef, useState, type MouseEvent } from "react";
import {
  Ban,
  Bot,
  ClipboardPaste,
  FolderOpen,
  Loader2,
  Send,
  Settings2,
  Sparkles,
  Trash2,
  User,
  X,
} from "lucide-react";
import Markdown from "react-markdown";
import { ApprovalModal } from "../components/chat/ApprovalModal";
import { AskUserModal } from "../components/chat/AskUserModal";
import { SessionSidebar } from "../components/chat/SessionSidebar";
import { ThinkingCard } from "../components/chat/ThinkingCard";
import { ToolCallCard } from "../components/chat/ToolCallCard";
import { streamChat } from "../lib/aiEvents";
import { api } from "../lib/api";
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

const SUGGESTIONS = [
  "Explain the difference between stored, reflected and DOM XSS with code examples.",
  "I found a `pickle.loads()` call on untrusted input — how do I fix it?",
  "Help me build a focused checklist for reviewing an authentication flow.",
  "What should I check when triaging a reported SQL injection in a Java app?",
];

interface UiMessage {
  id: string;
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
  const aiReady = useAppStore((state) => state.aiReady);
  const assistantHandoff = useAppStore((state) => state.assistantHandoff);
  const clearAssistantHandoff = useAppStore(
    (state) => state.clearAssistantHandoff,
  );
  const setActiveProjectStore = useAppStore(
    (state) => state.setActiveProject,
  );
  const setPage = useAppStore((state) => state.setPage);
  const push = useToastStore((state) => state.push);

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
  const [contextLabel, setContextLabel] = useState("Manual context");
  const [contextProjectPath, setContextProjectPath] = useState<string | null>(
    null,
  );
  const [contextAttaching, setContextAttaching] = useState(false);
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
  const contextCloseRef = useRef<HTMLButtonElement>(null);
  const contextDialogRef = useRef<HTMLElement>(null);
  const contextReturnFocusRef = useRef<HTMLElement | null>(null);
  const contextAttachPendingRef = useRef(false);
  const activeSessionIdRef = useRef(activeSessionId);
  activeSessionIdRef.current = activeSessionId;
  const assistantRootRef = useRef<HTMLDivElement>(null);
  const assistantFallbackRef = useRef<HTMLElement>(null);

  const activeSession =
    sessions.find((session) => session.id === activeSessionId) ?? null;

  const closeContext = () => {
    const returnFocus = contextReturnFocusRef.current;
    contextReturnFocusRef.current = null;
    setContextOpen(false);
    setContextText("");
    setContextLabel("Manual context");
    setContextProjectPath(null);
    setContextAttaching(false);
    requestAnimationFrame(() => {
      if (returnFocus?.isConnected) returnFocus.focus();
      else assistantFallbackRef.current?.focus();
    });
  };

  const discardContext = () => {
    if (contextAttachPendingRef.current) return;
    closeContext();
  };

  const refreshUsage = () => {
    api
      .getConversationUsage(conversationId.current)
      .then(setConvUsage)
      .catch(() => undefined);
  };

  const updateSessionInfo = (info: SessionInfo) => {
    setSessions((list) =>
      [...list.filter((session) => session.id !== info.id), info].sort((a, b) =>
        b.updatedAt.localeCompare(a.updatedAt),
      ),
    );
  };

  const applyRuntimeProject = async (projectPath: string | null) => {
    await api.setActiveProject(projectPath);
    setActiveProjectStore(projectPath);
  };

  const loadSession = async (id: string) => {
    const storedMessages = await api.sessionGetMessages(id);
    const info = sessions.find((session) => session.id === id);
    await applyRuntimeProject(info?.projectPath ?? null);
    setMessages(
      storedMessages.map((message) => ({
        id: message.id,
        role: message.role,
        content: message.content,
        tools: message.tools,
      })),
    );
    conversationId.current = id;
    setActiveSessionId(id);
    setModel(null);
    refreshUsage();
  };

  const createNewChat = async () => {
    try {
      const session = await api.sessionCreate(null, null);
      await applyRuntimeProject(null);
      setSessions((list) => [session, ...list]);
      setMessages([]);
      setConvUsage(null);
      setModel(null);
      conversationId.current = session.id;
      setActiveSessionId(session.id);
    } catch (error) {
      push("error", String(error));
    }
  };

  useEffect(() => {
    void (async () => {
      try {
        const list = await api.sessionList();
        setSessions(list);
        if (list.length > 0) {
          const storedMessages = await api.sessionGetMessages(list[0].id);
          await applyRuntimeProject(list[0].projectPath);
          setMessages(
            storedMessages.map((message) => ({
              id: message.id,
              role: message.role,
              content: message.content,
              tools: message.tools,
            })),
          );
          conversationId.current = list[0].id;
          setActiveSessionId(list[0].id);
          refreshUsage();
        } else {
          await createNewChat();
        }
      } catch {
        await createNewChat();
      }
    })();
    // The Assistant owns this one-time session bootstrap.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!assistantHandoff) return;
    contextReturnFocusRef.current = null;
    setContextText(assistantHandoff.content);
    setContextLabel(assistantHandoff.label);
    setContextProjectPath(assistantHandoff.projectPath);
    setContextOpen(true);
    clearAssistantHandoff();
  }, [assistantHandoff, clearAssistantHandoff]);

  useEffect(() => {
    const behavior = window.matchMedia("(prefers-reduced-motion: reduce)")
      .matches
      ? "auto"
      : "smooth";
    bottomRef.current?.scrollIntoView({ behavior });
  }, [messages, busy, streaming.text, toolRecords]);

  useEffect(() => {
    if (!contextOpen) return;
    const focusFrame = requestAnimationFrame(() =>
      contextCloseRef.current?.focus(),
    );
    const root = assistantRootRef.current;
    const main = root?.closest("main");
    const shellSection = main?.parentElement;
    const appShell = shellSection?.parentElement;
    const outsideRegions = [
      ...Array.from(main?.children ?? []).filter((element) => element !== root),
      ...Array.from(shellSection?.children ?? []).filter(
        (element) => element !== main,
      ),
      ...Array.from(appShell?.children ?? []).filter(
        (element) => element !== shellSection,
      ),
    ] as HTMLElement[];
    const previousIsolation = outsideRegions.map((element) => ({
      element,
      inert: element.inert,
      ariaHidden: element.getAttribute("aria-hidden"),
    }));
    for (const { element } of previousIsolation) {
      element.inert = true;
      element.setAttribute("aria-hidden", "true");
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (!contextAttachPendingRef.current) {
          event.preventDefault();
          discardContext();
        }
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = contextDialogRef.current;
      if (!dialog) return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      if (
        event.shiftKey &&
        (document.activeElement === first || !dialog.contains(document.activeElement))
      ) {
        event.preventDefault();
        last.focus();
      } else if (
        !event.shiftKey &&
        (document.activeElement === last || !dialog.contains(document.activeElement))
      ) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", onKeyDown);
      for (const { element, inert, ariaHidden } of previousIsolation) {
        element.inert = inert;
        if (ariaHidden === null) element.removeAttribute("aria-hidden");
        else element.setAttribute("aria-hidden", ariaHidden);
      }
    };
  }, [contextOpen]);

  const upsertTool = (record: ToolRecord) => {
    turnToolsRef.current.set(record.toolCallId, record);
    setToolRecords(Array.from(turnToolsRef.current.values()));
  };

  const finalize = (
    content: string,
    modelName: string | null,
    usage: Usage | null,
  ) => {
    if (settledRef.current) return;
    settledRef.current = true;
    const tools = Array.from(turnToolsRef.current.values());
    const stored: StoredMessage = {
      id: crypto.randomUUID(),
      role: "assistant",
      content,
      tools: tools.length ? tools : undefined,
      model: modelName,
      at: new Date().toISOString(),
    };
    setMessages((current) => [
      ...current,
      {
        id: stored.id,
        role: stored.role,
        content: stored.content,
        tools: stored.tools,
      },
    ]);
    setModel(modelName);
    setBusy(false);
    setStreaming({ text: "", reasoning: "", thinking: false });
    setToolRecords([]);
    turnToolsRef.current.clear();
    runIdRef.current = null;
    if (usage) refreshUsage();
    if (activeSessionId) {
      api
        .sessionAppend(activeSessionId, stored)
        .then(updateSessionInfo)
        .catch(() => undefined);
    }
  };

  const send = async (text?: string) => {
    const content = (text ?? input).trim();
    if (!content || busy || !activeSessionId || aiReady !== true) return;
    const history: ChatMessage[] = messages.map((message) => ({
      role: message.role,
      content: message.content,
    }));
    const next: ChatMessage[] = [...history, { role: "user", content }];
    const stored: StoredMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content,
      at: new Date().toISOString(),
    };
    setMessages((current) => [
      ...current,
      { id: stored.id, role: stored.role, content: stored.content },
    ]);
    setInput("");
    setBusy(true);
    settledRef.current = false;
    turnToolsRef.current.clear();
    setToolRecords([]);
    setStreaming({ text: "", reasoning: "", thinking: false });

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
        onDelta: (chunk) =>
          setStreaming((current) => ({
            ...current,
            text: current.text + chunk,
            thinking: false,
          })),
        onReasoning: (chunk) =>
          setStreaming((current) => ({
            ...current,
            reasoning: current.reasoning + chunk,
            thinking: true,
          })),
        onUsage: () => undefined,
        onToolStart: (toolCall) =>
          upsertTool({
            toolCallId: toolCall.toolCallId,
            name: toolCall.name,
            arguments: toolCall.arguments,
            status: "running",
            durationMs: null,
            resultPreview: null,
          }),
        onToolResult: (toolResult) => {
          const previous = turnToolsRef.current.get(toolResult.toolCallId);
          upsertTool({
            toolCallId: toolResult.toolCallId,
            name: previous?.name ?? toolResult.name,
            arguments: previous?.arguments ?? "",
            status: toolResult.success ? "success" : "error",
            durationMs: toolResult.durationMs,
            resultPreview: toolResult.resultPreview,
          });
        },
        onPermissionRequest: (prompt) => setPermission(prompt),
        onAskUser: (prompt) => setAskUser(prompt),
        onDone: (payload) =>
          finalize(payload.content, payload.model, payload.usage),
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
            setMessages((current) => [
              ...current,
              {
                id: crypto.randomUUID(),
                role: "assistant",
                content: partial
                  ? `${partial}\n\n_— interrupted (${message})_`
                  : `_— interrupted (${message})_`,
                tools: tools.length ? tools : undefined,
              },
            ]);
          } else if (!message.toLowerCase().includes("cancelled")) {
            push("error", message);
          }
          setStreaming({ text: "", reasoning: "", thinking: false });
        },
      },
    );
  };

  const cancel = async () => {
    if (!runIdRef.current) return;
    try {
      await api.cancelChat(runIdRef.current);
    } catch {
      /* The stream error event remains the source of cancellation state. */
    }
  };

  const attachContext = async () => {
    const targetSessionId = activeSessionIdRef.current;
    if (
      contextAttachPendingRef.current ||
      !contextText.trim() ||
      !targetSessionId
    ) {
      return;
    }
    const stored: StoredMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content: `[User-attached source context: ${contextLabel}]\n\n${contextText}`,
      at: new Date().toISOString(),
    };
    contextAttachPendingRef.current = true;
    setContextAttaching(true);
    try {
      const info = await api.sessionAppend(targetSessionId, stored);
      if (activeSessionIdRef.current === targetSessionId) {
        setMessages((current) => [
          ...current,
          { id: stored.id, role: stored.role, content: stored.content },
        ]);
      }
      updateSessionInfo(info);
      contextAttachPendingRef.current = false;
      setContextAttaching(false);
      closeContext();
    } catch (error) {
      push("error", `Context could not be attached: ${String(error)}`);
    } finally {
      contextAttachPendingRef.current = false;
      setContextAttaching(false);
    }
  };

  const clearConversation = async () => {
    setMessages([]);
    setConvUsage(null);
    setModel(null);
    setToolRecords([]);
    turnToolsRef.current.clear();
    if (!activeSessionId) return;
    await api.sessionTruncate(activeSessionId, 0).catch(() => undefined);
    const info = sessions.find((session) => session.id === activeSessionId);
    if (info) updateSessionInfo({ ...info, messageCount: 0 });
  };

  const openManualContext = (event: MouseEvent<HTMLButtonElement>) => {
    contextReturnFocusRef.current = event.currentTarget;
    setContextLabel("Manual context");
    setContextText("");
    setContextProjectPath(null);
    setContextOpen(true);
  };

  const showThinking =
    streaming.thinking || streaming.reasoning.trim().length > 0;
  const availabilityLabel =
    aiReady === true
      ? "AI ready"
      : aiReady === false
        ? "AI endpoint unavailable"
        : "AI not configured";

  return (
    <div
      ref={assistantRootRef}
      className="relative h-full min-h-0 overflow-hidden bg-ink-950"
    >
      <div
        inert={contextOpen}
        aria-hidden={contextOpen ? "true" : undefined}
        className="flex h-full min-h-0"
      >
        <SessionSidebar
        sessions={sessions}
        activeId={activeSessionId}
        busy={busy}
        onSelect={(id) => {
          if (id !== activeSessionId && !busy) {
            loadSession(id).catch((error) => push("error", String(error)));
          }
        }}
        onCreate={() => {
          if (!busy) void createNewChat();
        }}
        onRename={(id, title) => {
          api
            .sessionRename(id, title)
            .then(() => {
              const info = sessions.find((session) => session.id === id);
              if (info) updateSessionInfo({ ...info, title, autoTitle: false });
            })
            .catch(() => undefined);
        }}
        onDelete={async (id) => {
          await api.sessionDelete(id).catch(() => undefined);
          setSessions((list) =>
            list.filter((session) => session.id !== id),
          );
          if (id === activeSessionId) await createNewChat();
        }}
        />

        <section
          ref={assistantFallbackRef}
          tabIndex={-1}
          aria-label="Assistant conversation"
          className="flex min-w-0 flex-1 flex-col"
        >
        <header className="flex min-h-[52px] shrink-0 flex-wrap items-center justify-between gap-2 border-b border-ink-800 bg-ink-900/80 px-4 py-2">
          <div className="min-w-0">
            <p className="text-[13px] font-semibold text-stone-200">
              Conversation
            </p>
            <p className="mt-0.5 flex items-center gap-1.5 text-[11px] text-stone-400">
              <span
                aria-hidden="true"
                className={`h-1.5 w-1.5 rounded-full ${
                  aiReady === true
                    ? "bg-emerald-400"
                    : aiReady === false
                      ? "bg-red-400"
                      : "bg-stone-500"
                }`}
              />
              {availabilityLabel}
            </p>
          </div>

          <div className="flex min-w-0 flex-wrap items-center justify-end gap-1.5">
            {activeSession?.projectPath ? (
              <span
                title={activeSession.projectPath}
                className="inline-flex max-w-[min(32rem,42vw)] items-center gap-1.5 rounded-md border border-accent-600/50 bg-accent-500/10 px-2 py-1 text-[11px] text-accent-300"
              >
                <FolderOpen size={11} aria-hidden="true" className="shrink-0" />
                <span className="shrink-0 font-medium">Project context</span>
                <code className="truncate font-mono">
                  {activeSession.projectPath}
                </code>
              </span>
            ) : (
              <span className="rounded-md border border-ink-600 bg-ink-850 px-2 py-1 text-[11px] text-stone-400">
                Standalone · no project context
              </span>
            )}
            {model && (
              <span className="rounded-md border border-ink-600 bg-ink-850 px-2 py-1 font-mono text-[11px] text-stone-400">
                {model}
              </span>
            )}
            <button
              type="button"
              onClick={openManualContext}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-850 px-2.5 py-1.5 text-[12px] font-medium text-stone-300 hover:border-ink-500 hover:bg-ink-800 disabled:opacity-40"
            >
              <ClipboardPaste size={12} aria-hidden="true" />
              Attach context
            </button>
            <button
              type="button"
              onClick={() => void clearConversation()}
              disabled={busy || messages.length === 0}
              className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 bg-ink-850 px-2.5 py-1.5 text-[12px] text-stone-300 hover:border-red-500/40 hover:text-red-300 disabled:opacity-40"
            >
              <Trash2 size={12} aria-hidden="true" />
              Clear
            </button>
          </div>
        </header>

        {aiReady !== true && (
          <div
            role={aiReady === false ? "alert" : "status"}
            className="flex shrink-0 items-center justify-between gap-3 border-b border-ink-800 bg-amber-950/20 px-4 py-2"
          >
            <p className="text-[12px] text-amber-200">
              {aiReady === false
                ? "The configured AI endpoint cannot be reached. Messages remain available, but sending is paused."
                : "Configure an AI provider before sending a message. You can still review and attach context."}
            </p>
            <button
              type="button"
              onClick={() => setPage("settings")}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-amber-700/50 bg-amber-900/20 px-2.5 py-1 text-[12px] font-medium text-amber-200 hover:bg-amber-900/35"
            >
              <Settings2 size={11} aria-hidden="true" />
              Open Settings
            </button>
          </div>
        )}

        <div
          aria-busy={busy}
          className="min-h-0 flex-1 overflow-y-auto"
        >
          <div className="mx-auto flex min-h-full w-full max-w-4xl flex-col px-4 py-4 sm:px-6">
            {messages.length === 0 && !busy && (
              <div className="flex flex-1 flex-col items-center justify-center gap-4 py-8">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-accent-600/50 bg-accent-500/10">
                  <Bot size={19} aria-hidden="true" className="text-accent-300" />
                </div>
                <div className="text-center">
                  <h2 className="text-[14px] font-semibold text-stone-100">
                    Start a standalone security conversation
                  </h2>
                  <p className="mx-auto mt-1 max-w-md text-[13px] leading-relaxed text-stone-300">
                    Ask a security question or explicitly attach source material.
                    A project is available only when this conversation shows a
                    project context chip above.
                  </p>
                </div>
                <div className="grid w-full max-w-xl gap-1.5 sm:grid-cols-2">
                  {SUGGESTIONS.map((suggestion) => (
                    <button
                      key={suggestion}
                      type="button"
                      onClick={() => void send(suggestion)}
                      disabled={busy || aiReady !== true || !activeSessionId}
                      className="rounded-md border border-ink-700 bg-ink-900/70 px-3 py-2.5 text-left text-[13px] leading-relaxed text-stone-300 transition-colors hover:border-accent-600/50 hover:text-stone-100 disabled:opacity-40"
                    >
                      <Sparkles
                        size={11}
                        aria-hidden="true"
                        className="mr-1.5 inline text-accent-400"
                      />
                      {suggestion}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-4">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={`flex gap-2.5 ${
                    message.role === "user" ? "justify-end" : ""
                  }`}
                >
                  {message.role !== "user" && (
                    <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-accent-600/40 bg-accent-500/10">
                      <Bot
                        size={13}
                        aria-hidden="true"
                        className="text-accent-300"
                      />
                    </div>
                  )}
                  <div className="min-w-0 max-w-[88%] flex-1">
                    {message.tools && message.tools.length > 0 && (
                      <div className="mb-1.5 space-y-1">
                        {message.tools.map((tool) => (
                          <ToolCallCard key={tool.toolCallId} record={tool} />
                        ))}
                      </div>
                    )}
                    <div
                      className={`rounded-lg px-4 py-3 text-[13px] leading-relaxed ${
                        message.role === "user"
                          ? "selectable ml-auto rounded-tr-sm border border-accent-600/30 bg-accent-500/10 text-stone-200"
                          : "selectable md-body rounded-tl-sm border border-ink-700 bg-ink-900/70 text-stone-300"
                      }`}
                    >
                      {message.role === "user" ? (
                        <div className="whitespace-pre-wrap break-words">
                          {message.content}
                        </div>
                      ) : (
                        <Markdown>{message.content}</Markdown>
                      )}
                    </div>
                  </div>
                  {message.role === "user" && (
                    <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-ink-700 bg-ink-800">
                      <User
                        size={13}
                        aria-hidden="true"
                        className="text-stone-400"
                      />
                    </div>
                  )}
                </div>
              ))}

              {busy && (
                <div className="flex gap-2.5">
                  <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-accent-600/40 bg-accent-500/10">
                    <Bot
                      size={13}
                      aria-hidden="true"
                      className="text-accent-300"
                    />
                  </div>
                  <div className="min-w-0 max-w-[88%] flex-1">
                    {toolRecords.length > 0 && (
                      <div className="mb-1.5 space-y-1">
                        {toolRecords.map((tool) => (
                          <ToolCallCard key={tool.toolCallId} record={tool} />
                        ))}
                      </div>
                    )}
                    {showThinking && (
                      <ThinkingCard
                        text={streaming.reasoning}
                        streaming={streaming.thinking}
                      />
                    )}
                    {streaming.text && (
                      <div className="selectable md-body rounded-lg rounded-tl-sm border border-ink-700 bg-ink-900/70 px-4 py-3 text-[13px] text-stone-300">
                        <Markdown>{streaming.text}</Markdown>
                        <span
                          aria-hidden="true"
                          className="ml-0.5 inline-block h-3.5 w-[6px] animate-pulse rounded-[2px] bg-accent-400 align-middle"
                        />
                      </div>
                    )}
                    {!streaming.text && toolRecords.length === 0 && (
                      <div className="flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-900/70 px-4 py-3 text-[12px] text-stone-300">
                        <Loader2
                          size={13}
                          aria-hidden="true"
                          className="animate-spin"
                        />
                        {showThinking ? "Reasoning…" : "Waiting for response…"}
                      </div>
                    )}
                  </div>
                </div>
              )}
              <div ref={bottomRef} />
            </div>
          </div>
        </div>

        <div className="shrink-0 border-t border-ink-800 bg-ink-900/90 px-4 py-3 backdrop-blur sm:px-6">
          <form
            className="mx-auto w-full max-w-4xl"
            onSubmit={(event) => {
              event.preventDefault();
              void send();
            }}
          >
            <label htmlFor="assistant-composer" className="sr-only">
              Message the AI Assistant
            </label>
            <div className="flex items-end gap-2">
              <textarea
                id="assistant-composer"
                value={input}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void send();
                  }
                }}
                rows={2}
                aria-describedby="assistant-composer-help"
                disabled={aiReady !== true}
                placeholder={
                  aiReady === true
                    ? "Ask a security question or describe what you want to analyze…"
                    : "Configure an AI provider to send messages"
                }
                className="selectable min-h-11 flex-1 resize-none rounded-md border border-ink-600 bg-ink-950 px-3.5 py-2.5 text-[13px] leading-relaxed text-stone-200 outline-none placeholder:text-stone-400 focus:border-accent-500/70 disabled:cursor-not-allowed disabled:opacity-60"
              />
              {busy ? (
                <button
                  type="button"
                  onClick={() => void cancel()}
                  className="inline-flex h-11 shrink-0 items-center justify-center gap-1.5 rounded-md border border-red-500/40 bg-red-500/10 px-3 text-[12px] font-medium text-red-300 hover:bg-red-500/20"
                >
                  <Ban size={14} aria-hidden="true" />
                  Cancel
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!input.trim() || aiReady !== true || !activeSessionId}
                  className="inline-flex h-11 shrink-0 items-center justify-center gap-1.5 rounded-md bg-accent-500 px-3.5 text-[12px] font-semibold text-ink-950 hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Send size={14} aria-hidden="true" />
                  Send
                </button>
              )}
            </div>
            <div
              id="assistant-composer-help"
              className="mt-1.5 flex flex-wrap items-center justify-between gap-2 text-[11px] text-stone-400"
            >
              <span>
                Enter to send · Shift+Enter for a new line · tools require approval
              </span>
              {convUsage && (
                <span className="font-mono tabular-nums">
                  {model ? `${model} · ` : ""}
                  {(convUsage.totalTokens / 1000).toFixed(1)}k tokens · $
                  {convUsage.costUsd.toFixed(4)}
                </span>
              )}
            </div>
          </form>
          <p className="sr-only" aria-live="polite">
            {busy
              ? showThinking
                ? "The Assistant is reasoning."
                : "The Assistant is responding."
              : "The Assistant is idle."}
          </p>
        </div>
        </section>
      </div>

      {permission && (
        <ApprovalModal
          tool={permission.tool}
          argumentsPreview={permission.arguments}
          onDecide={(approve) => {
            api
              .respondPermission(permission.requestId, approve)
              .catch(() => undefined);
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
        <div
          className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 p-4 sm:p-6"
          onMouseDown={(event) => {
            if (
              !contextAttachPendingRef.current &&
              event.target === event.currentTarget
            ) {
              discardContext();
            }
          }}
        >
          <section
            ref={contextDialogRef}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            aria-busy={contextAttaching}
            aria-labelledby="assistant-context-title"
            aria-describedby="assistant-context-description"
            className="w-full max-w-2xl rounded-lg border border-ink-600 bg-ink-850 p-5 shadow-2xl"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h2
                  id="assistant-context-title"
                  className="flex items-center gap-2 text-[14px] font-semibold text-stone-100"
                >
                  <ClipboardPaste
                    size={15}
                    aria-hidden="true"
                    className="text-accent-400"
                  />
                  Review context before attaching
                </h2>
                <p className="mt-1 truncate text-[13px] font-medium text-accent-300">
                  {contextLabel}
                </p>
              </div>
              <button
                ref={contextCloseRef}
                type="button"
                aria-label="Close"
                onClick={discardContext}
                disabled={contextAttaching}
                className="rounded p-1 text-stone-400 hover:bg-ink-800 hover:text-stone-200 disabled:opacity-40"
              >
                <X size={15} aria-hidden="true" />
              </button>
            </div>
            <p
              id="assistant-context-description"
              className="mt-2 text-[13px] leading-relaxed text-stone-300"
            >
              Review and edit this source material before it is saved to the
              current conversation. Findings can contain source code or secrets.
              Attaching does not send anything to the model; it becomes context
              only on your next explicit Send.
            </p>
            {contextProjectPath && (
              <p className="mt-2 break-all rounded-md border border-ink-700 bg-ink-900 px-2.5 py-2 font-mono text-[12px] text-stone-300">
                Source scope: {contextProjectPath}
              </p>
            )}
            <label
              htmlFor="assistant-context-content"
              className="mt-4 block text-[12px] font-semibold uppercase tracking-[0.12em] text-stone-300"
            >
              Context content
            </label>
            <textarea
              id="assistant-context-content"
              value={contextText}
              onChange={(event) => setContextText(event.target.value)}
              readOnly={contextAttaching}
              rows={14}
              className="selectable mt-2 max-h-[55vh] w-full resize-y rounded-md border border-ink-600 bg-ink-950 px-3 py-2.5 font-mono text-[13px] leading-relaxed text-stone-200 focus:border-accent-500/70"
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={discardContext}
                disabled={contextAttaching}
                className="rounded-md border border-ink-600 bg-ink-900 px-3 py-2 text-[12px] font-medium text-stone-300 hover:bg-ink-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void attachContext()}
                disabled={
                  contextAttaching || !contextText.trim() || !activeSessionId
                }
                className="inline-flex items-center gap-1.5 rounded-md bg-accent-500 px-3.5 py-2 text-[12px] font-semibold text-ink-950 hover:bg-accent-400 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {contextAttaching ? (
                  <Loader2 size={13} aria-hidden="true" className="animate-spin" />
                ) : (
                  <ClipboardPaste size={13} aria-hidden="true" />
                )}
                {contextAttaching ? "Attaching…" : "Attach context"}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
