import { useDeferredValue, useEffect, useLayoutEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import {
  Ban,
  ClipboardPaste,
  CornerDownLeft,
  FolderOpen,
  History,
  Loader2,
  PanelRightClose,
  PanelRightOpen,
  Send,
  Search,
  Settings2,
  Sparkles,
  Trash2,
  User,
  X,
} from "lucide-react";
import { BrandMark } from "../components/brand/BrandMark";
import { AssistantActivityPanel } from "../components/chat/AssistantActivityPanel";
import { ApprovalModal } from "../components/chat/ApprovalModal";
import { AskUserModal } from "../components/chat/AskUserModal";
import { ChatSearchToolbar } from "../components/chat/ChatSearchToolbar";
import { ContextBudgetMeter } from "../components/chat/ContextBudgetMeter";
import { HighlightedText, SearchableMarkdown } from "../components/chat/SearchHighlight";
import { SessionSidebar } from "../components/chat/SessionSidebar";
import { ThinkingCard } from "../components/chat/ThinkingCard";
import { ToolCallCard } from "../components/chat/ToolCallCard";
import { streamChat, type StreamHandle } from "../lib/aiEvents";
import { nextSearchIndex } from "../lib/chatSearch";
import {
  buildContextBudget,
  estimateMessageTokens,
  type ContextBudgetMetadata,
} from "../lib/contextBudget";
import { planRewind } from "../lib/rewind";
import { api } from "../lib/api";
import {
  loadLatestSessionMessages,
  resolveRuntimeProject,
} from "../lib/assistantSessions";
import {
  LatestRequestQueue,
  type RequestToken,
} from "../lib/latestRequest";
import { useAppStore, useToastStore } from "../lib/stores";
import type {
  AskQuestion,
  ChatMessage,
  SessionInfo,
  StoredMessage,
  ToolRecord,
  Usage,
  TodoItem,
  UsageSummary,
} from "../lib/types";
import { Button } from "../components/ui";

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
  /** Submitted mid-run. Live-session styling only; a reload shows a plain turn. */
  steer?: boolean;
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

let assistantBootstrapPromise: Promise<SessionInfo[]> | null = null;

function ensureAssistantSessions(): Promise<SessionInfo[]> {
  if (!assistantBootstrapPromise) {
    assistantBootstrapPromise = (async () => {
      const sessions = await api.sessionList();
      if (sessions.length > 0) return sessions;
      return [await api.sessionCreate(null, null)];
    })().finally(() => {
      assistantBootstrapPromise = null;
    });
  }
  return assistantBootstrapPromise;
}

function toUiMessages(messages: StoredMessage[]): UiMessage[] {
  return messages.map((message) => ({
    id: message.id,
    role: message.role,
    content: message.content,
    tools: message.tools,
  }));
}

export function AssistantPage() {
  const aiReadiness = useAppStore((state) => state.aiReadiness);
  const settings = useAppStore((state) => state.settings);
  const aiReady = aiReadiness.status === "ready";
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
  /** Steers accepted by the run but not yet folded into the conversation. */
  const [pendingSteers, setPendingSteers] = useState<{ id: string; text: string }[]>([]);
  /** A message the run declined (it was already finishing); sent as a new turn. */
  const [followUp, setFollowUp] = useState<string | null>(null);
  /** The agent's working plan, maintained by the `todo` tool. */
  const [todos, setTodos] = useState<TodoItem[]>([]);
  const [sessionActivating, setSessionActivating] = useState(false);
  const [unavailableProject, setUnavailableProject] = useState<{
    sessionId: string;
    path: string;
  } | null>(null);
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
  const [activityOpen, setActivityOpen] = useState(true);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const deferredSearchQuery = useDeferredValue(searchQuery);
  const [searchIndex, setSearchIndex] = useState(0);
  const [searchTotal, setSearchTotal] = useState(0);
  const [contextBudgetMetadata, setContextBudgetMetadata] =
    useState<ContextBudgetMetadata | null>(null);

  const conversationId = useRef<string>(crypto.randomUUID());
  const streamHandleRef = useRef<StreamHandle | null>(null);
  const sessionRequestsRef = useRef<LatestRequestQueue | null>(null);
  if (!sessionRequestsRef.current) {
    sessionRequestsRef.current = new LatestRequestQueue();
  }
  const sessionRequests = sessionRequestsRef.current;
  const mountedRef = useRef(false);
  const sessionActivationPendingRef = useRef(false);
  const settledRef = useRef(false);
  const turnToolsRef = useRef<Map<string, ToolRecord>>(new Map());
  const [toolRecords, setToolRecords] = useState<ToolRecord[]>([]);
  const streamingRef = useRef(streaming);
  streamingRef.current = streaming;
  const bottomRef = useRef<HTMLDivElement>(null);
  const conversationScrollRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
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
  const activeUnavailableProject =
    unavailableProject?.sessionId === activeSessionId
      ? unavailableProject
      : null;

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

  const requestIsCurrent = (token: RequestToken) =>
    mountedRef.current && sessionRequests.isCurrent(token);

  const beginSessionRequest = (): RequestToken => {
    const token = sessionRequests.begin();
    sessionActivationPendingRef.current = true;
    setSessionActivating(true);
    return token;
  };

  const finishSessionRequest = (token: RequestToken) => {
    if (!requestIsCurrent(token)) return;
    sessionActivationPendingRef.current = false;
    setSessionActivating(false);
  };

  const refreshUsage = (
    sessionId = conversationId.current,
    token = sessionRequests.capture(),
  ) => {
    api
      .getConversationUsage(sessionId)
      .then((usage) => {
        if (
          requestIsCurrent(token) &&
          conversationId.current === sessionId
        ) {
          setConvUsage(usage);
        }
      })
      .catch(() => undefined);
  };

  const updateSessionInfo = (info: SessionInfo) => {
    setSessions((list) =>
      [...list.filter((session) => session.id !== info.id), info].sort((a, b) =>
        b.updatedAt.localeCompare(a.updatedAt),
      ),
    );
  };

  const applyRuntimeProject = async (
    projectPath: string | null,
    token: RequestToken,
  ): Promise<boolean> => {
    const result = await resolveRuntimeProject(projectPath, api.setActiveProject);

    setActiveProjectStore(result.runtimePath);
    if (!requestIsCurrent(token)) return false;
    setUnavailableProject(
      result.unavailablePath
        ? { sessionId: conversationId.current, path: result.unavailablePath }
        : null,
    );
    if (result.warning?.startsWith("Runtime project context")) {
      push("error", result.warning);
    }
    return true;
  };

  const activateSession = async (
    info: SessionInfo,
    token: RequestToken,
    knownMessages?: StoredMessage[],
  ) => {
    let storedMessages = knownMessages;
    if (!storedMessages) {
      const loaded = await loadLatestSessionMessages(
        sessionRequests,
        token,
        () => api.sessionGetMessages(info.id),
      );
      if (!loaded.current) return;
      storedMessages = loaded.value;
    }
    if (!requestIsCurrent(token)) return;
    setMessages(toUiMessages(storedMessages));
    conversationId.current = info.id;
    setActiveSessionId(info.id);
    setModel(null);
    setContextBudgetMetadata(null);
    setConvUsage(null);
    setUnavailableProject(null);
    setPendingSteers([]);
    // The plan lives in native state keyed by conversation, so switching back
    // to a session restores whatever the agent had planned there.
    api
      .todoList(info.id)
      .then((items) => {
        if (requestIsCurrent(token)) setTodos(items);
      })
      .catch(() => undefined);

    if (!(await applyRuntimeProject(info.projectPath, token))) return;
    refreshUsage(info.id, token);
  };

  const loadSession = async (id: string) => {
    if (sessionActivationPendingRef.current) return;
    const info = sessions.find((session) => session.id === id);
    if (!info) return;
    const token = beginSessionRequest();
    try {
      await activateSession(info, token);
    } catch (error) {
      if (requestIsCurrent(token)) push("error", String(error));
    } finally {
      finishSessionRequest(token);
    }
  };

  const createNewChat = async () => {
    if (sessionActivationPendingRef.current) return;
    const token = beginSessionRequest();
    try {
      const session = await api.sessionCreate(null, null);
      if (!requestIsCurrent(token)) return;
      setSessions((list) => [session, ...list]);
      await activateSession(session, token, []);
    } catch (error) {
      if (requestIsCurrent(token)) push("error", String(error));
    } finally {
      finishSessionRequest(token);
    }
  };

  useEffect(() => {
    mountedRef.current = true;
    const token = beginSessionRequest();
    void (async () => {
      try {
        const list = await ensureAssistantSessions();
        if (!requestIsCurrent(token)) return;
        setSessions(list);
        await activateSession(list[0], token);
      } catch (error) {
        if (requestIsCurrent(token)) {
          push("error", `Chat sessions could not be loaded: ${String(error)}`);
        }
      } finally {
        finishSessionRequest(token);
      }
    })();
    return () => {
      mountedRef.current = false;
      sessionActivationPendingRef.current = false;
      sessionRequests.invalidate();
    };
    // The Assistant owns this one-time session bootstrap.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    return () => streamHandleRef.current?.dispose();
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
    if (searchOpen && deferredSearchQuery.trim()) return;
    const behavior = window.matchMedia("(prefers-reduced-motion: reduce)")
      .matches
      ? "auto"
      : "smooth";
    bottomRef.current?.scrollIntoView({ behavior });
  }, [messages, busy, streaming.text, toolRecords, searchOpen, deferredSearchQuery]);

  useEffect(() => {
    const onFindShortcut = (event: KeyboardEvent) => {
      if (!(event.metaKey || event.ctrlKey) || event.key.toLowerCase() !== "f") {
        return;
      }
      if (contextOpen) return;
      event.preventDefault();
      setSearchOpen(true);
      requestAnimationFrame(() => {
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
      });
    };
    document.addEventListener("keydown", onFindShortcut);
    return () => document.removeEventListener("keydown", onFindShortcut);
  }, [contextOpen]);

  useLayoutEffect(() => {
    const root = conversationScrollRef.current;
    if (!searchOpen || !deferredSearchQuery.trim() || !root) {
      setSearchTotal(0);
      return;
    }
    const matches = Array.from(
      root.querySelectorAll<HTMLElement>("[data-chat-search-match]"),
    );
    const nextIndex = matches.length === 0 ? 0 : Math.min(searchIndex, matches.length - 1);
    setSearchTotal(matches.length);
    if (nextIndex !== searchIndex) setSearchIndex(nextIndex);
    matches.forEach((match, index) => {
      match.classList.toggle("chat-search-match--active", index === nextIndex);
    });
    matches[nextIndex]?.scrollIntoView({ block: "center" });
  }, [deferredSearchQuery, messages, searchIndex, searchOpen, streaming.text]);

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
    setPermission(null);
    setAskUser(null);
    setStreaming({ text: "", reasoning: "", thinking: false });
    setContextBudgetMetadata(null);
    setToolRecords([]);
    turnToolsRef.current.clear();
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
    if (
      !content ||
      busy ||
      sessionActivating ||
      !activeSessionId ||
      !aiReady
    ) {
      return;
    }
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
    setPendingSteers([]);
    settledRef.current = false;
    turnToolsRef.current.clear();
    setToolRecords([]);
    setStreaming({ text: "", reasoning: "", thinking: false });
    setContextBudgetMetadata(null);

    api
      .sessionAppend(activeSessionId, stored)
      .then(updateSessionInfo)
      .catch(() => undefined);

    const handle = streamChat(
      { messages: next, conversationId: conversationId.current },
      {
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
        onContextBudget: setContextBudgetMetadata,
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
        onSteer: (text) => {
          // The run has taken ownership of this message, so it stops being a
          // pending chip and becomes a real user turn in the transcript. It is
          // persisted too, otherwise a reload would show the model answering
          // something the history never recorded being asked.
          setPendingSteers((current) => {
            const index = current.findIndex((steer) => steer.text === text);
            return index === -1
              ? current
              : [...current.slice(0, index), ...current.slice(index + 1)];
          });
          const stored: StoredMessage = {
            id: crypto.randomUUID(),
            role: "user",
            content: text,
            at: new Date().toISOString(),
          };
          setMessages((current) => [
            ...current,
            { id: stored.id, role: "user", content: text, steer: true },
          ]);
          const sessionId = activeSessionIdRef.current;
          if (sessionId) {
            api
              .sessionAppend(sessionId, stored)
              .then(updateSessionInfo)
              .catch(() => undefined);
          }
        },
        onTodos: (items) => setTodos(items),
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
          setPermission(null);
          setAskUser(null);
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
          setContextBudgetMetadata(null);
        },
      },
    );
    streamHandleRef.current = handle;
    await handle.finished;
    if (streamHandleRef.current === handle) streamHandleRef.current = null;
  };

  /**
   * Drop this user turn and everything after it, handing the text back to the
   * composer so it can be re-asked differently.
   *
   * The transcript is truncated first: if that write fails the in-memory view is
   * left alone, so the UI never claims to have discarded turns that are still on
   * disk and would reappear on reload.
   */
  const rewindTo = async (messageId: string) => {
    if (busy || !activeSessionId) return;
    const plan = planRewind(messages, messageId);
    if (!plan) return;

    try {
      await api.sessionTruncate(activeSessionId, plan.keepCount);
    } catch (error) {
      push("error", `Could not rewind: ${String(error)}`);
      return;
    }

    setMessages((current) => current.slice(0, plan.keepCount));
    setInput(plan.restoredInput);
    setToolRecords([]);
    turnToolsRef.current.clear();
    setStreaming({ text: "", reasoning: "", thinking: false });
    setPendingSteers([]);
    const info = sessions.find((session) => session.id === activeSessionId);
    if (info) updateSessionInfo({ ...info, messageCount: plan.keepCount });
    document.getElementById("assistant-composer")?.focus();
  };

  /**
   * Send a message into a turn that is already running.
   *
   * The run owns the decision: its queue closes atomically while empty just
   * before it finishes, so a `false` here means the message was not taken and
   * must be sent as an ordinary new turn instead — it is never both.
   */
  const steer = async (content: string) => {
    const handle = streamHandleRef.current;
    if (!handle) {
      setFollowUp(content);
      return;
    }
    setInput("");
    try {
      if (await api.steerChat(handle.runId, content)) {
        setPendingSteers((current) => [
          ...current,
          { id: crypto.randomUUID(), text: content },
        ]);
      } else {
        setFollowUp(content);
      }
    } catch (error) {
      setInput(content);
      push("error", `That message could not be sent: ${String(error)}`);
    }
  };

  const submit = async () => {
    const content = input.trim();
    if (!content) return;
    if (busy) {
      await steer(content);
      return;
    }
    await send(content);
  };

  // A declined steer becomes the next turn. This runs as an effect rather than
  // inline so `send` reads the settled message list, including the answer the
  // run had already produced.
  useEffect(() => {
    if (!followUp || busy || sessionActivating || !activeSessionId || !aiReady) {
      return;
    }
    setFollowUp(null);
    void send(followUp);
    // `send` is recreated every render and intentionally not a dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [followUp, busy, sessionActivating, activeSessionId, aiReady]);

  const cancel = async () => {
    const handle = streamHandleRef.current;
    if (!handle) return;
    try {
      await handle.cancel();
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
    setTodos([]);
    setConvUsage(null);
    setModel(null);
    setContextBudgetMetadata(null);
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
  const activityTools = useMemo(() => {
    const toolsById = new Map<string, ToolRecord>();
    for (const message of messages) {
      for (const tool of message.tools ?? []) toolsById.set(tool.toolCallId, tool);
    }
    for (const tool of toolRecords) toolsById.set(tool.toolCallId, tool);
    return Array.from(toolsById.values());
  }, [messages, toolRecords]);
  const contextBudget = useMemo(() => {
    const localEstimate = estimateMessageTokens([
      ...messages,
      ...(streaming.text ? [{ content: streaming.text }] : []),
    ]);
    return buildContextBudget(
      Math.max(localEstimate, contextBudgetMetadata?.estimatedTokens ?? 0),
      contextBudgetMetadata?.contextWindow ?? settings?.ai.contextWindow ?? 128000,
      contextBudgetMetadata?.reservedOutputTokens ?? settings?.ai.maxTokens ?? 2048,
    );
  }, [contextBudgetMetadata, messages, settings, streaming.text]);
  const closeSearch = () => {
    setSearchOpen(false);
    setSearchQuery("");
    setSearchIndex(0);
    setSearchTotal(0);
    assistantFallbackRef.current?.focus();
  };
  const openSearch = () => {
    setSearchOpen(true);
    requestAnimationFrame(() => searchInputRef.current?.focus());
  };
  const availabilityLabel = {
    loading: "AI settings loading",
    checking: "AI endpoint checking",
    unconfigured: "AI not configured",
    offline: "AI endpoint unavailable",
    ready: "AI ready",
    unavailable: "AI readiness unavailable",
  }[aiReadiness.status];
  const unavailableMessage = {
    loading:
      "Saved AI settings are loading. Messages remain available; sending will unlock after readiness is known.",
    checking:
      "The newly persisted AI endpoint is being checked. Messages remain available; sending is paused until that check finishes.",
    unconfigured:
      "Configure an AI provider before sending a message. You can still review and attach context.",
    offline:
      "The configured AI endpoint cannot be reached. Messages remain available, but sending is paused.",
    ready: "",
    unavailable:
      "AI readiness could not be loaded from local settings. Messages remain available; review Settings before sending.",
  }[aiReadiness.status];
  const composerPlaceholder = {
    loading: "Loading saved AI settings…",
    checking: "Checking the newly persisted AI endpoint…",
    unconfigured: "Configure an AI provider to send messages",
    offline: "The saved AI endpoint is offline",
    ready: "Ask a security question or describe what you want to analyze…",
    unavailable: "Review Settings to restore AI readiness",
  }[aiReadiness.status];

  return (
    <div
      ref={assistantRootRef}
      className="relative h-full min-h-0 overflow-hidden bg-surface-primary"
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
          disabled={sessionActivating}
          onSelect={(id) => {
            if (id !== activeSessionId && !busy && !sessionActivating) {
              void loadSession(id);
            }
          }}
          onCreate={() => {
            if (!busy && !sessionActivating) void createNewChat();
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

        <div className="flex min-w-0 flex-1">
          <section
            ref={assistantFallbackRef}
            tabIndex={-1}
            aria-label="Assistant conversation"
            className="flex min-w-0 flex-1 flex-col"
          >
        <header className="flex h-[52px] shrink-0 items-center gap-3 border-b border-border px-4">
          <div className="min-w-0 flex-1">
            <h2 className="truncate font-display text-[15px] font-normal italic text-text-primary">
              {activeSession?.title || "New security conversation"}
            </h2>
            <p className="mt-0.5 flex items-center gap-1.5 text-[10px] text-text-muted">
              <span
                aria-hidden="true"
                className={`h-1.5 w-1.5 rounded-full ${ aiReady ? "bg-success" : aiReadiness.status === "offline" ? "bg-error" : aiReadiness.status === "checking" ? "bg-accent" : "bg-text-muted" }`}
              />
              {availabilityLabel}
            </p>
          </div>

          <div className="flex min-w-0 items-center justify-end gap-1">
            {activeUnavailableProject ? (
              <span
                title={activeUnavailableProject.path}
                className="inline-flex max-w-[min(22rem,30vw)] items-center gap-1.5 rounded-sm border border-warning-border bg-warning-subtle px-2 py-1 text-[10px] text-warning"
              >
                <FolderOpen size={11} aria-hidden="true" className="shrink-0" />
                <span className="shrink-0 font-medium">Project unavailable</span>
                <code className="truncate font-mono">
                  {activeUnavailableProject.path}
                </code>
              </span>
            ) : activeSession?.projectPath ? (
              <span
                title={activeSession.projectPath}
                className="inline-flex max-w-[min(22rem,30vw)] items-center gap-1.5 rounded-sm border border-accent-glow bg-accent-subtle px-2 py-1 text-[10px] text-accent"
              >
                <FolderOpen size={11} aria-hidden="true" className="shrink-0" />
                <span className="shrink-0 font-medium">Project context</span>
                <code className="truncate font-mono">
                  {activeSession.projectPath}
                </code>
              </span>
            ) : null}
            <button
              type="button"
              onClick={openSearch}
              aria-expanded={searchOpen}
              title="Search conversation (⌘/Ctrl+F)"
              aria-label="Search conversation"
              className="flex h-8 w-8 items-center justify-center rounded-sm text-text-muted transition-colors hover:bg-surface-hover hover:text-text-primary"
            >
              <Search size={14} aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={() => setActivityOpen((open) => !open)}
              aria-expanded={activityOpen}
              aria-controls="assistant-activity-panel"
              title={activityOpen ? "Hide activity" : "Show activity"}
              className="flex h-8 w-8 items-center justify-center rounded-sm text-text-muted transition-colors hover:bg-surface-hover hover:text-text-primary max-[1180px]:hidden"
            >
              {activityOpen ? (
                <PanelRightClose size={14} aria-hidden="true" />
              ) : (
                <PanelRightOpen size={14} aria-hidden="true" />
              )}
              <span className="sr-only">{activityOpen ? "Hide" : "Show"} assistant activity</span>
            </button>
            <button
              type="button"
              onClick={() => void clearConversation()}
              disabled={busy || sessionActivating || messages.length === 0}
              title="Clear conversation"
              aria-label="Clear conversation"
              className="flex h-8 w-8 items-center justify-center rounded-sm text-text-muted transition-colors hover:bg-error-subtle hover:text-error disabled:opacity-30"
            >
              <Trash2 size={13} aria-hidden="true" />
            </button>
          </div>
        </header>

        {searchOpen && (
          <ChatSearchToolbar
            ref={searchInputRef}
            query={searchQuery}
            current={searchIndex}
            total={searchTotal}
            onQueryChange={(query) => {
              setSearchQuery(query);
              setSearchIndex(0);
            }}
            onNext={() =>
              setSearchIndex((current) => nextSearchIndex(current, searchTotal, 1))
            }
            onPrevious={() =>
              setSearchIndex((current) => nextSearchIndex(current, searchTotal, -1))
            }
            onClose={closeSearch}
          />
        )}

        {activeUnavailableProject && (
          <div
            role="status"
            className="shrink-0 border-b border-warning-border bg-warning-subtle px-4 py-2 text-[12px] text-warning"
          >
            Project unavailable ·{" "}
            <code className="font-mono">{activeUnavailableProject.path}</code>.
            The persisted transcript remains available and runtime project context is cleared.
          </div>
        )}

        {!aiReady && (
          <div
            role={
              aiReadiness.status === "offline" ||
              aiReadiness.status === "unavailable"
                ? "alert"
                : "status"
            }
            className="flex shrink-0 items-center justify-between gap-3 border-b border-warning-border bg-warning-subtle px-4 py-1.5"
          >
            <p className="truncate text-[11px] text-warning">
              {unavailableMessage}
            </p>
            <button
              type="button"
              onClick={() => setPage("settings")}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-sm px-2 py-1 text-[11px] font-medium text-warning hover:bg-surface-hover"
            >
              <Settings2 size={11} aria-hidden="true" />
              Open Settings
            </button>
          </div>
        )}

        <div
          ref={conversationScrollRef}
          aria-busy={busy}
          className="min-h-0 flex-1 overflow-y-auto"
        >
          <div className="mx-auto flex min-h-full w-full max-w-[780px] flex-col px-4 py-4 sm:px-6">
            {messages.length === 0 && !busy && (
              <div className="flex flex-1 flex-col items-center justify-center gap-5 py-10">
                <div className="flex h-11 w-11 items-center justify-center rounded-full bg-surface-tertiary text-accent">
                  <BrandMark className="h-[17px] w-[25px]" />
                </div>
                <div className="text-center">
                  <h2 className="font-display text-[18px] font-normal text-text-primary">
                    What would you like to audit?
                  </h2>
                  <p className="mx-auto mt-1.5 max-w-md text-[13px] leading-relaxed text-text-muted">
                    Ask a security question, investigate a finding, or attach source
                    context for a focused review.
                  </p>
                </div>
                <div className="grid w-full max-w-[620px] gap-1.5 sm:grid-cols-2">
                  {SUGGESTIONS.map((suggestion) => (
                    <button
                      key={suggestion}
                      type="button"
                      onClick={() => void send(suggestion)}
                      disabled={
                        busy ||
                        sessionActivating ||
                        !aiReady ||
                        !activeSessionId
                      }
                      className="group/suggestion flex items-start gap-2 rounded-md border border-border bg-surface-secondary px-3 py-2.5 text-left text-[12px] leading-relaxed text-text-secondary transition-colors hover:border-border-strong hover:bg-surface-tertiary hover:text-text-primary disabled:opacity-40"
                    >
                      <Sparkles
                        size={12}
                        aria-hidden="true"
                        className="mt-0.5 shrink-0 text-accent opacity-70"
                      />
                      <span>{suggestion}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-1">
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={`group flex gap-3 rounded-sm px-2 py-3 transition-colors hover:bg-surface-hover ${ message.role === "user" ? "justify-end" : "" }`}
                >
                  {message.role === "user" && !busy && (
                    <button
                      type="button"
                      onClick={() => void rewindTo(message.id)}
                      title="Discard this and everything after it, and put the text back in the composer"
                      aria-label="Rewind the conversation to this message"
                      className="mt-5 flex h-7 w-7 shrink-0 items-center justify-center self-start rounded-sm text-text-muted opacity-0 transition-opacity hover:bg-surface-tertiary hover:text-text-primary focus-visible:opacity-100 group-hover:opacity-100"
                    >
                      <History size={13} aria-hidden="true" />
                    </button>
                  )}
                  {message.role !== "user" && (
                    <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-surface-tertiary text-accent">
                      <BrandMark className="h-[11px] w-[17px]" />
                    </div>
                  )}
                  <div className={`min-w-0 ${message.role === "user" ? "max-w-[76%]" : "max-w-[720px] flex-1"}`}>
                    <div className={`mb-1 text-[11px] font-medium text-text-muted ${message.role === "user" ? "text-right" : ""}`}>
                      {message.role === "user" ? "You" : "Assistant"}
                    </div>
                    {message.tools && message.tools.length > 0 && (
                      <div className="mb-2 flex flex-wrap gap-1.5">
                        {message.tools.map((tool) => (
                          <ToolCallCard key={tool.toolCallId} record={tool} />
                        ))}
                      </div>
                    )}
                    <div
                      className={message.role === "user"
                        ? "selectable ml-auto inline-block rounded-md rounded-tr-sm border border-border bg-surface-tertiary px-3.5 py-2.5 text-[14px] leading-relaxed text-text-primary"
                        : "selectable md-body text-[14px] leading-[1.72] text-text-primary"}
                    >
                      {message.role === "user" ? (
                        <div className="whitespace-pre-wrap break-words">
                          {message.steer && (
                            <span className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-accent opacity-80">
                              <CornerDownLeft size={10} aria-hidden="true" />
                              steered mid-run
                            </span>
                          )}
                          <HighlightedText text={message.content} query={deferredSearchQuery} />
                        </div>
                      ) : (
                        <SearchableMarkdown content={message.content} query={deferredSearchQuery} />
                      )}
                    </div>
                  </div>
                  {message.role === "user" && (
                    <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent-subtle">
                      <User
                        size={13}
                        aria-hidden="true"
                        className="text-accent"
                      />
                    </div>
                  )}
                </div>
              ))}

              {busy && (
                <div className="flex gap-3 rounded-sm px-2 py-3">
                  <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-surface-tertiary text-accent">
                    <BrandMark className="h-[11px] w-[17px]" />
                  </div>
                  <div className="min-w-0 max-w-[720px] flex-1">
                    <div className="mb-1 text-[11px] font-medium text-text-muted">
                      Assistant
                    </div>
                    {toolRecords.length > 0 && (
                      <div className="mb-2 flex flex-wrap gap-1.5">
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
                      <div className="selectable md-body text-[14px] leading-[1.72] text-text-primary">
                        <SearchableMarkdown content={streaming.text} query={deferredSearchQuery} />
                        <span
                          aria-hidden="true"
                          className="ml-0.5 inline-block h-3.5 w-[6px] animate-pulse rounded-[2px] bg-accent align-middle"
                        />
                      </div>
                    )}
                    {!streaming.text && toolRecords.length === 0 && (
                      <div className="flex items-center gap-2 py-1 text-[12px] text-text-muted">
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

        <div className="shrink-0 bg-surface-primary px-4 pb-3 pt-2 sm:px-6">
          <form
            className="mx-auto w-full max-w-[780px]"
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            {pendingSteers.length > 0 && (
              <ul
                aria-label="Queued messages"
                className="mb-2 flex flex-wrap items-center gap-1.5"
              >
                {pendingSteers.map((queued) => (
                  <li
                    key={queued.id}
                    className="inline-flex max-w-full items-center gap-1.5 rounded-full border border-accent-glow bg-accent-subtle px-2.5 py-1 text-[11px] text-accent"
                  >
                    <CornerDownLeft size={11} aria-hidden="true" className="shrink-0" />
                    <span className="truncate">{queued.text}</span>
                    <span className="shrink-0 opacity-70">queued</span>
                  </li>
                ))}
              </ul>
            )}
            <label htmlFor="assistant-composer" className="sr-only">
              Message the AI Assistant
            </label>
            <div className="overflow-hidden rounded-md border border-border bg-surface-secondary shadow-sm transition-[border-color,box-shadow] focus-within:border-border-focus focus-within:shadow-md">
              <textarea
                id="assistant-composer"
                value={input}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void submit();
                  }
                }}
                rows={2}
                aria-describedby="assistant-composer-help"
                disabled={!aiReady || sessionActivating}
                placeholder={busy ? "Steer the run — your message is folded in at the next step…" : composerPlaceholder}
                className="selectable block min-h-[58px] w-full resize-none border-0 bg-transparent px-4 py-3 text-[14px] leading-relaxed text-text-primary outline-none placeholder:text-text-muted disabled:cursor-not-allowed disabled:opacity-60"
              />
              <div className="flex min-h-10 items-center gap-1 border-t border-border px-2 py-1.5">
                <button
                  type="button"
                  onClick={openManualContext}
                  disabled={busy || sessionActivating}
                  className="inline-flex h-7 items-center gap-1.5 rounded-sm px-2 text-[11px] text-text-muted transition-colors hover:bg-surface-tertiary hover:text-text-primary disabled:opacity-35"
                >
                  <ClipboardPaste size={12} aria-hidden="true" />
                  Context
                </button>
                <span className="mx-1 h-4 w-px bg-border" aria-hidden="true" />
                <span className="inline-flex min-w-0 items-center gap-1.5 px-1 text-[10px] text-text-muted">
                  <span
                    aria-hidden="true"
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${aiReady ? "bg-success" : aiReadiness.status === "offline" ? "bg-error" : "bg-text-muted"}`}
                  />
                  <span className="truncate">{aiReady ? model ?? "AI ready" : availabilityLabel}</span>
                </span>
                <span className="flex-1" />
                {convUsage && (
                  <span className="hidden shrink-0 font-mono text-[10px] tabular-nums text-text-muted sm:inline">
                    {(convUsage.totalTokens / 1000).toFixed(1)}k · ${convUsage.costUsd.toFixed(4)}
                  </span>
                )}
                <ContextBudgetMeter budget={contextBudget} />
                {busy ? (
                  <>
                    <button
                      type="button"
                      onClick={() => void cancel()}
                      title="Cancel the running turn"
                      aria-label="Cancel the running turn"
                      className="flex h-8 w-8 shrink-0 items-center justify-center rounded-sm text-error transition-colors hover:bg-error-subtle"
                    >
                      <Ban size={14} aria-hidden="true" />
                    </button>
                    <button
                      type="submit"
                      disabled={!input.trim()}
                      title="Steer the running turn"
                      aria-label="Steer the running turn"
                      className="flex h-8 w-8 shrink-0 items-center justify-center rounded-sm bg-accent text-accent-contrast transition-transform hover:scale-[1.03] disabled:cursor-not-allowed disabled:opacity-25"
                    >
                      <CornerDownLeft size={14} aria-hidden="true" />
                    </button>
                  </>
                ) : (
                  <button
                    type="submit"
                    disabled={
                      !input.trim() ||
                      sessionActivating ||
                      !aiReady ||
                      !activeSessionId
                    }
                    title="Send message"
                    aria-label="Send message"
                    className="flex h-8 w-8 shrink-0 items-center justify-center rounded-sm bg-accent text-accent-contrast transition-transform hover:scale-[1.03] disabled:cursor-not-allowed disabled:opacity-25"
                  >
                    <Send size={14} aria-hidden="true" />
                  </button>
                )}
              </div>
            </div>
            <div
              id="assistant-composer-help"
              className="mt-1.5 flex items-center justify-between gap-2 px-1 text-[10px] text-text-muted"
            >
              <span>
                {busy
                  ? "Enter to steer the running turn · Shift+Enter for a new line"
                  : "Enter to send · Shift+Enter for a new line"}
              </span>
              <span className="shrink-0">Tools require approval</span>
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
          {activityOpen && (
            <AssistantActivityPanel
              busy={busy}
              model={model}
              tools={activityTools}
              todos={todos}
              usage={convUsage}
            />
          )}
        </div>
      </div>

      {permission && (
        <ApprovalModal
          tool={permission.tool}
          argumentsPreview={permission.arguments}
          onRestoreFocus={() => assistantFallbackRef.current?.focus()}
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
          onRestoreFocus={() => assistantFallbackRef.current?.focus()}
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
            className="w-full max-w-2xl rounded-md border border-border bg-surface-secondary p-5 shadow-lg"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h2
                  id="assistant-context-title"
                  className="flex items-center gap-2 text-[14px] font-semibold text-text-primary"
                >
                  <ClipboardPaste
                    size={15}
                    aria-hidden="true"
                    className="text-accent"
                  />
                  Review context before attaching
                </h2>
                <p className="mt-1 truncate text-[13px] font-medium text-accent">
                  {contextLabel}
                </p>
              </div>
              <button
                ref={contextCloseRef}
                type="button"
                aria-label="Close"
                onClick={discardContext}
                disabled={contextAttaching}
                className="rounded-sm p-1 text-text-muted hover:bg-surface-hover hover:text-text-primary disabled:opacity-40"
              >
                <X size={15} aria-hidden="true" />
              </button>
            </div>
            <p
              id="assistant-context-description"
              className="mt-2 text-[13px] leading-relaxed text-text-secondary"
            >
              Review and edit this source material before it is saved to the
              current conversation. Findings can contain source code or secrets.
              Attaching does not send anything to the model; it becomes context
              only on your next explicit Send.
            </p>
            {contextProjectPath && (
              <p className="mt-2 break-all rounded-sm border border-border bg-surface-secondary px-2.5 py-2 font-mono text-[12px] text-text-secondary">
                Source scope: {contextProjectPath}
              </p>
            )}
            <label
              htmlFor="assistant-context-content"
              className="mt-4 block text-[12px] font-semibold uppercase tracking-[0.12em] text-text-secondary"
            >
              Context content
            </label>
            <textarea
              id="assistant-context-content"
              value={contextText}
              onChange={(event) => setContextText(event.target.value)}
              readOnly={contextAttaching}
              rows={14}
              className="selectable mt-2 max-h-[55vh] w-full resize-y rounded-sm border border-border bg-surface-primary px-3 py-2.5 font-mono text-[13px] leading-relaxed text-text-primary focus:border-accent"
            />
            <div className="mt-4 flex justify-end gap-2">
              <Button
                type="button"
                onClick={discardContext}
                disabled={contextAttaching}
                variant="ghost"
                size="md"
              >
                Cancel
              </Button>
              <button
                type="button"
                onClick={() => void attachContext()}
                disabled={
                  contextAttaching || !contextText.trim() || !activeSessionId
                }
                className="inline-flex items-center gap-1.5 rounded-sm bg-accent px-3.5 py-2 text-[12px] font-semibold text-accent-contrast hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
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
