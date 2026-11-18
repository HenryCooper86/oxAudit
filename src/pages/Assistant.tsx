import {
  Fragment,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent,
} from "react";
import {
  Activity,
  ClipboardPaste,
  CornerDownLeft,
  FolderOpen,
  Loader2,
  Maximize2,
  MessagesSquare,
  Minimize2,
  Search,
  Send,
  Settings2,
  Square,
  Trash2,
  X,
} from "lucide-react";
import { AssistantActivityPanel } from "../components/chat/AssistantActivityPanel";
import { AgentTodoPanel } from "../components/chat/AgentTodoPanel";
import { ApprovalModal } from "../components/chat/ApprovalModal";
import { AskUserModal } from "../components/chat/AskUserModal";
import { AssistantNotice } from "../components/chat/AssistantNotice";
import { AssistantPanelDock } from "../components/chat/AssistantPanelDock";
import { AssistantWelcome, projectName } from "../components/chat/AssistantWelcome";
import {
  AssistantAnswer,
  AssistantRow,
  AttachedContextMessage,
  ToolCallList,
  UserMessage,
} from "../components/chat/ChatMessage";
import { ChatSearchToolbar } from "../components/chat/ChatSearchToolbar";
import { ComposerModeToggle } from "../components/chat/ComposerModeToggle";
import { ConfirmDialog } from "../components/chat/ConfirmDialog";
import { ContextBudgetMeter } from "../components/chat/ContextBudgetMeter";
import { ContextCompactedNotice } from "../components/chat/ContextCompactedNotice";
import {
  DIALOG_CARD_CLASS,
  DIALOG_OVERLAY_CLASS,
  DIALOG_TITLE_CLASS,
} from "../components/chat/dialogRecipe";
import { SessionSidebar } from "../components/chat/SessionSidebar";
import { SlashCommandMenu } from "../components/chat/SlashCommandMenu";
import { ThinkingCard } from "../components/chat/ThinkingCard";
import { useMediaQuery } from "../components/chat/useMediaQuery";
import { streamChat, type StreamHandle } from "../lib/aiEvents";
import {
  applyMode,
  composerLayout,
  parseAttachedContext,
  readChatMode,
  saveChatMode,
  type ChatMode,
} from "../lib/assistantComposer";
import {
  ASSISTANT_DRAWER_QUERY,
  readAssistantPanel,
  saveAssistantPanel,
  toggleAssistantPanel,
  type AssistantPanel,
} from "../lib/assistantPanels";
import { nextSearchIndex } from "../lib/chatSearch";
import {
  buildContextBudget,
  estimateMessageTokens,
  type ContextBudgetMetadata,
} from "../lib/contextBudget";
import { useHeaderActions, type HeaderAction } from "../lib/headerActions";
import { planRewind } from "../lib/rewind";
import { matchingSlashCommands, type SlashCommand } from "../lib/slashCommands";
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
import { serverMode } from "../lib/transport";
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
import { errorMessage } from "../lib/commandError";
import { newId } from "../lib/ids";

interface UiMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  /** Submitted mid-run. Live-session styling only; a reload shows a plain turn. */
  steer?: boolean;
  tools?: ToolRecord[];
  /** This answer was generated from a compacted conversation. */
  compaction?: { summarizedMessages: number; summary: string };
  /** When it was written (ISO); shown as the message's time. */
  at?: string;
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
    compaction: message.compaction,
    at: message.at,
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
  const openSettings = useAppStore((state) => state.openSettings);
  const push = useToastStore((state) => state.push);

  const [messages, setMessages] = useState<UiMessage[]>([]);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  /** A rewind awaiting confirmation; truncation is permanent. */
  const [rewindRequest, setRewindRequest] = useState<{
    messageId: string;
    discardedCount: number;
    replacesDraft: boolean;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  /** Steers accepted by the run but not yet folded into the conversation. */
  const [pendingSteers, setPendingSteers] = useState<{ id: string; text: string }[]>([]);
  /** A message the run declined (it was already finishing); sent as a new turn. */
  const [followUp, setFollowUp] = useState<string | null>(null);
  /** The agent's working plan, maintained by the `todo` tool. */
  const [todos, setTodos] = useState<TodoItem[]>([]);
  // Mounting always starts the session bootstrap, so the page begins in the
  // activating state rather than briefly claiming there is no conversation.
  const [sessionActivating, setSessionActivating] = useState(true);
  /** Why the session list could not be loaded; cleared by a successful retry. */
  const [sessionsError, setSessionsError] = useState<string | null>(null);
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
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const deferredSearchQuery = useDeferredValue(searchQuery);
  const [searchIndex, setSearchIndex] = useState(0);
  const [searchTotal, setSearchTotal] = useState(0);
  const [contextBudgetMetadata, setContextBudgetMetadata] =
    useState<ContextBudgetMetadata | null>(null);
  /** Older turns summarized for the current turn; null while nothing was folded. */
  const [compaction, setCompaction] = useState<{
    summarizedMessages: number;
    summary: string;
  } | null>(null);
  /** Highlighted row in the composer's slash-command menu. */
  const [slashIndex, setSlashIndex] = useState(0);
  /** Auto, or "Plan & act": a planning instruction on the model's copy of each message. */
  const [mode, setModeState] = useState<ChatMode>(() => readChatMode());
  /** The composer's taller "expanded" size. */
  const [expanded, setExpanded] = useState(false);
  /** Narrow windows open the side panels as a drawer over the conversation. */
  const drawer = useMediaQuery(ASSISTANT_DRAWER_QUERY);
  const drawerRef = useRef(drawer);
  drawerRef.current = drawer;
  /** The open side panel (Conversations or Activity); one at a time, closed by default. */
  const [panel, setPanelState] = useState<AssistantPanel | null>(() =>
    typeof window !== "undefined" && window.matchMedia?.(ASSISTANT_DRAWER_QUERY)?.matches
      ? null
      : readAssistantPanel(),
  );
  const composerRef = useRef<HTMLTextAreaElement>(null);

  const conversationId = useRef<string>(newId());
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
  const compactionRef = useRef<{ summarizedMessages: number; summary: string } | null>(
    null,
  );
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

  /** Open or close a side panel. Only the docked layout's choice is remembered. */
  const setPanel = (next: AssistantPanel | null) => {
    setPanelState(next);
    if (!drawerRef.current) saveAssistantPanel(next);
  };

  const setMode = (next: ChatMode) => {
    setModeState(next);
    saveChatMode(next);
  };
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
      // A later user action or another dialog owns focus now. Do not let this
      // deferred return move it back into the previous workspace.
      const focused = document.activeElement;
      if (document.querySelector('[aria-modal="true"]') ||
        (focused && focused !== document.body && focused !== document.documentElement)) return;
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
    setCompaction(null);
    compactionRef.current = null;
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
      if (requestIsCurrent(token)) push("error", errorMessage(error));
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
      if (requestIsCurrent(token)) push("error", errorMessage(error));
    } finally {
      finishSessionRequest(token);
    }
  };

  /**
   * Load the session list and open the newest session, unless the one already
   * open (a chat started after an earlier failure) is still in the list.
   * A failure is kept on screen with a Retry rather than flashed as a toast:
   * without a session nothing can be sent.
   */
  const bootstrapSessions = async (token: RequestToken) => {
    try {
      const list = await ensureAssistantSessions();
      if (!requestIsCurrent(token)) return;
      setSessionsError(null);
      setSessions(list);
      const current = list.find(
        (session) => session.id === activeSessionIdRef.current,
      );
      if (!current) await activateSession(list[0], token);
    } catch (error) {
      if (requestIsCurrent(token)) {
        setSessionsError(errorMessage(error));
        // Retry lives in the Conversations panel; nothing can be sent until
        // it succeeds, so open the panel rather than leave the reason hidden.
        setPanelState("sessions");
      }
    } finally {
      finishSessionRequest(token);
    }
  };

  const retrySessions = () => {
    if (sessionActivationPendingRef.current) return;
    void bootstrapSessions(beginSessionRequest());
  };

  /** Stop targeting a session that no longer exists. */
  const clearActiveSession = () => {
    conversationId.current = newId();
    activeSessionIdRef.current = null;
    setActiveSessionId(null);
    setMessages([]);
    setTodos([]);
    setConvUsage(null);
    setModel(null);
    setContextBudgetMetadata(null);
    setPendingSteers([]);
    setUnavailableProject(null);
  };

  // The Assistant owns this one-time session bootstrap. An effect event, so
  // the per-render session helpers it calls are not dependencies.
  const bootstrapOnMount = useEffectEvent(() => {
    void bootstrapSessions(beginSessionRequest());
  });

  useEffect(() => {
    mountedRef.current = true;
    bootstrapOnMount();
    return () => {
      mountedRef.current = false;
      sessionActivationPendingRef.current = false;
      sessionRequests.invalidate();
    };
    // sessionRequests is created once per mount (lazy ref), so this runs once.
  }, [sessionRequests]);

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

  // Escape runs the latest discard, not the one from when the dialog opened.
  const discardContextOnEscape = useEffectEvent(() => discardContext());

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
          discardContextOnEscape();
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
    const compactionRecord = compactionRef.current;
    const stored: StoredMessage = {
      id: newId(),
      role: "assistant",
      content,
      tools: tools.length ? tools : undefined,
      model: modelName,
      compaction: compactionRecord ?? undefined,
      at: new Date().toISOString(),
    };
    setMessages((current) => [
      ...current,
      {
        id: stored.id,
        role: stored.role,
        content: stored.content,
        tools: stored.tools,
        compaction: compactionRecord ?? undefined,
        at: stored.at,
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

  /**
   * Append `content` as a user turn to `history` and stream the agent's reply.
   * Shared by `send` (full history, compaction allowed) and
   * `regenerateWithFullContext` (history rebuilt from a truncated transcript,
   * compaction suppressed).
   *
   * `modelContent` is what the model receives for this turn (the Plan & act
   * prefix, when that mode is on). The transcript, the session file and
   * rewind always keep `content`, the text the person typed.
   */
  const runStreamedTurn = async (
    history: ChatMessage[],
    content: string,
    allowCompaction: boolean,
    modelContent: string = content,
  ) => {
    const next: ChatMessage[] = [...history, { role: "user", content: modelContent }];
    const stored: StoredMessage = {
      id: newId(),
      role: "user",
      content,
      at: new Date().toISOString(),
    };
    setMessages((current) => [
      ...current,
      { id: stored.id, role: stored.role, content: stored.content, at: stored.at },
    ]);
    setInput("");
    setBusy(true);
    setPendingSteers([]);
    settledRef.current = false;
    turnToolsRef.current.clear();
    setToolRecords([]);
    setStreaming({ text: "", reasoning: "", thinking: false });
    setContextBudgetMetadata(null);
    setCompaction(null);
    compactionRef.current = null;

    if (activeSessionId) {
      api
        .sessionAppend(activeSessionId, stored)
        .then(updateSessionInfo)
        .catch(() => undefined);
    }

    const handle = streamChat(
      {
        messages: next,
        conversationId: conversationId.current,
        allowCompaction,
      },
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
        onContextCompacted: (compactionEvent) => {
          compactionRef.current = {
            summarizedMessages: compactionEvent.summarizedMessages,
            summary: compactionEvent.summary,
          };
          setCompaction(compactionRef.current);
        },
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
            id: newId(),
            role: "user",
            content: text,
            at: new Date().toISOString(),
          };
          setMessages((current) => [
            ...current,
            { id: stored.id, role: "user", content: text, steer: true, at: stored.at },
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
                id: newId(),
                role: "assistant",
                content: partial
                  ? `${partial}\n\n_— interrupted (${message})_`
                  : `_— interrupted (${message})_`,
                tools: tools.length ? tools : undefined,
                at: new Date().toISOString(),
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
   * Start a turn. `planMode` false sends the text as typed whatever the
   * composer mode (a declined steer re-sent as its own turn was never a
   * planning request).
   */
  const send = async (text?: string, planMode = true) => {
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
    await runStreamedTurn(history, content, true, applyMode(content, planMode ? mode : "auto"));
  };

  /**
   * Re-answer the question that produced a compacted reply, this time with the
   * full conversation sent uncompacted. Rewinds to just before that question
   * (dropping the compacted answer) and re-sends it with compaction suppressed.
   * Only offered on the most recent turn, so nothing after it is discarded.
   */
  const regenerateWithFullContext = async (assistantMessageId: string) => {
    if (busy || sessionActivating || !activeSessionId || !aiReady) return;
    const assistantIndex = messages.findIndex(
      (message) => message.id === assistantMessageId,
    );
    if (assistantIndex !== messages.length - 1 || assistantIndex < 1) return;
    const question = messages[assistantIndex - 1];
    if (question.role !== "user") return;

    const plan = planRewind(messages, question.id);
    if (!plan) return;

    try {
      await api.sessionTruncate(activeSessionId, plan.keepCount);
    } catch (error) {
      push("error", `Could not retry with full context: ${errorMessage(error)}`);
      return;
    }

    const kept = messages.slice(0, plan.keepCount);
    setMessages(kept);
    setInput("");
    const history: ChatMessage[] = kept.map((message) => ({
      role: message.role,
      content: message.content,
    }));
    await runStreamedTurn(history, question.content, false, applyMode(question.content, mode));
  };

  /**
   * Drop this user turn and everything after it, handing the text back to the
   * composer so it can be re-asked differently.
   *
   * The transcript is truncated first: if that write fails the in-memory view is
   * left alone, so the UI never claims to have discarded turns that are still on
   * disk and would reappear on reload.
   */
  const requestRewind = (messageId: string) => {
    if (busy || !activeSessionId) return;
    const plan = planRewind(messages, messageId);
    if (!plan) return;
    const draft = input.trim();
    setRewindRequest({
      messageId,
      discardedCount: plan.discardedCount,
      replacesDraft: draft !== "" && draft !== plan.restoredInput.trim(),
    });
  };

  const rewindTo = async (messageId: string) => {
    if (busy || !activeSessionId) return;
    const plan = planRewind(messages, messageId);
    if (!plan) return;

    try {
      await api.sessionTruncate(activeSessionId, plan.keepCount);
    } catch (error) {
      push("error", `Could not rewind: ${errorMessage(error)}`);
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
    composerRef.current?.focus();
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
          { id: newId(), text: content },
        ]);
      } else {
        setFollowUp(content);
      }
    } catch (error) {
      setInput(content);
      push("error", `That message could not be sent: ${errorMessage(error)}`);
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
  // run had already produced. `send` is an effect event: the latest one runs,
  // and recreating it each render does not re-trigger the follow-up.
  const sendFollowUp = useEffectEvent((content: string) => {
    void send(content, false);
  });

  useEffect(() => {
    if (!followUp || busy || sessionActivating || !activeSessionId || !aiReady) {
      return;
    }
    setFollowUp(null);
    sendFollowUp(followUp);
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
      id: newId(),
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
          { id: stored.id, role: stored.role, content: stored.content, at: stored.at },
        ]);
      }
      updateSessionInfo(info);
      contextAttachPendingRef.current = false;
      setContextAttaching(false);
      closeContext();
    } catch (error) {
      push("error", `Context could not be attached: ${errorMessage(error)}`);
    } finally {
      contextAttachPendingRef.current = false;
      setContextAttaching(false);
    }
  };

  /**
   * Clear the transcript. Persisted sessions truncate first: if that write
   * fails the in-memory view is left alone, so the UI never claims a cleared
   * conversation whose turns are still on disk and would reappear on reload.
   */
  const clearConversation = async () => {
    if (activeSessionId) {
      try {
        await api.sessionTruncate(activeSessionId, 0);
      } catch (error) {
        push("error", `Could not clear the conversation: ${errorMessage(error)}`);
        return;
      }
    }
    setMessages([]);
    setTodos([]);
    setConvUsage(null);
    setModel(null);
    setContextBudgetMetadata(null);
    setToolRecords([]);
    turnToolsRef.current.clear();
    if (!activeSessionId) return;
    const info = sessions.find((session) => session.id === activeSessionId);
    if (info) updateSessionInfo({ ...info, messageCount: 0 });
  };

  /** Run a composer slash command. Clears the composer first, as a command is a
   *  shortcut — it never leaves a half-typed `/scan` behind. */
  const executeSlashCommand = async (command: SlashCommand) => {
    setInput("");
    setSlashIndex(0);
    const action = command.action;
    switch (action.kind) {
      case "navigate":
        setPage(action.page);
        return;
      case "clear":
        await clearConversation();
        return;
      case "resume": {
        const other = sessions.find((session) => session.id !== activeSessionId);
        if (other) await loadSession(other.id);
        else push("info", "No other conversations to resume.");
        return;
      }
      case "copy": {
        const lastAssistant = [...messages]
          .reverse()
          .find((message) => message.role === "assistant");
        if (!lastAssistant) {
          push("error", "No assistant reply to copy yet.");
          return;
        }
        try {
          if (!navigator.clipboard) throw new Error("Clipboard API unavailable");
          await navigator.clipboard.writeText(lastAssistant.content);
          push("success", "Last reply copied to clipboard.");
        } catch (error) {
          push("error", `Could not copy: ${errorMessage(error)}`);
        }
        return;
      }
    }
  };

  const openManualContext = (event: MouseEvent<HTMLButtonElement>) => {
    contextReturnFocusRef.current = event.currentTarget;
    setContextLabel("Manual context");
    setContextText("");
    setContextProjectPath(null);
    setContextOpen(true);
  };

  /**
   * Give the empty conversation a project. A session's project is fixed when
   * it is created, so this starts a new conversation in that project and opens
   * it through the same activation (and runtime-project coordinator) as any
   * other session. The empty, auto-titled conversation it replaces is deleted
   * once the new one is open; if that delete fails it simply stays listed.
   */
  const startConversationInProject = async (projectPath: string | null) => {
    if (busy || sessionActivationPendingRef.current) return;
    const previous = activeSession;
    const replaceable =
      previous !== null &&
      previous.autoTitle &&
      previous.messageCount === 0 &&
      messages.length === 0;
    const token = beginSessionRequest();
    try {
      const session = await api.sessionCreate(null, projectPath);
      if (!requestIsCurrent(token)) return;
      setSessions((list) => [session, ...list]);
      await activateSession(session, token, []);
      if (replaceable && previous && requestIsCurrent(token)) {
        api
          .sessionDelete(previous.id)
          .then(() => {
            if (mountedRef.current) {
              setSessions((list) => list.filter((item) => item.id !== previous.id));
            }
          })
          .catch(() => undefined);
      }
    } catch (error) {
      if (requestIsCurrent(token)) push("error", errorMessage(error));
    } finally {
      finishSessionRequest(token);
    }
  };

  /** A starter prompt fills the composer for editing; it never sends by itself. */
  const fillComposer = (text: string) => {
    setInput(text);
    setSlashIndex(0);
    requestAnimationFrame(() => {
      const composer = composerRef.current;
      if (!composer || composer.disabled) return;
      composer.focus();
      composer.setSelectionRange(text.length, text.length);
    });
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
  const slashCommands = useMemo(() => matchingSlashCommands(input), [input]);
  const slashOpen = !busy && slashCommands.length > 0;
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
  /** Why the composer is locked when no conversation is open. */
  const noSessionMessage =
    activeSessionId || sessionActivating
      ? null
      : sessionsError
        ? "Conversations could not be loaded. Use Retry in the Conversations panel, or start a new chat."
        : "No conversation is open. Start a new chat to send a message.";
  const availabilityLabel = {
    loading: "AI settings loading",
    checking: "AI endpoint checking",
    unconfigured: "AI not configured",
    offline: "AI endpoint unavailable",
    ready: "AI ready",
    unavailable: "AI readiness unavailable",
    unsupported: "AI not available in this build",
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
    unsupported:
      "AI is available in the oxAudit desktop app; this server does not accept AI requests.",
  }[aiReadiness.status];
  const composerPlaceholder = {
    loading: "Loading saved AI settings…",
    checking: "Checking the newly persisted AI endpoint…",
    unconfigured: "Configure an AI provider to send messages",
    offline: "The saved AI endpoint is offline",
    ready:
      mode === "plan"
        ? "Describe the task; the assistant outlines a plan, then acts…"
        : "Ask a security question or describe what you want to analyze…",
    unavailable: "Review Settings to restore AI readiness",
    unsupported: "AI is not available in the browser build",
  }[aiReadiness.status];


  // Entering the narrow layout closes a docked panel instead of throwing a
  // drawer over the conversation the person was reading.
  useEffect(() => {
    if (drawer) setPanelState(null);
  }, [drawer]);

  // oxFuzz's auto-grow: about three lines at rest, growing with the text up to
  // a share of the window, then scrolling inside the composer.
  useLayoutEffect(() => {
    const composer = composerRef.current;
    if (!composer) return;
    composer.style.height = "auto";
    const layout = composerLayout({
      scrollHeight: composer.scrollHeight,
      expanded,
      viewportHeight: window.innerHeight,
    });
    composer.style.height = `${layout.height}px`;
    composer.style.overflowY = layout.scroll ? "auto" : "hidden";
  }, [input, expanded]);

  // The header toggles read the latest handlers through a ref, so the actions
  // array only changes when what they show changes.
  const headerHandlersRef = useRef({
    toggleSearch: () => undefined as void,
    togglePanel: (_panel: AssistantPanel) => undefined as void,
  });
  headerHandlersRef.current = {
    toggleSearch: () => (searchOpen ? closeSearch() : openSearch()),
    togglePanel: (requested) => setPanel(toggleAssistantPanel(panel, requested)),
  };
  const headerActions = useMemo<HeaderAction[]>(
    () => [
      {
        id: "search",
        label: "Search conversation",
        icon: Search,
        pressed: searchOpen,
        keyShortcuts: "Meta+F Control+F",
        onSelect: () => headerHandlersRef.current.toggleSearch(),
      },
      {
        id: "conversations",
        label: "Conversations",
        icon: MessagesSquare,
        pressed: panel === "sessions",
        controls: panel === "sessions" ? "assistant-sessions-panel" : undefined,
        onSelect: () => headerHandlersRef.current.togglePanel("sessions"),
      },
      {
        id: "activity",
        label: "Activity",
        icon: Activity,
        pressed: panel === "activity",
        controls: panel === "activity" ? "assistant-activity-panel" : undefined,
        onSelect: () => headerHandlersRef.current.togglePanel("activity"),
      },
    ],
    [searchOpen, panel],
  );
  useHeaderActions("assistant", headerActions);

  const conversationTitle = activeSession?.title || "New security conversation";
  const empty = messages.length === 0 && !busy;
  const composerDisabled = !aiReady || sessionActivating || !activeSessionId;
  const hasText = input.trim().length > 0;
  const canSend = hasText && !composerDisabled;
  const canClear = messages.length > 0 && !busy && !sessionActivating;
  const projectPath = activeSession?.projectPath ?? null;
  const projectDetachable = messages.length === 0 && !busy && !sessionActivating;
  const readinessRole =
    aiReadiness.status === "offline" ||
    aiReadiness.status === "unavailable" ||
    aiReadiness.status === "unsupported"
      ? "alert"
      : "status";
  const readinessTone =
    aiReadiness.status === "offline"
      ? "error"
      : aiReadiness.status === "unsupported"
        ? "info"
        : aiReadiness.status === "loading" || aiReadiness.status === "checking"
          ? "progress"
          : "warning";
  const modelLabel = aiReady
    ? model ?? settings?.ai.model ?? "AI ready"
    : availabilityLabel;
  const drawerOpen = drawer && panel !== null;

  const selectSession = (id: string) => {
    if (id !== activeSessionId && !busy && !sessionActivating) {
      void loadSession(id);
    }
    if (drawerRef.current) setPanelState(null);
  };

  return (
    <div
      ref={assistantRootRef}
      className="relative h-full min-h-0 overflow-hidden bg-surface-primary"
    >
      <div
        inert={contextOpen}
        aria-hidden={contextOpen ? "true" : undefined}
        className="flex h-full min-h-0 min-w-0"
      >
        <section
          ref={assistantFallbackRef}
          tabIndex={-1}
          aria-label="Assistant conversation"
          inert={drawerOpen}
          className="flex min-w-0 flex-1 animate-fade-in flex-col"
        >
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

          <div
            ref={conversationScrollRef}
            aria-busy={busy}
            className="min-h-0 flex-1 overflow-y-auto"
          >
            <div className="flex min-h-full w-full flex-col px-4 pb-2 pt-4">
              <h2
                className={
                  empty
                    ? "sr-only"
                    : "mb-3 truncate text-center text-[11px] font-medium text-text-muted"
                }
              >
                {conversationTitle}
              </h2>

              {empty && (
                <AssistantWelcome
                  projectPath={projectPath}
                  onSelectProject={(path) => void startConversationInProject(path)}
                  projectDisabled={busy || sessionActivating}
                  serverMode={serverMode}
                  onSuggestion={fillComposer}
                />
              )}

              <div className="flex flex-col gap-3">
                {messages.map((message) => {
                  const onRewind =
                    message.role === "user" && !busy
                      ? () => requestRewind(message.id)
                      : undefined;
                  const attached =
                    message.role === "user" ? parseAttachedContext(message.content) : null;
                  return (
                    <Fragment key={message.id}>
                      {message.compaction && (
                        <ContextCompactedNotice
                          summarizedMessages={message.compaction.summarizedMessages}
                          summary={message.compaction.summary}
                          onRetry={
                            message.id === messages[messages.length - 1]?.id
                              ? () => void regenerateWithFullContext(message.id)
                              : undefined
                          }
                        />
                      )}
                      {message.role === "user" ? (
                        attached ? (
                          <AttachedContextMessage
                            label={attached.label}
                            body={attached.body}
                            at={message.at}
                            query={deferredSearchQuery}
                            onRewind={onRewind}
                          />
                        ) : (
                          <UserMessage
                            content={message.content}
                            at={message.at}
                            steer={message.steer}
                            query={deferredSearchQuery}
                            onRewind={onRewind}
                          />
                        )
                      ) : (
                        <AssistantRow>
                          <ToolCallList tools={message.tools ?? []} />
                          {(message.content.trim() || !message.tools?.length) && (
                            <AssistantAnswer
                              content={message.content}
                              query={deferredSearchQuery}
                              at={message.at}
                            />
                          )}
                        </AssistantRow>
                      )}
                    </Fragment>
                  );
                })}

                {busy && compaction && (
                  <ContextCompactedNotice
                    summarizedMessages={compaction.summarizedMessages}
                    summary={compaction.summary}
                  />
                )}

                {busy && (
                  <AssistantRow busy>
                    <ToolCallList tools={toolRecords} />
                    {showThinking && (
                      <ThinkingCard
                        text={streaming.reasoning}
                        streaming={streaming.thinking}
                      />
                    )}
                    {todos.length > 0 && panel !== "activity" && (
                      <div className="w-[min(420px,100%)]">
                        <AgentTodoPanel items={todos} />
                      </div>
                    )}
                    {streaming.text && (
                      <AssistantAnswer
                        content={streaming.text}
                        query={deferredSearchQuery}
                        streaming
                      />
                    )}
                    {!streaming.text && toolRecords.length === 0 && (
                      <div className="flex items-center gap-2 px-1 py-1 text-[13px] text-text-muted">
                        <Loader2 size={14} aria-hidden="true" className="animate-spin" />
                        {showThinking ? "Reasoning…" : "Waiting for response…"}
                      </div>
                    )}
                  </AssistantRow>
                )}
              </div>
              <div ref={bottomRef} />
            </div>
          </div>

          <div className="shrink-0 px-4 pb-4 pt-2">
            {(activeUnavailableProject || !aiReady) && (
              <div className="mb-2 space-y-2">
                {activeUnavailableProject && (
                  <AssistantNotice role="status" tone="warning" title="Project unavailable">
                    <code className="font-mono">{activeUnavailableProject.path}</code>. The persisted
                    transcript remains available and runtime project context is cleared.
                  </AssistantNotice>
                )}
                {!aiReady && (
                  <AssistantNotice
                    role={readinessRole}
                    tone={readinessTone}
                    title={availabilityLabel}
                    action={
                      aiReadiness.status !== "unsupported" && (
                        <Button variant="outline" size="sm" onClick={() => openSettings("ai")}>
                          <Settings2 size={12} aria-hidden="true" />
                          Open Settings
                        </Button>
                      )
                    }
                  >
                    {unavailableMessage}
                  </AssistantNotice>
                )}
              </div>
            )}

            <form
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
                      className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-accent-glow bg-accent-subtle px-2.5 py-1 text-[11px] text-accent"
                    >
                      <CornerDownLeft size={11} aria-hidden="true" className="shrink-0" />
                      <span className="truncate">{queued.text}</span>
                      <span className="shrink-0 opacity-70">queued</span>
                    </li>
                  ))}
                </ul>
              )}
              {slashOpen && (
                <SlashCommandMenu
                  commands={slashCommands}
                  selectedIndex={slashIndex}
                  onSelect={(command) => void executeSlashCommand(command)}
                  onHighlight={setSlashIndex}
                />
              )}
              <div className="assistant-composer-card @container flex flex-col rounded-composer border border-border bg-surface-secondary px-3 pb-2 pt-2.5 transition-[border-color,box-shadow] duration-150 focus-within:border-border-strong">
                {projectPath && (
                  <div className="mb-2 flex items-center gap-1.5 self-start">
                    <span
                      title={
                        activeUnavailableProject
                          ? `Project unavailable: ${projectPath}`
                          : projectDetachable
                            ? projectPath
                            : `${projectPath}. A conversation keeps its project; start a new chat to use another.`
                      }
                      className={`inline-flex max-w-[min(28rem,70vw)] items-center gap-1.5 rounded-md border border-border bg-surface-active px-2 py-[3px] font-mono text-[11px] ${activeUnavailableProject ? "text-warning" : "text-text-secondary"}`}
                    >
                      <FolderOpen
                        size={12}
                        aria-hidden="true"
                        className={`shrink-0 ${activeUnavailableProject ? "text-warning" : "text-accent"}`}
                      />
                      <span className="sr-only">Project context: </span>
                      <span className="truncate">{projectName(projectPath)}</span>
                      {projectDetachable && (
                        <button
                          type="button"
                          onClick={() => void startConversationInProject(null)}
                          aria-label="Remove the project from this conversation"
                          title="Remove the project from this conversation"
                          className="inline-flex shrink-0 items-center rounded-sm text-text-muted transition-colors duration-150 hover:text-text-primary"
                        >
                          <X size={12} aria-hidden="true" />
                        </button>
                      )}
                    </span>
                  </div>
                )}
                <label htmlFor="assistant-composer" className="sr-only">
                  Message the AI Assistant
                </label>
                <textarea
                  ref={composerRef}
                  id="assistant-composer"
                  value={input}
                  onChange={(event) => {
                    setInput(event.target.value);
                    setSlashIndex(0);
                  }}
                  onKeyDown={(event) => {
                    if (slashOpen) {
                      if (event.key === "ArrowDown") {
                        event.preventDefault();
                        setSlashIndex((current) =>
                          (current + 1) % slashCommands.length,
                        );
                        return;
                      }
                      if (event.key === "ArrowUp") {
                        event.preventDefault();
                        setSlashIndex(
                          (current) =>
                            (current - 1 + slashCommands.length) %
                            slashCommands.length,
                        );
                        return;
                      }
                      if (event.key === "Enter" && !event.shiftKey) {
                        event.preventDefault();
                        void executeSlashCommand(slashCommands[slashIndex]);
                        return;
                      }
                      if (event.key === "Escape") {
                        event.preventDefault();
                        setInput("");
                        setSlashIndex(0);
                        return;
                      }
                    }
                    // WebKit can report the IME confirmation as keyCode 229 after compositionend.
                    if (event.nativeEvent.isComposing || event.keyCode === 229) return;
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      void submit();
                    }
                  }}
                  rows={3}
                  aria-describedby="assistant-composer-help"
                  disabled={composerDisabled}
                  placeholder={
                    busy
                      ? "Steer the run — your message is folded in at the next step…"
                      : noSessionMessage
                        ? sessionsError
                          ? "Conversations could not be loaded"
                          : "Start a new chat to send a message"
                        : composerPlaceholder
                  }
                  className="assistant-composer-input selectable block min-h-[76px] w-full resize-none border-0 bg-transparent px-0.5 py-1 text-[14px] leading-normal text-text-primary outline-none [overflow-wrap:anywhere] placeholder:text-text-muted disabled:cursor-not-allowed disabled:opacity-60"
                />
                <div className="mt-1 flex items-center justify-between gap-2">
                  <div className="flex shrink-0 items-center gap-1">
                    <ComposerModeToggle mode={mode} onChange={setMode} />
                    <button
                      type="button"
                      onClick={openManualContext}
                      disabled={busy || sessionActivating || !activeSessionId}
                      aria-label="Context"
                      title="Review source material and attach it to this conversation. Nothing is sent until you send a message."
                      className="inline-flex h-[30px] min-w-[30px] items-center justify-center gap-1.5 rounded-md px-1.5 text-[12px] text-text-muted transition-colors duration-150 hover:bg-surface-hover hover:text-text-primary disabled:pointer-events-none disabled:opacity-55 @[520px]:px-2"
                    >
                      <ClipboardPaste size={15} aria-hidden="true" />
                      <span aria-hidden="true" className="hidden @[520px]:inline">
                        Context
                      </span>
                    </button>
                    {canClear && (
                      <button
                        type="button"
                        onClick={() => void clearConversation()}
                        title="Clear conversation"
                        aria-label="Clear conversation"
                        className="inline-flex h-[30px] w-[30px] items-center justify-center rounded-md text-text-muted transition-colors duration-150 hover:bg-error-subtle hover:text-error"
                      >
                        <Trash2 size={15} aria-hidden="true" />
                      </button>
                    )}
                  </div>
                  <div className="flex min-w-0 items-center justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setExpanded((current) => !current)}
                      title={expanded ? "Collapse input" : "Expand input"}
                      aria-label={expanded ? "Collapse input" : "Expand input"}
                      className="inline-flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-md text-text-muted transition-colors duration-150 hover:bg-surface-hover hover:text-text-primary"
                    >
                      {expanded ? (
                        <Minimize2 size={15} aria-hidden="true" />
                      ) : (
                        <Maximize2 size={15} aria-hidden="true" />
                      )}
                    </button>
                    {convUsage && (
                      <span className="hidden shrink-0 font-mono text-[10px] tabular-nums text-text-muted @[760px]:inline">
                        {(convUsage.totalTokens / 1000).toFixed(1)}k · ${convUsage.costUsd.toFixed(4)}
                      </span>
                    )}
                    <ContextBudgetMeter budget={contextBudget} className="hidden @[600px]:flex" />
                    <span
                      className="inline-flex min-w-0 items-center gap-1.5 px-1 text-[12px] text-text-muted"
                      title={aiReady ? `Model: ${modelLabel}` : unavailableMessage}
                    >
                      <span
                        aria-hidden="true"
                        className={`h-1.5 w-1.5 shrink-0 rounded-full ${aiReady ? "bg-success" : aiReadiness.status === "offline" ? "bg-error" : aiReadiness.status === "checking" ? "bg-accent" : "bg-text-muted"}`}
                      />
                      <span className="max-w-[200px] truncate">{modelLabel}</span>
                    </span>
                    {busy ? (
                      <>
                        {hasText && (
                          <button
                            type="submit"
                            title="Steer the running turn"
                            aria-label="Steer the running turn"
                            className="inline-flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-full bg-accent text-accent-contrast transition-colors duration-150 hover:bg-accent-hover"
                          >
                            <CornerDownLeft size={15} aria-hidden="true" />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => void cancel()}
                          title="Cancel the running turn"
                          aria-label="Cancel the running turn"
                          className="inline-flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-full border border-border bg-surface-active text-text-primary transition-colors duration-150 hover:bg-surface-hover"
                        >
                          <Square size={12} fill="currentColor" aria-hidden="true" />
                        </button>
                      </>
                    ) : (
                      <button
                        type="submit"
                        disabled={!canSend}
                        title="Send message"
                        aria-label="Send message"
                        className={
                          canSend
                            ? "inline-flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-full bg-accent text-accent-contrast transition-colors duration-150 hover:bg-accent-hover"
                            : "inline-flex h-[30px] w-[30px] shrink-0 cursor-default items-center justify-center rounded-full bg-transparent text-text-secondary disabled:opacity-55"
                        }
                      >
                        <Send size={15} aria-hidden="true" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </form>
            <div
              id="assistant-composer-help"
              className="mt-1.5 flex flex-wrap items-center justify-between gap-x-3 gap-y-0.5 px-1 text-[10.5px] text-text-muted"
            >
              <span>
                {busy
                  ? "Enter to steer the running turn · Shift+Enter for a new line"
                  : noSessionMessage ??
                    "Enter to send · Shift+Enter for a new line"}
              </span>
              <span>Project reads run without asking; other tools ask for approval</span>
            </div>
            <p className="sr-only" aria-live="polite">
              {busy
                ? showThinking
                  ? "The Assistant is reasoning."
                  : "The Assistant is responding."
                : "The Assistant is idle."}
            </p>
          </div>
        </section>

        {panel && (
          <AssistantPanelDock drawer={drawer} onClose={() => setPanel(null)}>
            {panel === "sessions" ? (
              <SessionSidebar
                sessions={sessions}
                activeId={activeSessionId}
                busy={busy}
                disabled={sessionActivating}
                onClose={() => setPanel(null)}
                onSelect={selectSession}
                onCreate={() => {
                  if (!busy && !sessionActivating) void createNewChat();
                  if (drawerRef.current) setPanelState(null);
                }}
                onRename={(id, title) => {
                  // The list only adopts the new title after the write succeeds, so
                  // a failed rename leaves the old title instead of claiming one
                  // that was never persisted.
                  api
                    .sessionRename(id, title)
                    .then(() => {
                      const info = sessions.find((session) => session.id === id);
                      if (info) updateSessionInfo({ ...info, title, autoTitle: false });
                    })
                    .catch((error) => {
                      push("error", `Could not rename the conversation: ${errorMessage(error)}`);
                    });
                }}
                loadError={sessionsError}
                onRetry={retrySessions}
                onDelete={async (id) => {
                  // Drop the session from the list only after the delete persists;
                  // on failure it stays visible instead of vanishing until reload.
                  try {
                    await api.sessionDelete(id);
                  } catch (error) {
                    push("error", `Could not delete the conversation: ${errorMessage(error)}`);
                    return;
                  }
                  setSessions((list) =>
                    list.filter((session) => session.id !== id),
                  );
                  if (id === activeSessionId) {
                    // Cleared first, so a failed replacement leaves no session to
                    // send to rather than one whose transcript is already gone.
                    clearActiveSession();
                    await createNewChat();
                  }
                }}
              />
            ) : (
              <AssistantActivityPanel
                busy={busy}
                model={model ?? (settings?.ai.model || null)}
                tools={activityTools}
                todos={todos}
                usage={convUsage}
                onClose={() => setPanel(null)}
              />
            )}
          </AssistantPanelDock>
        )}
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

      {rewindRequest && (
        <ConfirmDialog
          title="Rewind this conversation?"
          confirmLabel="Rewind"
          onCancel={() => setRewindRequest(null)}
          onConfirm={() => {
            const { messageId } = rewindRequest;
            setRewindRequest(null);
            void rewindTo(messageId);
          }}
          onRestoreFocus={() => assistantFallbackRef.current?.focus()}
        >
          <p>
            This permanently removes {rewindRequest.discardedCount}{" "}
            {rewindRequest.discardedCount === 1 ? "message" : "messages"} from this
            conversation, starting with the selected one. Its text goes back into the
            composer so you can ask again.
          </p>
          {rewindRequest.replacesDraft && (
            <p className="text-warning">
              Your unsent draft will be replaced with the rewound message.
            </p>
          )}
        </ConfirmDialog>
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
        // The backdrop is a pointer-only dismiss target; Escape is the keyboard path.
        <div
          role="presentation"
          className={DIALOG_OVERLAY_CLASS}
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
            className={`${DIALOG_CARD_CLASS} flex max-h-[calc(100vh-2rem)] max-w-2xl flex-col overflow-y-auto`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h2
                  id="assistant-context-title"
                  className={`flex items-center gap-2 ${DIALOG_TITLE_CLASS}`}
                >
                  <ClipboardPaste
                    size={18}
                    aria-hidden="true"
                    className="shrink-0 text-accent"
                  />
                  Review context before attaching
                </h2>
                <p className="mt-1 truncate text-[12px] font-medium text-accent">
                  {contextLabel}
                </p>
              </div>
              <button
                ref={contextCloseRef}
                type="button"
                aria-label="Close"
                onClick={discardContext}
                disabled={contextAttaching}
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-text-muted transition-colors duration-150 hover:bg-surface-hover hover:text-text-primary disabled:opacity-55"
              >
                <X size={15} aria-hidden="true" />
              </button>
            </div>
            <p
              id="assistant-context-description"
              className="mt-3 text-[12px] leading-relaxed text-text-secondary"
            >
              Review and edit this source material before it is saved to the
              current conversation. Findings can contain source code or secrets.
              Attaching does not send anything to the model; it becomes context
              only on your next explicit Send.
            </p>
            {contextProjectPath && (
              <p className="mt-2 break-all rounded-md border border-border bg-surface-secondary px-2.5 py-1.5 font-mono text-[12px] text-text-secondary">
                Source scope: {contextProjectPath}
              </p>
            )}
            <label
              htmlFor="assistant-context-content"
              className="mt-4 block text-[10.5px] font-semibold uppercase tracking-[0.08em] text-text-muted"
            >
              Context content
            </label>
            <textarea
              id="assistant-context-content"
              value={contextText}
              onChange={(event) => setContextText(event.target.value)}
              readOnly={contextAttaching}
              rows={14}
              className="selectable mt-2 max-h-[55vh] min-h-24 w-full resize-y rounded-md border border-border bg-surface-code px-3 py-2.5 font-mono text-[12px] leading-relaxed text-text-primary outline-none focus:border-border-focus"
            />
            <div className="mt-4 flex items-center justify-end gap-2">
              <Button
                type="button"
                onClick={discardContext}
                disabled={contextAttaching}
                variant="outline"
                size="md"
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                size="md"
                onClick={() => void attachContext()}
                disabled={
                  contextAttaching || !contextText.trim() || !activeSessionId
                }
              >
                {contextAttaching ? (
                  <Loader2 size={13} aria-hidden="true" className="animate-spin" />
                ) : (
                  <ClipboardPaste size={13} aria-hidden="true" />
                )}
                {contextAttaching ? "Attaching…" : "Attach context"}
              </Button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
