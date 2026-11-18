import { ClipboardPaste, CornerDownLeft, History } from "lucide-react";
import type { JSX, ReactNode } from "react";
import type { ToolRecord } from "../../lib/types";
import { BrandMark } from "../brand/BrandMark";
import { HighlightedText, SearchableMarkdown } from "./SearchHighlight";
import { ToolCallCard } from "./ToolCallCard";

/**
 * The Assistant's message rows, after oxFuzz's `ChatView`: the person's turns
 * are right-aligned accent-tinted bubbles; the assistant's are a bordered
 * secondary-surface card beside a 28px avatar. Everything that is not model
 * prose keeps its own shape so it can never be mistaken for it: tool calls are
 * code-surface chips above the card, attached source context is a code-surface
 * card of its own, compaction is a dashed divider.
 */

/** Local time of a persisted ISO stamp, or null when there is none. */
export function messageTime(at: string | undefined): { label: string; full: string } | null {
  if (!at) return null;
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return null;
  return {
    label: date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    full: date.toLocaleString(),
  };
}

function MessageTime({ at, className = "" }: { at?: string; className?: string }): JSX.Element | null {
  const time = messageTime(at);
  if (!time) return null;
  return (
    <time dateTime={at} title={time.full} className={`text-[10px] tabular-nums text-text-muted ${className}`}>
      {time.label}
    </time>
  );
}

export function AssistantAvatar(): JSX.Element {
  return (
    <span
      aria-hidden="true"
      className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-border bg-surface-active text-accent"
    >
      <BrandMark className="h-3.5 w-3.5" />
    </span>
  );
}

function RewindButton({ onRewind }: { onRewind: () => void }): JSX.Element {
  return (
    <button
      type="button"
      onClick={onRewind}
      title="Discard this and everything after it, and put the text back in the composer"
      aria-label="Rewind the conversation to this message"
      className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-text-muted opacity-0 transition-[opacity,color,background-color] duration-150 hover:bg-surface-hover hover:text-text-primary focus-visible:opacity-100 group-hover:opacity-100"
    >
      <History size={14} aria-hidden="true" />
    </button>
  );
}

/** One of the person's turns: a right-aligned bubble, at most 80% wide. */
export function UserMessage({
  content,
  at,
  steer = false,
  query,
  onRewind,
}: {
  content: string;
  at?: string;
  /** Sent while a run was active and folded into it. */
  steer?: boolean;
  query: string;
  onRewind?: () => void;
}): JSX.Element {
  return (
    <article aria-label="Your message" className="group flex animate-slide-in-up items-start justify-end gap-1">
      {onRewind && <RewindButton onRewind={onRewind} />}
      <div className="selectable min-w-0 max-w-[80%] rounded-lg border border-border bg-accent-subtle px-4 py-2 text-[14px] leading-[1.6] text-text-primary">
        {steer && (
          <span className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-accent">
            <CornerDownLeft size={10} aria-hidden="true" />
            steered mid-run
          </span>
        )}
        <p className="whitespace-pre-wrap [overflow-wrap:anywhere]">
          <HighlightedText text={content} query={query} />
        </p>
        <MessageTime at={at} className="mt-1 block" />
      </div>
    </article>
  );
}

/**
 * Source material the person attached with "Attach context". It is theirs, not
 * the model's, and reads as material rather than conversation: a code-surface
 * card with its label, right-aligned like their other turns.
 */
export function AttachedContextMessage({
  label,
  body,
  at,
  query,
  onRewind,
}: {
  label: string;
  body: string;
  at?: string;
  query: string;
  onRewind?: () => void;
}): JSX.Element {
  return (
    <article aria-label="Attached source context" className="group flex animate-slide-in-up items-start justify-end gap-1">
      {onRewind && <RewindButton onRewind={onRewind} />}
      <div className="selectable flex min-w-0 max-w-[80%] flex-col overflow-hidden rounded-lg border border-border bg-surface-code">
        <div className="flex items-center gap-1.5 border-b border-border px-3 py-1.5 text-[11px] font-medium text-text-secondary">
          <ClipboardPaste size={12} aria-hidden="true" className="shrink-0 text-accent" />
          <span className="min-w-0 truncate">User-attached source context: {label}</span>
        </div>
        <pre className="max-h-56 overflow-auto whitespace-pre-wrap px-3 py-2 font-mono text-[11.5px] leading-relaxed text-text-secondary [overflow-wrap:anywhere]">
          <HighlightedText text={body} query={query} />
        </pre>
        <div className="flex items-center justify-between gap-3 border-t border-border px-3 py-1 text-[10px] text-text-muted">
          <span>Context only: included when you next send</span>
          <MessageTime at={at} />
        </div>
      </div>
    </article>
  );
}

/** The assistant's side of a turn: avatar, then a column of tools, thinking and the answer card. */
export function AssistantRow({
  children,
  busy = false,
}: {
  children: ReactNode;
  /** The live turn; not announced as a finished message. */
  busy?: boolean;
}): JSX.Element {
  return (
    <article
      aria-label={busy ? "Assistant is working" : "Assistant message"}
      className="flex animate-slide-in-up items-start gap-2"
    >
      <AssistantAvatar />
      <div className="flex min-w-0 max-w-[80%] flex-col items-start gap-1.5">{children}</div>
    </article>
  );
}

/** Tool calls of one turn, as code-surface chips above the answer. */
export function ToolCallList({ tools }: { tools: ToolRecord[] }): JSX.Element | null {
  if (tools.length === 0) return null;
  return (
    <div role="group" aria-label="Tool calls" className="flex max-w-full flex-wrap gap-1.5">
      {tools.map((tool) => (
        <ToolCallCard key={tool.toolCallId} record={tool} />
      ))}
    </div>
  );
}

/** The model's prose: the bordered secondary-surface card. */
export function AssistantAnswer({
  content,
  query,
  streaming = false,
  at,
}: {
  content: string;
  query: string;
  streaming?: boolean;
  at?: string;
}): JSX.Element {
  return (
    <>
      <div className="selectable md-body min-w-0 max-w-full rounded-lg border border-border bg-surface-secondary px-4 py-2 text-[14px] leading-[1.6] text-text-primary [overflow-wrap:anywhere]">
        <SearchableMarkdown content={content} query={query} />
        {streaming && (
          <span
            aria-hidden="true"
            className="ml-0.5 inline-block h-3.5 w-[6px] animate-status-pulse rounded-sm bg-accent align-middle"
          />
        )}
      </div>
      <MessageTime at={at} />
    </>
  );
}
