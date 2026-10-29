import type { ComponentProps, JSX, MouseEvent } from "react";
import Markdown, { type Components } from "react-markdown";
import { openUrl } from "../lib/opener";

const ALLOWED_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);

/**
 * Returns a normalized href when the link uses an allowed external scheme
 * (http, https, mailto), otherwise null. Relative and fragment links are
 * rejected too: AI-written markdown must never navigate the app window.
 */
export function safeMarkdownHref(href: string | null | undefined): string | null {
  if (typeof href !== "string") return null;
  const trimmed = href.trim();
  if (!trimmed) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  return ALLOWED_PROTOCOLS.has(parsed.protocol) ? parsed.href : null;
}

type AnchorProps = ComponentProps<"a"> & { node?: unknown };

/**
 * Markdown `a` renderer: opens allowed links through the system opener (a new
 * tab in server mode) and never lets the click navigate the app itself.
 */
export function MarkdownLink({ node: _node, href, children, onClick: _onClick, target: _target, rel: _rel, ...props }: AnchorProps): JSX.Element {
  const safe = safeMarkdownHref(href);
  if (!safe) return <span {...(props as ComponentProps<"span">)}>{children}</span>;
  const open = (event: MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault();
    void openUrl(safe).catch(() => {});
  };
  return (
    <a {...props} href={safe} target="_blank" rel="noopener noreferrer" onClick={open}>
      {children}
    </a>
  );
}

export const safeMarkdownComponents: Components = { a: MarkdownLink };

/** react-markdown with the safe external link renderer. */
export function SafeMarkdown({ children }: { children: string }): JSX.Element {
  return <Markdown components={safeMarkdownComponents}>{children}</Markdown>;
}
