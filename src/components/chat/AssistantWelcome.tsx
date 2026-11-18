import { open as openFolderPicker } from "@tauri-apps/plugin-dialog";
import { ChevronDown, FolderOpen, FolderPlus, FolderX, Keyboard } from "lucide-react";
import { useEffect, useId, useRef, useState, type JSX, type KeyboardEvent } from "react";
import { api } from "../../lib/api";
import { errorMessage } from "../../lib/commandError";
import { useToastStore } from "../../lib/stores";
import type { RecentProject } from "../../lib/types";
import { BrandMark } from "../brand/BrandMark";
import { Button } from "../ui";

/** Starter prompts: a short chip label and the prompt it puts in the composer. */
export const ASSISTANT_SUGGESTIONS: ReadonlyArray<{ label: string; prompt: string }> = [
  {
    label: "Compare XSS variants",
    prompt: "Explain the difference between stored, reflected and DOM XSS with code examples.",
  },
  {
    label: "Fix an unsafe pickle.loads()",
    prompt: "I found a `pickle.loads()` call on untrusted input — how do I fix it?",
  },
  {
    label: "Auth flow checklist",
    prompt: "Help me build a focused checklist for reviewing an authentication flow.",
  },
  {
    label: "Triage a SQL injection",
    prompt: "What should I check when triaging a reported SQL injection in a Java app?",
  },
];

const RECENT_LIMIT = 8;

export function projectName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

/**
 * The empty conversation, after oxFuzz's welcome: the mark with its accent
 * glow, an italic display title, what the assistant is and is not, the
 * conversation's project, and starter prompts that fill the composer without
 * sending anything.
 */
export function AssistantWelcome({
  projectPath,
  onSelectProject,
  projectDisabled,
  serverMode,
  onSuggestion,
}: {
  /** The conversation's project, or null when it has none. */
  projectPath: string | null;
  onSelectProject: (path: string | null) => void;
  projectDisabled: boolean;
  serverMode: boolean;
  onSuggestion: (prompt: string) => void;
}): JSX.Element {
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-4 py-8 text-center">
      <BrandMark className="mb-[18px] h-[84px] w-[84px] text-accent drop-shadow-[0_0_24px_var(--accent-glow)]" />
      <h2 className="mb-1 font-display text-[22px] font-medium italic text-text-primary">Welcome to oxAudit</h2>
      <p className="max-w-md text-[13px] leading-[1.6] text-text-secondary">
        A security review assistant. It reads the project you attach, asks before using any other
        tool, and its answers are advisory.
        <span className="block">What would you like to audit?</span>
      </p>
      <div className="mt-6">
        <WelcomeProjectSelector
          projectPath={projectPath}
          onSelect={onSelectProject}
          disabled={projectDisabled}
          serverMode={serverMode}
        />
      </div>
      <div className="mt-6 flex max-w-lg flex-wrap justify-center gap-2">
        {ASSISTANT_SUGGESTIONS.map(({ label, prompt }) => (
          <Button key={label} variant="outline" size="sm" title={prompt} onClick={() => onSuggestion(prompt)}>
            {label}
          </Button>
        ))}
      </div>
    </div>
  );
}

type RecentState = { status: "loading" } | { status: "ready"; projects: RecentProject[] } | { status: "error" };

/**
 * oxFuzz's `WelcomeProjectSelector`: a bordered 260px trigger naming the
 * conversation's project, opening a list of recent projects (the sidebar's
 * source) and a way to choose another folder: the native picker on the
 * desktop, a typed server path in server mode.
 */
export function WelcomeProjectSelector({
  projectPath,
  onSelect,
  disabled,
  serverMode,
}: {
  projectPath: string | null;
  onSelect: (path: string | null) => void;
  disabled: boolean;
  serverMode: boolean;
}): JSX.Element {
  const [open, setOpen] = useState(false);
  const [typing, setTyping] = useState(false);
  const [typedPath, setTypedPath] = useState("");
  const [recent, setRecent] = useState<RecentState>({ status: "loading" });
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const pathFieldRef = useRef<HTMLInputElement>(null);
  const push = useToastStore((state) => state.push);
  const menuId = useId();
  const name = projectPath ? projectName(projectPath) : "No project";

  useEffect(() => {
    let current = true;
    api
      .listSourceProjects(RECENT_LIMIT)
      .then((projects) => {
        if (current) setRecent({ status: "ready", projects: projects.slice(0, RECENT_LIMIT) });
      })
      .catch(() => {
        if (current) setRecent({ status: "error" });
      });
    return () => {
      current = false;
    };
  }, []);

  // Opening moves focus to the chosen option (or the first), so the list is keyboard-drivable.
  useEffect(() => {
    if (!open) return;
    if (typing) {
      pathFieldRef.current?.focus();
      return;
    }
    const options = Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role="option"]') ?? []);
    (options.find((option) => option.getAttribute("aria-selected") === "true") ?? options[0])?.focus();
  }, [open, typing, recent]);

  const close = (returnFocus = true) => {
    setOpen(false);
    setTyping(false);
    setTypedPath("");
    if (returnFocus) triggerRef.current?.focus();
  };

  const choose = (path: string | null) => {
    close();
    if (path !== projectPath) onSelect(path);
  };

  const browse = async () => {
    close();
    let selected: string | string[] | null;
    try {
      selected = await openFolderPicker({ directory: true, multiple: false, title: "Choose a project for this conversation" });
    } catch (cause) {
      push("error", `Could not open the folder picker. ${errorMessage(cause)}`);
      return;
    }
    if (typeof selected === "string" && selected.trim() && selected.trim() !== projectPath) {
      onSelect(selected.trim());
    }
  };

  const onMenuKey = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    const items = Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role="option"]') ?? []);
    const index = items.indexOf(document.activeElement as HTMLElement);
    const target =
      event.key === "ArrowDown"
        ? items[Math.min(items.length - 1, index + 1)]
        : event.key === "ArrowUp"
          ? items[Math.max(0, index - 1)]
          : event.key === "Home"
            ? items[0]
            : event.key === "End"
              ? items[items.length - 1]
              : null;
    if (target) {
      event.preventDefault();
      target.focus();
    }
  };

  const optionClass = (selected: boolean) =>
    selected
      ? "flex w-full items-center gap-2 bg-surface-active px-3 py-2 text-left text-[13px] text-text-primary"
      : "flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-text-secondary transition-colors duration-150 hover:bg-surface-hover hover:text-text-primary";

  return (
    <div className="relative inline-block text-left">
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={`Project for this conversation: ${name}`}
        title={projectPath ?? "This conversation has no project"}
        disabled={disabled}
        onClick={() => (open ? close() : setOpen(true))}
        onKeyDown={(event) => {
          if (!open && event.key === "ArrowDown") {
            event.preventDefault();
            setOpen(true);
          }
        }}
        className="inline-flex min-w-[260px] max-w-[min(360px,80vw)] items-center gap-2 rounded-lg text-left border border-border bg-surface-secondary px-3.5 py-2.5 text-text-primary transition-colors duration-150 hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-55"
      >
        <FolderOpen size={15} aria-hidden="true" className="shrink-0 text-accent" />
        <span className="min-w-0 flex-1 truncate text-[13px]">{name}</span>
        <ChevronDown size={15} aria-hidden="true" className="shrink-0 text-text-muted" />
      </button>
      {open && (
        <>
          {/* A pointer-only dismiss target; Escape is the keyboard path. */}
          <div role="presentation" className="fixed inset-0 z-40" onMouseDown={() => close(false)} />
          <div
            ref={menuRef}
            id={menuId}
            className="absolute left-0 right-0 z-50 mt-1 overflow-hidden rounded-lg border border-border bg-surface-primary shadow-md"
          >
            {typing ? (
              <form
                aria-label="Project folder on the server"
                className="space-y-2 p-3"
                onSubmit={(event) => {
                  event.preventDefault();
                  if (typedPath.trim()) choose(typedPath.trim());
                }}
              >
                <label htmlFor={`${menuId}-path`} className="block text-[11px] font-medium text-text-secondary">
                  Project folder on the server
                </label>
                <input
                  ref={pathFieldRef}
                  id={`${menuId}-path`}
                  value={typedPath}
                  onChange={(event) => setTypedPath(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Escape") {
                      event.preventDefault();
                      close();
                    }
                  }}
                  placeholder="/srv/repos/app"
                  className="selectable h-8 w-full rounded-md border border-border bg-surface-primary px-2.5 font-mono text-[12px] text-text-primary outline-none placeholder:text-text-muted focus:border-border-focus"
                />
                <p className="text-[11px] leading-relaxed text-text-muted">Paths refer to the server's filesystem.</p>
                <div className="flex justify-end gap-2">
                  <Button variant="ghost" size="sm" onClick={() => setTyping(false)}>
                    Back
                  </Button>
                  <Button type="submit" variant="primary" size="sm" disabled={!typedPath.trim()}>
                    Use folder
                  </Button>
                </div>
              </form>
            ) : (
              <div role="listbox" aria-label="Choose a project" tabIndex={-1} onKeyDown={onMenuKey}>
                {recent.status === "loading" && (
                  <p className="px-3 py-2.5 text-[12px] text-text-muted">Loading recent projects…</p>
                )}
                {recent.status === "error" && (
                  <p className="px-3 py-2.5 text-[12px] text-text-muted">Recent projects are unavailable.</p>
                )}
                {recent.status === "ready" && recent.projects.length === 0 && (
                  <p className="px-3 py-2.5 text-[12px] text-text-muted">No recent projects yet.</p>
                )}
                {recent.status === "ready" &&
                  recent.projects.map((project) => {
                    const selected = project.canonicalPath === projectPath;
                    return (
                      <button
                        key={project.canonicalPath}
                        type="button"
                        role="option"
                        aria-selected={selected}
                        title={project.canonicalPath}
                        onClick={() => choose(project.canonicalPath)}
                        className={optionClass(selected)}
                      >
                        <FolderOpen size={13} aria-hidden="true" className="shrink-0 text-text-muted" />
                        <span className="min-w-0 truncate">{project.displayName || projectName(project.canonicalPath)}</span>
                      </button>
                    );
                  })}
                <div className="border-t border-border" />
                {projectPath && (
                  <button
                    type="button"
                    role="option"
                    aria-selected={false}
                    onClick={() => choose(null)}
                    className={optionClass(false)}
                  >
                    <FolderX size={13} aria-hidden="true" className="shrink-0 text-text-muted" />
                    <span>No project</span>
                  </button>
                )}
                {serverMode ? (
                  <button
                    type="button"
                    role="option"
                    aria-selected={false}
                    onClick={() => setTyping(true)}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-accent transition-colors duration-150 hover:bg-surface-hover"
                  >
                    <Keyboard size={13} aria-hidden="true" className="shrink-0" />
                    <span>Type a server path…</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    role="option"
                    aria-selected={false}
                    onClick={() => void browse()}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] text-accent transition-colors duration-150 hover:bg-surface-hover"
                  >
                    <FolderPlus size={13} aria-hidden="true" className="shrink-0" />
                    <span>Browse for project…</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
