import { Binary, Bot, Boxes, Bug, FileSearch } from "lucide-react";
import { ToolLaunchCard } from "../components/workbench/ToolLaunchCard";
import { ToolPage } from "../components/workbench/ToolPage";
import { ProjectHome } from "../features/project-home/ProjectHome";
import { useAppStore } from "../lib/stores";

const tools = [
  ["Scanning", "Source Scan", "Inspect code for dangerous patterns, secrets, and risky APIs.", "Start source scan", "source-scan"],
  ["Scanning", "Dependency Scan", "Check pinned packages against the OSV advisory database.", "Check dependencies", "deps-scan"],
  ["Scanning", "Binary Scan", "Find vulnerable components bundled inside binaries and firmware.", "Scan a binary", "binary-scan"],
  ["Research", "CVE Research", "Search NVD and OSV without requiring an active project.", "Research vulnerabilities", "cve-research"],
  ["Research", "AI Assistant", "Ask security questions with optional project or finding context.", "Open assistant", "assistant"],
] as const;

const toolIcons = {
  "source-scan": <FileSearch size={18} strokeWidth={1.8} />,
  "deps-scan": <Boxes size={18} strokeWidth={1.8} />,
  "binary-scan": <Binary size={18} strokeWidth={1.8} />,
  "cve-research": <Bug size={18} strokeWidth={1.8} />,
  assistant: <Bot size={18} strokeWidth={1.8} />,
};

export function Dashboard() {
  const { setPage, aiReadiness } = useAppStore();
  const aiAnnouncement = {
    loading: "AI assistant settings are loading.",
    checking: "AI assistant endpoint is being checked.",
    unconfigured: "AI assistant not configured.",
    offline: "AI assistant endpoint unavailable.",
    ready: "AI assistant ready.",
    unavailable: "AI assistant readiness could not be loaded.",
  }[aiReadiness.status];
  const aiDescription = {
    loading: "Loading the saved AI provider settings.",
    checking: "Checking the newly persisted AI endpoint before enabling sends.",
    unconfigured: "Not configured. Add an AI endpoint to enable assistant research.",
    offline: "Configured but unreachable. Check the endpoint settings.",
    ready: "Connected and ready for security research.",
    unavailable: "Readiness could not be loaded from local settings. Review Settings and retry.",
  }[aiReadiness.status];
  const readinessPending =
    aiReadiness.status === "loading" || aiReadiness.status === "checking";

  return (
    <ToolPage title="Project home" description="Resume your project, review saved evidence, and check source and dependencies.">
      <p aria-live="polite" aria-atomic="true" className="sr-only">
        {aiAnnouncement}
      </p>
      <ProjectHome />
      <section aria-label="Tools" className="grid gap-3 sm:grid-cols-2">
        {tools.map(([category, title, description, actionLabel, page]) => (
          <ToolLaunchCard
            key={page}
            category={category}
            title={title}
            description={description}
            actionLabel={actionLabel}
            icon={toolIcons[page]}
            onOpen={() => setPage(page)}
          />
        ))}
      </section>

      <section aria-labelledby="assistant-status-title" className="border-t border-border pt-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 id="assistant-status-title" className="text-[13px] font-semibold text-text-primary">
              AI Assistant
            </h2>
            <p className="mt-1 text-[13px] text-text-muted">
              {aiDescription}
            </p>
          </div>
          <button
            type="button"
            onClick={() =>
              setPage(
                aiReadiness.status === "unavailable" ||
                  aiReadiness.status === "unconfigured"
                  ? "settings"
                  : "assistant",
              )
            }
            disabled={readinessPending}
            className="shrink-0 rounded-sm border border-border bg-surface-tertiary px-3 py-1.5 text-[13px] font-medium text-text-primary transition-colors hover:border-border-strong hover:bg-surface-active"
          >
            {aiReadiness.status === "unavailable"
              ? "Review settings"
              : aiReadiness.status === "unconfigured"
                ? "Configure AI"
                : aiReadiness.status === "loading"
                  ? "Loading AI…"
                  : aiReadiness.status === "checking"
                    ? "Checking AI…"
                    : "Open assistant"}
          </button>
        </div>
      </section>
    </ToolPage>
  );
}
