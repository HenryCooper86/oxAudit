import { Binary, Bot, Boxes, Bug, FileSearch } from "lucide-react";
import { ToolLaunchCard } from "../components/workbench/ToolLaunchCard";
import { ToolPage } from "../components/workbench/ToolPage";
import { fmtDate } from "../lib/format";
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
  const { recentScans, setPage, aiReadiness } = useAppStore();
  const recentActivity = recentScans.slice(0, 6);
  const activityAnnouncement = recentActivity.length === 0
    ? "No recent activity."
    : `${recentActivity.length} recent ${recentActivity.length === 1 ? "activity item" : "activity items"} shown.`;
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
    <ToolPage title="Research Workbench" description="Choose a tool or resume recent work.">
      <p aria-live="polite" aria-atomic="true" className="sr-only">
        {activityAnnouncement} {aiAnnouncement}
      </p>
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

      <section aria-labelledby="recent-activity-title">
        <div className="flex items-center justify-between gap-3">
          <h2 id="recent-activity-title" className="text-[13px] font-semibold text-text-primary">
            Recent activity
          </h2>
          {recentActivity.length > 0 && (
            <span className="text-[12px] text-text-muted">Latest {recentActivity.length}</span>
          )}
        </div>
        <div className="mt-2 overflow-hidden rounded-sm border border-border bg-surface-secondary">
          {recentActivity.length === 0 ? (
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
              <p className="text-[13px] text-text-muted">No activity yet</p>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => setPage("source-scan")}
                  className="rounded-sm border border-border bg-surface-tertiary px-3 py-1.5 text-[13px] font-medium text-text-primary transition-colors hover:border-border-strong hover:bg-surface-active"
                >
                  Start source scan
                </button>
                <button
                  type="button"
                  onClick={() => setPage("deps-scan")}
                  className="rounded-sm border border-border bg-surface-tertiary px-3 py-1.5 text-[13px] font-medium text-text-primary transition-colors hover:border-border-strong hover:bg-surface-active"
                >
                  Check dependencies
                </button>
              </div>
            </div>
          ) : (
            <table className="w-full table-fixed text-left text-[13px]">
              <thead className="border-b border-border text-[12px] text-text-muted">
                <tr>
                  <th scope="col" className="w-[45%] px-4 py-2.5 font-medium">Target</th>
                  <th scope="col" className="w-[20%] px-4 py-2.5 font-medium">Tool</th>
                  <th scope="col" className="w-[15%] px-4 py-2.5 text-right font-medium">Findings</th>
                  <th scope="col" className="w-[20%] px-4 py-2.5 text-right font-medium">When</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {recentActivity.map((scan) => (
                  <tr key={scan.id} className="text-text-secondary">
                    <td className="truncate px-4 py-2.5 font-mono text-[12px]">{scan.path}</td>
                    <td className="px-4 py-2.5">{scan.kind === "source" ? "Source Scan" : "Dependency Scan"}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums">{scan.findings}</td>
                    <td className="px-4 py-2.5 text-right text-[12px] text-text-muted">{fmtDate(scan.at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
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
