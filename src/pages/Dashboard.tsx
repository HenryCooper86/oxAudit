import { Bot, Boxes, Bug, FileSearch } from "lucide-react";
import { ToolLaunchCard } from "../components/workbench/ToolLaunchCard";
import { ToolPage } from "../components/workbench/ToolPage";
import { fmtDate } from "../lib/format";
import { useAppStore } from "../lib/stores";

const tools = [
  ["Scanning", "Source Scan", "Inspect code for dangerous patterns, secrets, and risky APIs.", "Start source scan", "source-scan"],
  ["Scanning", "Dependency Scan", "Check pinned packages against the OSV advisory database.", "Check dependencies", "deps-scan"],
  ["Research", "CVE Research", "Search NVD and OSV without requiring an active project.", "Research vulnerabilities", "cve-research"],
  ["Research", "AI Assistant", "Ask security questions with optional project or finding context.", "Open assistant", "assistant"],
] as const;

const toolIcons = {
  "source-scan": <FileSearch size={18} strokeWidth={1.8} />,
  "deps-scan": <Boxes size={18} strokeWidth={1.8} />,
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
          <h2 id="recent-activity-title" className="text-[13px] font-semibold text-slate-200">
            Recent activity
          </h2>
          {recentActivity.length > 0 && (
            <span className="text-[12px] text-slate-400">Latest {recentActivity.length}</span>
          )}
        </div>
        <div className="mt-2 overflow-hidden rounded-lg border border-ink-700 bg-ink-850">
          {recentActivity.length === 0 ? (
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
              <p className="text-[13px] text-slate-400">No activity yet</p>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => setPage("source-scan")}
                  className="rounded-md border border-ink-600 bg-ink-750 px-3 py-1.5 text-[13px] font-medium text-slate-200 transition-colors hover:border-ink-500 hover:bg-ink-700"
                >
                  Start source scan
                </button>
                <button
                  type="button"
                  onClick={() => setPage("deps-scan")}
                  className="rounded-md border border-ink-600 bg-ink-750 px-3 py-1.5 text-[13px] font-medium text-slate-200 transition-colors hover:border-ink-500 hover:bg-ink-700"
                >
                  Check dependencies
                </button>
              </div>
            </div>
          ) : (
            <table className="w-full table-fixed text-left text-[13px]">
              <thead className="border-b border-ink-700 text-[12px] text-slate-400">
                <tr>
                  <th scope="col" className="w-[45%] px-4 py-2.5 font-medium">Target</th>
                  <th scope="col" className="w-[20%] px-4 py-2.5 font-medium">Tool</th>
                  <th scope="col" className="w-[15%] px-4 py-2.5 text-right font-medium">Findings</th>
                  <th scope="col" className="w-[20%] px-4 py-2.5 text-right font-medium">When</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {recentActivity.map((scan) => (
                  <tr key={scan.id} className="text-slate-300">
                    <td className="truncate px-4 py-2.5 font-mono text-[12px]">{scan.path}</td>
                    <td className="px-4 py-2.5">{scan.kind === "source" ? "Source Scan" : "Dependency Scan"}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums">{scan.findings}</td>
                    <td className="px-4 py-2.5 text-right text-[12px] text-slate-400">{fmtDate(scan.at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      <section aria-labelledby="assistant-status-title" className="border-t border-ink-800 pt-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 id="assistant-status-title" className="text-[13px] font-semibold text-slate-200">
              AI Assistant
            </h2>
            <p className="mt-1 text-[13px] text-slate-400">
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
            className="shrink-0 rounded-md border border-ink-600 bg-ink-750 px-3 py-1.5 text-[13px] font-medium text-slate-200 transition-colors hover:border-ink-500 hover:bg-ink-700"
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
