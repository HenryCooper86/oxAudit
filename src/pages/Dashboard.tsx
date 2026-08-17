import { Activity, Boxes, Bot, Bug, FileSearch, ShieldAlert } from "lucide-react";
import { StatCard } from "../components/StatCard";
import { TopBar } from "../components/TopBar";
import { fmtDate } from "../lib/format";
import { useAppStore } from "../lib/stores";

export function Dashboard() {
  const { recentScans, setPage, aiReady } = useAppStore();

  const totals = recentScans.reduce(
    (acc, r) => {
      acc.findings += r.findings;
      acc.critical += r.critical;
      acc.high += r.high;
      return acc;
    },
    { findings: 0, critical: 0, high: 0 },
  );

  return (
    <div className="mx-auto max-w-5xl px-6 py-6">
      <TopBar title="Dashboard" subtitle="Your vulnerability research cockpit" />

      <div className="mt-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="Scans run"
          value={recentScans.length}
          icon={<Activity size={15} />}
          onClick={() => setPage(recentScans.length ? "source-scan" : "source-scan")}
        />
        <StatCard label="Findings" value={totals.findings} icon={<ShieldAlert size={15} />} tone="warning" />
        <StatCard label="Critical" value={totals.critical} icon={<ShieldAlert size={15} />} tone="danger" />
        <StatCard label="High" value={totals.high} icon={<ShieldAlert size={15} />} tone="warning" />
      </div>

      <div className="mt-6">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">
          Quick actions
        </h2>
        <div className="mt-2 grid gap-3 sm:grid-cols-3">
          <button
            onClick={() => setPage("source-scan")}
            className="group rounded-xl border border-ink-700 bg-ink-850 p-4 text-left transition-colors hover:border-teal-500/50 hover:bg-ink-800"
          >
            <FileSearch size={20} className="text-teal-400" />
            <div className="mt-2.5 text-sm font-semibold text-slate-200">Scan source code</div>
            <div className="mt-0.5 text-xs leading-relaxed text-slate-500">
              Detect vulnerable patterns & leaked secrets across a codebase.
            </div>
          </button>
          <button
            onClick={() => setPage("deps-scan")}
            className="group rounded-xl border border-ink-700 bg-ink-850 p-4 text-left transition-colors hover:border-teal-500/50 hover:bg-ink-800"
          >
            <Boxes size={20} className="text-sky-400" />
            <div className="mt-2.5 text-sm font-semibold text-slate-200">Scan dependencies</div>
            <div className="mt-0.5 text-xs leading-relaxed text-slate-500">
              Check your lockfiles against the OSV vulnerability database.
            </div>
          </button>
          <button
            onClick={() => setPage("cve-research")}
            className="group rounded-xl border border-ink-700 bg-ink-850 p-4 text-left transition-colors hover:border-teal-500/50 hover:bg-ink-800"
          >
            <Bug size={20} className="text-orange-400" />
            <div className="mt-2.5 text-sm font-semibold text-slate-200">Research a CVE</div>
            <div className="mt-0.5 text-xs leading-relaxed text-slate-500">
              Search NVD, browse advisories, and get AI briefings on CVEs.
            </div>
          </button>
        </div>
      </div>

      <div className="mt-6 grid gap-3 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">
            Recent scans
          </h2>
          <div className="mt-2 overflow-hidden rounded-xl border border-ink-700 bg-ink-850">
            {recentScans.length === 0 ? (
              <div className="px-4 py-8 text-center text-xs text-slate-500">
                No scans yet — pick a folder from the Source Scan or Dependencies page.
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead className="border-b border-ink-700 text-[10px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="px-4 py-2.5">Target</th>
                    <th className="px-4 py-2.5">Kind</th>
                    <th className="px-4 py-2.5 text-right">Findings</th>
                    <th className="px-4 py-2.5 text-right">Critical</th>
                    <th className="px-4 py-2.5 text-right">High</th>
                    <th className="px-4 py-2.5 text-right">When</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-800">
                  {recentScans.map((r) => (
                    <tr key={r.id} className="text-slate-300">
                      <td className="max-w-[260px] truncate px-4 py-2.5 font-mono text-[11px]">
                        {r.path}
                      </td>
                      <td className="px-4 py-2.5 capitalize">{r.kind}</td>
                      <td className="px-4 py-2.5 text-right tabular-nums">{r.findings}</td>
                      <td className="px-4 py-2.5 text-right tabular-nums text-red-400">
                        {r.critical}
                      </td>
                      <td className="px-4 py-2.5 text-right tabular-nums text-orange-400">{r.high}</td>
                      <td className="px-4 py-2.5 text-right text-slate-500">{fmtDate(r.at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div>
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">
            AI assistant
          </h2>
          <div className="mt-2 rounded-xl border border-ink-700 bg-ink-850 p-4">
            <div className="flex items-center gap-2">
              <Bot size={16} className="text-teal-400" />
              <span className="text-sm font-semibold text-slate-200">VulnCompanion AI</span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-500">
              {aiReady === null
                ? "Not configured. Add an OpenAI-compatible endpoint in Settings to get AI analysis of findings and CVE briefings."
                : aiReady
                  ? "Connected. Ask about scan findings, CVE details, exploit patterns or remediation."
                  : "Configured but unreachable — check your endpoint settings."}
            </p>
            <button
              onClick={() => setPage(aiReady === null ? "settings" : "assistant")}
              className="mt-3 w-full rounded-lg border border-ink-600 bg-ink-750 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-teal-500/50 hover:bg-ink-700"
            >
              {aiReady === null ? "Configure AI" : "Open assistant"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
