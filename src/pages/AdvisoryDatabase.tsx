import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Database, Download, RefreshCw } from "lucide-react";
import { api } from "../lib/api";
import type { AdvisoryDbStatus, AdvisoryDbUpdateReport } from "../lib/types";
import { useToastStore } from "../lib/stores";
import { Button, SectionLabel } from "../components/ui";
import { ToolPage } from "../components/workbench/ToolPage";

function formatTimestamp(ms: number | null): string {
  return ms === null ? "unknown" : new Date(ms).toLocaleString();
}

export function AdvisoryDatabasePage() {
  const push = useToastStore((s) => s.push);
  const [path, setPath] = useState("");
  const [extraEcosystems, setExtraEcosystems] = useState("");
  const [status, setStatus] = useState<AdvisoryDbStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"status" | "update" | null>(null);
  const [progress, setProgress] = useState<string[]>([]);
  const [report, setReport] = useState<AdvisoryDbUpdateReport | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    let stop: (() => void) | undefined;
    void listen<string>("advisorydb://progress", (event) => {
      if (mounted.current) setProgress((lines) => [...lines.slice(-200), event.payload]);
    }).then((unlisten) => {
      stop = unlisten;
    });
    return () => stop?.();
  }, []);

  useEffect(() => {
    let cancelled = false;
    api.defaultAdvisoryDbPath()
      .then((defaultPath) => {
        if (!cancelled) setPath((current) => current || defaultPath);
      })
      .catch(() => {
        // The field stays editable when no default can be resolved.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const refreshStatus = async () => {
    if (!path.trim()) return;
    setBusy("status");
    setStatusError(null);
    try {
      const next = await api.advisoryDbStatus(path.trim());
      if (mounted.current) setStatus(next);
    } catch (cause) {
      if (mounted.current) setStatusError(String(cause));
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  const update = async () => {
    if (!path.trim()) return;
    setBusy("update");
    setProgress([]);
    setReport(null);
    const ecosystems = extraEcosystems
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    try {
      const next = await api.advisoryDbUpdate(path.trim(), ecosystems);
      if (!mounted.current) return;
      setReport(next);
      push("success", `advisory database updated: ${next.totalAdvisories} advisories`);
      const refreshed = await api.advisoryDbStatus(path.trim());
      if (mounted.current) setStatus(refreshed);
    } catch (cause) {
      if (mounted.current) push("error", `advisory database update failed: ${String(cause)}`);
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  return (
    <ToolPage
      title="Advisory Database"
      description="Build and refresh the local OSV corpus that dependency and image scans can answer from without the network."
    >
      <div className="space-y-4">
        <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px]">
          <SectionLabel>Database file</SectionLabel>
          <div className="mt-2 flex flex-wrap gap-2">
            <input
              aria-label="Advisory database path"
              className="min-w-[320px] flex-1 rounded-sm border border-border bg-surface px-2 py-1 text-[13px] text-text-primary"
              placeholder="advisories.sqlite3 — the file dependency and image scans answer from offline"
              value={path}
              onChange={(event) => setPath(event.target.value)}
            />
            <Button variant="outline" disabled={busy !== null || !path.trim()} onClick={refreshStatus}>
              {busy === "status" ? <RefreshCw size={13} className="animate-spin" aria-hidden /> : <Database size={13} aria-hidden />}
              Status
            </Button>
            <Button disabled={busy !== null || !path.trim()} onClick={update}>
              {busy === "update" ? <RefreshCw size={13} className="animate-spin" aria-hidden /> : <Download size={13} aria-hidden />}
              Download defaults
            </Button>
          </div>
          <label className="mt-3 flex items-center gap-2 text-[12px] text-text-secondary">
            Extra ecosystems (comma-separated, added to the defaults)
            <input
              aria-label="Extra ecosystems"
              className="min-w-[260px] flex-1 rounded-sm border border-border bg-surface px-2 py-1 text-[12px] text-text-primary"
              placeholder='Debian:12, Alpine:v3.20, Hex, Pub'
              value={extraEcosystems}
              onChange={(event) => setExtraEcosystems(event.target.value)}
            />
          </label>
        </section>

        {statusError && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px] text-warning">{statusError}</section>
        )}

        {status && (
          <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary text-[13px]">
            <div className="divide-y divide-border">
              <div className="flex justify-between px-4 py-3"><span className="text-text-secondary">Coverage</span><span>{status.ecosystems.join(", ") || "empty"}</span></div>
              <div className="flex justify-between px-4 py-3"><span className="text-text-secondary">Advisories / packages</span><span>{status.advisories} / {status.packages}</span></div>
              <div className="flex justify-between px-4 py-3"><span className="text-text-secondary">Built</span><span>{formatTimestamp(status.builtAtMs)}</span></div>
              <div className="flex justify-between px-4 py-3"><span className="text-text-secondary">Size</span><span>{Math.round(status.sizeBytes / (1024 * 1024))} MiB</span></div>
            </div>
          </section>
        )}

        {progress.length > 0 && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4">
            <SectionLabel>Progress</SectionLabel>
            <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-text-secondary">
              {progress.join("\n")}
            </pre>
          </section>
        )}

        {report && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px]">
            <SectionLabel>Last update</SectionLabel>
            <p className="mt-2 text-text-secondary">
              {report.totalAdvisories} advisories over {report.totalPackages} packages from{" "}
              {report.ecosystems.map((entry) => `${entry.ecosystem} (${entry.records})`).join(", ")}
            </p>
          </section>
        )}

        <p className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
          Downloads come from OSV's published dump bucket (or a mirror set in the CLI via --source).
          Budgets: 2 GiB per ecosystem dump, 16 MiB per record, 300,000 records per ecosystem. A
          failed update never widens coverage: an ecosystem the database does not carry fails
          dependency matching as incomplete coverage, never as a clean result.
        </p>
      </div>
    </ToolPage>
  );
}
