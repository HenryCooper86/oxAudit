import { useEffect, useRef, useState } from "react";
import { listen } from "../lib/events";
import { CircleX, ScanSearch } from "lucide-react";
import { api } from "../lib/api";
import type { ImageScanOutcome } from "../lib/types";
import { useToastStore } from "../lib/stores";
import { Button, SectionLabel, Switch } from "../components/ui";
import { ToolPage } from "../components/workbench/ToolPage";

export function ImageScanPage() {
  const push = useToastStore((s) => s.push);
  const [target, setTarget] = useState("");
  const [advisoryDbPath, setAdvisoryDbPath] = useState("");
  const [offline, setOffline] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string[]>([]);
  const [outcome, setOutcome] = useState<ImageScanOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  const scanInFlight = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let stop: (() => void) | undefined;
    void listen<string>("image://progress", (event) => {
      if (!disposed) setProgress((lines) => [...lines.slice(-199), event.payload]);
    }).then((unlisten) => {
      if (disposed) unlisten();
      else stop = unlisten;
    }).catch((cause) => {
      if (!disposed) setError(String(cause));
    });
    return () => { disposed = true; stop?.(); };
  }, []);

  const scan = async () => {
    if (!target.trim() || scanInFlight.current) return;
    scanInFlight.current = true;
    setBusy(true);
    setProgress([]);
    setOutcome(null);
    setError(null);
    try {
      const next = await api.scanImage({
        target: target.trim(),
        advisoryDbPath: advisoryDbPath.trim() || null,
        offline,
      });
      if (!mounted.current) return;
      setOutcome(next);
      push("success", `image scan complete: ${next.result.summary.vulnerabilities} vulnerabilit${next.result.summary.vulnerabilities === 1 ? "y" : "ies"}`);
    } catch (cause) {
      if (mounted.current) setError(String(cause));
    } finally {
      scanInFlight.current = false;
      if (mounted.current) setBusy(false);
    }
  };

  const summary = outcome?.result.summary;

  return (
    <ToolPage
      title="Image Scan"
      description="Scan a container image — a saved tar, an OCI layout, or a registry reference pulled directly — with the built-in scanner, including the OS package database inside it."
    >
      <div className="space-y-4">
        <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px]">
          <SectionLabel>Target</SectionLabel>
          <input
            aria-label="Image target"
            className="mt-2 w-full rounded-sm border border-border bg-surface px-2 py-1 text-[13px] text-text-primary"
            placeholder="registry-1.docker.io/library/nginx:1.25, a saved image tar, an OCI layout directory, a firmware archive"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void scan();
            }}
          />
          <label className="mt-3 flex items-center gap-2 text-[12px] text-text-secondary">
            Advisory database (optional — offline advisory matching)
            <input
              aria-label="Advisory database path"
              className="min-w-[260px] flex-1 rounded-sm border border-border bg-surface px-2 py-1 text-[12px] text-text-primary"
              placeholder="advisories.sqlite3 (built on the Advisory Database page)"
              value={advisoryDbPath}
              onChange={(event) => setAdvisoryDbPath(event.target.value)}
            />
          </label>
          <label className="mt-3 flex items-center gap-2 text-[12px] text-text-secondary">
            <Switch checked={offline} onChange={setOffline} label="Offline advisories" />
            Offline advisories — answer distro packages only from the advisory database
          </label>
          <div className="mt-3 flex gap-2">
            <Button disabled={busy || !target.trim()} onClick={scan}>
              <ScanSearch size={13} aria-hidden />
              Scan
            </Button>
            {busy && (
              <Button variant="outline" onClick={() => void api.cancelImageScan()}>
                <CircleX size={13} aria-hidden />
                Cancel
              </Button>
            )}
          </div>
        </section>

        {error && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px] text-warning">{error}</section>
        )}

        {progress.length > 0 && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4">
            <SectionLabel>Progress</SectionLabel>
            <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap font-mono text-[11px] text-text-secondary">
              {progress.join("\n")}
            </pre>
          </section>
        )}

        {outcome && summary && (
          <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary text-[13px]">
            <div className="border-b border-border px-4 py-3 font-semibold">
              {outcome.result.target}: {summary.components} component{summary.components === 1 ? "" : "s"},{" "}
              {summary.vulnerabilities} vulnerabilit{summary.vulnerabilities === 1 ? "y" : "ies"}
              {Number(summary.vulnerabilities) > 0 &&
                ` (${[["critical", summary.critical], ["high", summary.high], ["medium", summary.medium], ["low", summary.low]]
                  .filter(([, count]) => Number(count) > 0)
                  .map(([name, count]) => `${count} ${name}`)
                  .join(", ")})`}
            </div>
            <ul className="divide-y divide-border">
              {outcome.result.components.map((component) => (
                <li key={`${component.product}@${component.version}`} className="px-4 py-3">
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="font-semibold">{component.product} <span className="text-text-secondary">{component.version}</span></span>
                    <span className="text-[11px] font-mono text-text-muted">{component.paths[0]}</span>
                  </div>
                  {component.vulnerabilities.length > 0 && (
                    <ul className="mt-1 space-y-1">
                      {component.vulnerabilities.map((vulnerability) => (
                        <li key={vulnerability.cveId} className="text-[12px] text-text-secondary">
                          <span className="font-semibold uppercase">{vulnerability.severity}</span>{" "}
                          {vulnerability.cveId} ({vulnerability.source}
                          {vulnerability.fixedIn ? `, fixed in ${vulnerability.fixedIn}` : ""})
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
            {outcome.notes.length > 0 && (
              <div className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
                {outcome.notes.map((note, index) => (
                  <p key={index}>{note}</p>
                ))}
              </div>
            )}
          </section>
        )}

        <p className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
          Registry pulls verify every blob against its manifest digest; auth is the registry's token
          flow plus docker login's config.json. Offline scans answer distribution packages from the
          advisory database and state which components could only be asked online — never implying a
          clean result. Results are shown here and not persisted as canonical runs.
        </p>
      </div>
    </ToolPage>
  );
}
