import { useEffect, useRef, useState } from "react";
import { BadgeCheck, ShieldOff, Wand2 } from "lucide-react";
import { api } from "../lib/api";
import type { CanonicalRun, VexClaimSet, VexSuggestions } from "../lib/types";
import { useToastStore } from "../lib/stores";
import { Button, SectionLabel } from "../components/ui";
import { ToolPage } from "../components/workbench/ToolPage";
import { normalizeCommandError } from "../lib/commandError";

function shortSha(sha: string): string {
  return sha.slice(0, 12);
}

export function VexTrustPage() {
  const push = useToastStore((s) => s.push);
  const [claimSets, setClaimSets] = useState<VexClaimSet[] | null>(null);
  const [grantedBy, setGrantedBy] = useState("");
  const [note, setNote] = useState("");
  const [runs, setRuns] = useState<CanonicalRun[]>([]);
  const [runId, setRunId] = useState("");
  const [suggestions, setSuggestions] = useState<VexSuggestions | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [claimsError, setClaimsError] = useState<string | null>(null);
  const [suggestionError, setSuggestionError] = useState<string | null>(null);
  const activeOperation = useRef<string | null>(null);
  const suggestionRequest = useRef(0);
  const claimsRequest = useRef(0);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      suggestionRequest.current += 1;
      claimsRequest.current += 1;
    };
  }, []);

  const refreshClaims = async () => {
    const request = ++claimsRequest.current;
    try {
      const next = await api.vexClaimSets();
      if (mounted.current && request === claimsRequest.current) {
        setClaimSets(next);
        setClaimsError(null);
      }
    } catch (cause) {
      if (mounted.current && request === claimsRequest.current) setClaimsError(normalizeCommandError(cause).message);
    }
  };

  const refreshRuns = async () => {
    try {
      const next = await api.listCanonicalRuns("dependencies");
      if (mounted.current) setRuns(next.filter((run) => run.state === "completed"));
    } catch {
      // The run list is optional context; suggestions name their run.
    }
  };

  useEffect(() => {
    void refreshClaims();
    void refreshRuns();
  }, []);

  const invalidateSuggestions = () => {
    suggestionRequest.current += 1;
    setSuggestions(null);
    setSuggestionError(null);
    if (activeOperation.current === "suggest") {
      activeOperation.current = null;
      setBusy(null);
    }
  };

  const changeTrust = async (contentSha256: string, trusted: boolean) => {
    if (activeOperation.current || (trusted && !grantedBy.trim())) return;
    invalidateSuggestions();
    activeOperation.current = contentSha256;
    setBusy(contentSha256);
    try {
      if (trusted) await api.vexGrantTrust(contentSha256, grantedBy.trim(), note.trim() || undefined);
      else await api.vexRevokeTrust(contentSha256);
      if (!mounted.current) return;
      push("success", trusted
        ? `trusted ${shortSha(contentSha256)}; its not_affected claims can now surface as suggestions`
        : `trust revoked for ${shortSha(contentSha256)}`);
      await refreshClaims();
    } catch (cause) {
      if (mounted.current) push("error", normalizeCommandError(cause).message);
    } finally {
      activeOperation.current = null;
      if (mounted.current) setBusy(null);
    }
  };

  const suggest = async () => {
    if (!runId || activeOperation.current) return;
    const request = ++suggestionRequest.current;
    activeOperation.current = "suggest";
    setBusy("suggest");
    setSuggestions(null);
    setSuggestionError(null);
    try {
      const next = await api.vexSuggest(runId);
      if (mounted.current && request === suggestionRequest.current) setSuggestions(next);
    } catch (cause) {
      if (mounted.current && request === suggestionRequest.current) setSuggestionError(normalizeCommandError(cause).message);
    } finally {
      if (mounted.current && request === suggestionRequest.current) {
        activeOperation.current = null;
        setBusy(null);
      }
    }
  };

  return (
    <ToolPage
      title="VEX Trust"
      description="Imported claims are inert until a person trusts their document. Trusted not_affected claims then surface as triage suggestions — never automatic review changes (ADR 0003)."
    >
      <div className="space-y-4">
        <section className="rounded-sm border border-border bg-surface-secondary p-4">
          <SectionLabel>Trust grants</SectionLabel>
          <p className="mt-2 text-[12px] text-text-secondary">
            Recorded for audit: who granted trust, when, and the document's content hash. Revocable.
          </p>
          <div className="mt-2 flex flex-wrap gap-2 text-[12px]">
            <input
              aria-label="Granted by"
              className="min-w-[160px] rounded-sm border border-border bg-surface px-2 py-1 text-[12px] text-text-primary"
              placeholder="granted by (your name)"
              value={grantedBy}
              onChange={(event) => setGrantedBy(event.target.value)}
            />
            <input
              aria-label="Trust note"
              className="min-w-[240px] flex-1 rounded-sm border border-border bg-surface px-2 py-1 text-[12px] text-text-primary"
              placeholder="note (why this document is trusted)"
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
          </div>
          {!grantedBy.trim() && (
            <p className="mt-2 text-[12px] text-text-muted">
              Enter who grants trust; the name is recorded with every grant.
            </p>
          )}
        </section>

        {claimsError && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px] text-warning">
            <p>{claimsError}</p>
            <Button variant="outline" onClick={() => void refreshClaims()}>Retry claim documents</Button>
          </section>
        )}
        {claimSets === null ? !claimsError && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px] text-text-secondary">Loading claim documents…</section>
        ) : claimSets.length === 0 ? (
          <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px] text-text-secondary">
            No imported claim documents. Import a SARIF, OpenVEX, or CycloneDX VEX report from the
            Export Center, or with <code>oxaudit-cli import</code>.
          </section>
        ) : (
          <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary text-[13px]">
            <ul className="divide-y divide-border">
              {claimSets.map((set) => (
                <li key={set.contentSha256} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-text-muted">{shortSha(set.contentSha256)}</span>
                      <span className="font-semibold">{set.format}</span>
                      <span className={set.trusted ? "text-accent" : "text-text-muted"}>
                        {set.trusted ? `TRUSTED${set.grantedBy ? ` · ${set.grantedBy}` : ""}` : "untrusted"}
                      </span>
                    </div>
                    <p className="text-[11px] text-text-muted">{set.claims} claim(s) · imported as run {set.runId.slice(0, 12)}</p>
                  </div>
                  {set.trusted ? (
                    <Button variant="outline" disabled={busy !== null} onClick={() => void changeTrust(set.contentSha256, false)}>
                      <ShieldOff size={13} aria-hidden />
                      Revoke trust
                    </Button>
                  ) : (
                    <Button disabled={busy !== null || !grantedBy.trim()} onClick={() => void changeTrust(set.contentSha256, true)}>
                      <BadgeCheck size={13} aria-hidden />
                      Trust this document
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          </section>
        )}

        <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px]">
          <SectionLabel>Suggestions against a dependency run</SectionLabel>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <select
              aria-label="Dependency run"
              className="min-w-[280px] rounded-sm border border-border bg-surface px-2 py-1 text-[12px] text-text-primary"
              value={runId}
              onChange={(event) => {
                invalidateSuggestions();
                setRunId(event.target.value);
              }}
            >
              <option value="">select a completed dependency run…</option>
              {runs.map((run) => (
                <option key={run.id} value={run.id}>
                  {run.targetLabel} · {new Date(run.updatedAtMs).toLocaleString()}
                </option>
              ))}
            </select>
            <Button disabled={!runId || busy !== null} onClick={suggest}>
              <Wand2 size={13} aria-hidden />
              Suggest
            </Button>
          </div>
        </section>

        {suggestions && (
          <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary text-[13px]">
            {suggestions.suggestions.length === 0 ? (
              <div className="px-4 py-3 text-text-secondary">
                No suggestions from trusted documents against this run.
              </div>
            ) : (
              <ul className="divide-y divide-border">
                {suggestions.suggestions.map((suggestion, index) => (
                  <li key={index} className="px-4 py-3">
                    <div className="flex items-baseline justify-between gap-3">
                      <span>
                        <span className="font-semibold uppercase text-warning">not_affected</span>{" "}
                        {suggestion.advisoryId} — {suggestion.packageName}@{suggestion.installedVersion}
                      </span>
                      <span className="text-[11px] font-mono text-text-muted">{shortSha(suggestion.documentSha256)} · {suggestion.grantedBy}</span>
                    </div>
                    <p className="mt-1 text-[12px] text-text-secondary">{suggestion.justification}</p>
                    <p className="mt-1 text-[11px] text-text-muted">A suggestion, not a decision — record the review yourself if you agree.</p>
                  </li>
                ))}
              </ul>
            )}
            {suggestions.unmapped.length > 0 && (
              <div className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
                {suggestions.unmapped.map(([sha, record, reason], index) => (
                  <p key={index}>unmapped: {record.slice(0, 24)}… — {reason} (document {shortSha(sha)})</p>
                ))}
              </div>
            )}
            {suggestions.untrusted.length > 0 && (
              <div className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
                {suggestions.untrusted.map(([sha, claims]) => (
                  <p key={sha}>untrusted document {shortSha(sha)} with {claims} claim(s) was not consulted</p>
                ))}
              </div>
            )}
          </section>
        )}

        {suggestionError && (
          <section className="rounded-sm border border-border bg-surface-secondary p-4 text-[13px] text-warning">{suggestionError}</section>
        )}

        <p className="border-t border-border px-4 py-3 text-[11px] text-text-muted">
          Mapping is exact-identity only: a claim must name the advisory by id or alias AND the
          component by exact purl or versioned coordinates. A claim about left-pad@1.2.0 does not
          apply to 1.3.0, and a name-only claim applies to nothing. Unmapped claims state their
          reason; untrusted documents are summarized as not consulted.
        </p>
      </div>
    </ToolPage>
  );
}
