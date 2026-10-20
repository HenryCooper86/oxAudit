import { BadgeCheck, Search, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from "react";
import { Button, Select } from "../components/ui";
import { InlineState } from "../components/workbench/InlineState";
import { ResultsToolbar } from "../components/workbench/ResultsToolbar";
import { ResultPagination } from "../components/workbench/ResultPagination";
import { SplitWorkspace } from "../components/workbench/SplitWorkspace";
import { ToolPage } from "../components/workbench/ToolPage";
import { api } from "../lib/api";
import { useToastStore } from "../lib/stores";
import { usePagination } from "../lib/pagination";
import { useVerificationWrites } from "../features/verification/writes";
import type { CanonicalFinding, VerificationRecord, VerificationResult } from "../lib/types";

export function VerificationPage(): JSX.Element {
  const [claims, setClaims] = useState<CanonicalFinding[] | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [verifierId, setVerifierId] = useState("local-human-reviewer");
  const [error, setError] = useState<string | null>(null);

  const [loadRevision, setLoadRevision] = useState(0);
  useEffect(() => {
    let disposed = false;
    setError(null);
    void api.listVerificationClaims()
      .then(loaded => {
        if (disposed) return;
        setClaims(loaded);
        setSelectedId(current => current && loaded.some(claim => claim.id === current)
          ? current
          : loaded[0]?.id ?? null);
      })
      .catch(cause => { if (!disposed) setError(String(cause)); });
    return () => { disposed = true; };
  }, [loadRevision]);

  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return (claims ?? []).filter((claim) => !normalized || `${claim.title} ${claim.id} ${claim.runId}`.toLowerCase().includes(normalized));
  }, [claims, query]);
  const selected = visible.find(claim => claim.id === selectedId) ?? null;
  const page = usePagination(visible, 50, visible.findIndex(claim => claim.id === selectedId));

  return (
    <ToolPage title="Independent Verification" description="Check an immutable finding snapshot as a separate actor. Verification records evidence and limitations; it never silently changes review disposition.">
      {!claims && !error && <InlineState tone="running" title="Loading verifiable claims" />}
      {error && (
        <InlineState
          tone="error"
          title="Claims could not be loaded"
          description={error}
          action={<Button onClick={() => setLoadRevision(value => value + 1)}>Retry claims</Button>}
        />
      )}
      {claims?.length === 0 && (
        <InlineState
          tone="empty"
          title="No canonical findings are ready for verification"
          description="Complete a new scan to project its issue observations into the independent verification queue."
        />
      )}
      {claims && claims.length > 0 && (
        <section className="overflow-hidden rounded-sm border border-border bg-surface-secondary">
          <ResultsToolbar
            countLabel={`${visible.length} of ${claims.length} claims`}
            search={
              <label className="relative">
                <span className="sr-only">Search claims</span>
                <Search size={13} aria-hidden="true" className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  value={query}
                  onChange={event => setQuery(event.target.value)}
                  placeholder="Search claims…"
                  className="w-56 rounded-sm border border-border bg-surface-primary py-1.5 pl-8 pr-2 text-[12px] text-text-primary"
                />
              </label>
            }
          />
          <SplitWorkspace
            panelId="verification-claims"
            listLabel="Claims"
            detailLabel="Independent verification"
            hasSelection={selected !== null}
            onBackToList={() => setSelectedId(null)}
            list={visible.length === 0 ? (
              <InlineState tone="empty" compact title="No claims match this search" />
            ) : (
              <>
                <ul className="divide-y divide-border">
                  {page.items.map(claim => (
                    <li key={claim.id}>
                      <button
                        type="button"
                        data-detail-trigger
                        onClick={() => setSelectedId(claim.id)}
                        aria-current={selected?.id === claim.id}
                        className={`w-full border-l-2 px-3 py-3 text-left ${selected?.id === claim.id ? "border-accent-glow bg-accent-subtle" : "border-transparent hover:bg-surface-hover"}`}
                      >
                        <span className="block text-[13px] font-medium text-text-primary">{claim.title}</span>
                        <span className="mt-1 block truncate font-mono text-[10px] text-text-muted">{claim.id}</span>
                      </button>
                    </li>
                  ))}
                </ul>
                <ResultPagination label="verification claims" pagination={page} onPageChange={page.setPage} />
              </>
            )}
            detail={selected ? (
              <ClaimVerification key={selected.id} claim={selected} verifierId={verifierId} onVerifierId={setVerifierId} />
            ) : <InlineState tone="empty" compact title="Select a claim" />}
          />
        </section>
      )}
    </ToolPage>
  );
}

/** Each claim panel owns its history and draft; writes survive panel navigation. */
function ClaimVerification({ claim, verifierId, onVerifierId }: {
  claim: CanonicalFinding;
  verifierId: string;
  onVerifierId: (value: string) => void;
}): JSX.Element {
  const push = useToastStore(state => state.push);
  const [records, setRecords] = useState<VerificationRecord[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyRevision, setHistoryRevision] = useState(0);
  const [result, setResult] = useState<VerificationResult>("inconclusive");
  const [limitation, setLimitation] = useState("");
  const saving = useVerificationWrites(state => state.pending.has(claim.id));
  const saved = useVerificationWrites(state => state.receipts.get(claim.id) ?? null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const mounted = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => {
    let disposed = false;
    setHistoryLoading(true);
    setHistoryError(null);
    if (saved) setRecords(current => [saved, ...current.filter(record => record.id !== saved.id)]);
    void api.listVerifications(claim.id).then(loaded => {
      if (disposed) return;
      // A read started before a save may omit the new immutable record.
      setRecords(current => {
        const byId = new Map(loaded.map(record => [record.id, record]));
        current.forEach(record => byId.set(record.id, record));
        return [...byId.values()].sort((a, b) => b.verifiedAtMs - a.verifiedAtMs);
      });
      if (saved && loaded.some(record => record.id === saved.id)) {
        useVerificationWrites.getState().acknowledge(claim.id, saved.id);
      }
    }).catch(cause => { if (!disposed) setHistoryError(String(cause)); })
      .finally(() => { if (!disposed) setHistoryLoading(false); });
    return () => { disposed = true; };
  }, [claim.id, historyRevision, saved]);

  const verify = useCallback(async () => {
    if (!verifierId.trim() || !useVerificationWrites.getState().begin(claim.id)) return;
    setSaveError(null);
    let savedRecord: VerificationRecord | undefined;
    try {
      const record = await api.verifyFinding(claim.id, verifierId, result, limitation);
      savedRecord = record;
      if (mounted.current) {
        setRecords(current => [record, ...current.filter(item => item.id !== record.id)]);
        setLimitation("");
      }
      push("success", `Independent verification saved for ${claim.title}`);
    } catch (cause) {
      if (mounted.current) setSaveError(String(cause));
      else push("error", `Verification failed for ${claim.title}: ${String(cause)}`);
    } finally {
      useVerificationWrites.getState().finish(claim.id, savedRecord);
    }
  }, [claim.id, claim.title, verifierId, result, limitation, push]);

  return (
    <div className="space-y-4 p-4">
      <div>
        <p className="font-mono text-[10px] text-text-muted">{claim.id}</p>
        <h2 className="mt-1 text-[15px] font-semibold text-text-primary">{claim.title}</h2>
        <p className="mt-1 text-[12px] text-text-secondary">Candidate from run {claim.runId}. The input hash below is fixed when verification is saved.</p>
      </div>
      <div className="rounded-sm border border-border bg-surface-primary p-3">
        <h3 className="flex items-center gap-2 text-[12px] font-semibold text-text-primary">
          <ShieldAlert size={13} aria-hidden="true" />Independence contract
        </h3>
        <p className="mt-1 text-[11px] leading-relaxed text-text-muted">The verifier identity must differ from the producing detector. This action records a verdict but does not confirm, suppress, or edit the finding.</p>
      </div>
      <label className="block text-[12px] text-text-secondary">
        Verifier identity
        <input
          value={verifierId}
          onChange={event => onVerifierId(event.target.value)}
          disabled={saving}
          className="mt-1 w-full rounded-sm border border-border bg-surface-primary px-3 py-2 text-[12px] text-text-primary"
        />
      </label>
      <label className="block text-[12px] text-text-secondary">
        Verdict
        <Select disabled={saving} className="mt-1 w-full" value={result} onChange={event => setResult(event.target.value as VerificationResult)}>
          <option value="supported">Supported by independent check</option>
          <option value="refuted">Refuted</option>
          <option value="inconclusive">Inconclusive</option>
        </Select>
      </label>
      <label className="block text-[12px] text-text-secondary">
        Limitations
        <textarea
          disabled={saving}
          value={limitation}
          onChange={event => setLimitation(event.target.value)}
          rows={3}
          placeholder="What could this check not establish?"
          className="mt-1 w-full resize-y rounded-sm border border-border bg-surface-primary px-3 py-2 text-[12px] text-text-primary"
        />
      </label>
      <Button type="button" onClick={() => void verify()} disabled={saving || !verifierId.trim()} variant="primary" size="md">
        <BadgeCheck size={13} aria-hidden="true" />{saving ? "Saving…" : "Record verification"}
      </Button>
      {saveError && <InlineState compact tone="error" title="Verification could not be saved" description={saveError} />}
      {historyLoading && <InlineState compact tone="running" title="Loading verification history" />}
      {historyError && (
        <InlineState
          compact
          tone="error"
          title="Verification history unavailable"
          description={historyError}
          action={<Button onClick={() => setHistoryRevision(value => value + 1)}>Retry history</Button>}
        />
      )}
      {records.length > 0 && (
        <section>
          <h3 className="text-[11px] font-semibold uppercase tracking-[0.1em] text-text-muted">Immutable history</h3>
          <ul className="mt-2 space-y-2">
            {records.map(record => (
              <li key={record.id} className="rounded-sm border border-border bg-surface-primary p-3">
                <div className="flex justify-between gap-3">
                  <span className="text-[12px] font-medium capitalize text-text-primary">{record.result}</span>
                  <time className="text-[10px] text-text-muted">{new Date(record.verifiedAtMs).toLocaleString()}</time>
                </div>
                <p className="mt-1 text-[11px] text-text-secondary">{record.verifier.id} · producer {record.producerId}</p>
                <p className="mt-1 truncate font-mono text-[9px] text-text-muted" title={record.inputSnapshotSha256}>Input {record.inputSnapshotSha256}</p>
                <p className="mt-1 text-[11px] text-text-muted">{record.limitations.join(" ")}</p>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
