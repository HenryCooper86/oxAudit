import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { normalizeCommandError } from "./commandError";
import type { CanonicalProjectionSection, ResultPage, ResultPageQuery } from "./types";

/** Rows are owned by a query lifetime, not a reusable run key. */
export function useServerPage<T, P extends ResultPage<T> = ResultPage<T>>(
  runId: string | null, query: ResultPageQuery,
  load: (runId: string, query: ResultPageQuery) => Promise<P>,
  totalHint = 0, revision = 0, pageSize = 50, scope = "",
) {
  const key = JSON.stringify([runId, query, revision, pageSize, scope]);
  const [position, setPosition] = useState({ key, generation: 0, page: 0, retry: 0, visit: 0 });
  let current = position;
  if (position.key !== key) {
    current = { key, generation: position.generation + 1, page: 0, retry: 0, visit: 0 };
    setPosition(current);
  }
  const { generation, page, retry, visit } = current;
  // Returning to the same offset is a new request, even if the intervening
  // page never settled. Keep totals for the query, but do not revive old rows.
  const request = JSON.stringify([key, generation, page, retry, visit]);
  const [response, setResponse] = useState<{ request: string; key: string; generation: number; total?: number; data?: P; error?: string } | null>(null);
  useEffect(() => {
    if (!runId) return;
    let disposed = false;
    const parsed = JSON.parse(key)[1] as ResultPageQuery;
    void load(runId, { ...parsed, offset: page * pageSize, limit: pageSize }).then(
      data => { if (!disposed) setResponse({ request, key, generation, total: data.filteredTotal, data }); },
      cause => {
        if (!disposed) setResponse(previous => ({
          request, key, generation,
          // A failed later page must remain retryable at the same offset.
          // Counts belong to this query lifetime; rows still belong to one request.
          total: previous?.key === key && previous.generation === generation ? previous.total : undefined,
          error: normalizeCommandError(cause).message,
        }));
      },
    );
    return () => { disposed = true; };
  }, [runId, key, generation, page, retry, request, load, pageSize]);
  const owned = response?.key === key && response.generation === generation ? response : null;
  const settled = owned?.request === request ? owned : null;
  const data = settled?.data;
  const total = owned?.total ?? totalHint;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const boundedPage = Math.min(page, pageCount - 1);
  if (boundedPage !== page) setPosition({ ...current, page: boundedPage, visit: visit + 1 });
  const start = boundedPage * pageSize;
  return {
    page: boundedPage, pageCount, pageSize, total, start, end: Math.min(start + pageSize, total),
    items: boundedPage === page ? data?.items ?? [] : [], data: boundedPage === page ? data : undefined,
    loading: Boolean(runId && !settled), error: settled?.error ?? null,
    setPage: (next: number) => {
      const nextPage = Math.max(0, Math.min(pageCount - 1, Math.trunc(next) || 0));
      if (nextPage !== page) setPosition({ ...current, page: nextPage, visit: visit + 1 });
    },
    retry: () => setPosition({ ...current, retry: retry + 1 }),
  };
}

export function useCanonicalPage<T>(runId: string | null, section: CanonicalProjectionSection, query: ResultPageQuery = {}, total = 0) {
  const load = useCallback((id: string, value: ResultPageQuery) => api.loadCanonicalProjectionPage<T>(id, section, value), [section]);
  return useServerPage<T>(runId, query, load, total, 0, 50, section);
}
