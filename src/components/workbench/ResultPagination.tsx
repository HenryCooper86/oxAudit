import { useLayoutEffect, useRef, type JSX } from "react";
import type { Pagination } from "../../lib/pagination";
import { Button } from "../ui";

export function ResultPagination({ pagination, label, onPageChange }: {
  pagination: Pagination & { loading?: boolean; error?: string | null };
  label: string;
  onPageChange(page: number): void;
}): JSX.Element {
  const { page, pageCount, start, end, total } = pagination;
  const navigationRef = useRef<HTMLElement>(null);
  const pendingScrollPage = useRef<number | null>(null);
  useLayoutEffect(() => {
    if (pagination.loading || pendingScrollPage.current === null) return;
    const requestedPage = pendingScrollPage.current;
    pendingScrollPage.current = null;
    if (requestedPage !== page) return;
    const results = navigationRef.current?.parentElement;
    const workspace = results?.closest("main");
    if (results && workspace) {
      workspace.scrollTop += results.getBoundingClientRect().top - workspace.getBoundingClientRect().top;
    }
  }, [page, pagination.loading]);
  const changePage = (nextPage: number) => {
    // Server pages temporarily remove their rows; scroll only after they arrive.
    pendingScrollPage.current = nextPage;
    onPageChange(nextPage);
  };
  return <nav ref={navigationRef} aria-label={`Pagination for ${label}`} className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2">
    <span role="status" aria-live="polite" className="text-[11px] tabular-nums text-text-muted">
      {pagination.loading ? `Loading page ${(page + 1).toLocaleString()}…` : pagination.error ? "Saved page unavailable" : <>{total ? (start + 1).toLocaleString() : "0"}–{end.toLocaleString()} of {total.toLocaleString()} · Page {(page + 1).toLocaleString()} of {pageCount.toLocaleString()}</>}
    </span>
    <div className="flex items-center gap-1">
      <Button type="button" variant="ghost" size="sm" aria-label={`First page of ${label}`} disabled={pagination.loading || page === 0} onClick={() => changePage(0)}>First</Button>
      <Button type="button" variant="ghost" size="sm" aria-label={`Previous page of ${label}`} disabled={pagination.loading || page === 0} onClick={() => changePage(page - 1)}>Previous</Button>
      <Button type="button" variant="ghost" size="sm" aria-label={`Next page of ${label}`} disabled={pagination.loading || page >= pageCount - 1} onClick={() => changePage(page + 1)}>Next</Button>
      <Button type="button" variant="ghost" size="sm" aria-label={`Last page of ${label}`} disabled={pagination.loading || page >= pageCount - 1} onClick={() => changePage(pageCount - 1)}>Last</Button>
    </div>
  </nav>;
}
