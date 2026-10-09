import { useState } from "react";

export interface Pagination {
  /** Zero-based page; displayed controls use one-based labels. */
  page: number;
  pageCount: number;
  pageSize: number;
  total: number;
  /** Zero-based start, exclusive end. */
  start: number;
  end: number;
}

/** Keep DOM work bounded; callers keep their filtered arrays stable with useMemo. */
export function usePagination<T>(items: readonly T[], pageSize = 50, activeIndex?: number) {
  const size = Number.isSafeInteger(pageSize) && pageSize > 0 ? pageSize : 50;
  const pageCount = Math.max(1, Math.ceil(items.length / size));
  const clamp = (page: number) => Math.max(0, Math.min(pageCount - 1, Math.trunc(page) || 0));
  const activePage = activeIndex !== undefined && activeIndex >= 0 ? clamp(Math.floor(activeIndex / size)) : 0;
  const [position, setPosition] = useState({ items, size, activeIndex, page: activePage });
  let current = position;
  // Adjust during render so a replaced filter never briefly shows an empty
  // stale page or an aria-activedescendant that has not been mounted yet.
  if (position.items !== items || position.size !== size || position.activeIndex !== activeIndex) {
    current = { items, size, activeIndex, page: activePage };
    setPosition(current);
  }
  const page = clamp(current.page);
  const start = page * size;
  const end = Math.min(start + size, items.length);
  return {
    page, pageCount, pageSize: size, total: items.length, start, end,
    items: items.slice(start, end),
    setPage: (next: number) => setPosition({ items, size, activeIndex, page: clamp(next) }),
  };
}
