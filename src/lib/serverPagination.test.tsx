import { ResultPagination } from "../components/workbench/ResultPagination";
import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { useServerPage } from "./serverPagination";
import type { ResultPage, ResultPageQuery } from "./types";
const deferred = <T,>() => { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; };
const page = (items: string[], filteredTotal = 300, offset = 0): ResultPage<string> => ({ items, total: 300, filteredTotal, offset, limit: 50 });

test('authoritative filter totals cannot strand navigation on a page beyond the result set', async () => {
  const filtered = deferred<ResultPage<string>>();
  const load = vi.fn(async (_: string, query: ResultPageQuery) => query.search ? filtered.promise : page(['original']));
  const hook = renderHook(({ search }) => useServerPage<string>('run', { search }, load, 300), { initialProps: { search: '' } });
  await waitFor(() => expect(hook.result.current.items).toEqual(['original']));
  hook.rerender({ search: 'narrow' });
  expect(hook.result.current.items).toEqual([]);
  act(() => hook.result.current.setPage(5));
  await act(async () => filtered.resolve(page(['only', 'two'], 2)));
  await waitFor(() => expect(hook.result.current.page).toBe(0));
  expect(hook.result.current.pageCount).toBe(1);
  expect(hook.result.current.start).toBe(0);
  expect(hook.result.current.end).toBe(2);
  expect(hook.result.current.items).toEqual(['only', 'two']);
});

test('query and A to B to A run lifetimes hide old rows immediately and reject delayed responses', async () => {
  const requests: Array<{ id: string; query: ResultPageQuery; pending: ReturnType<typeof deferred<ResultPage<string>>> }> = [];
  const load = (id: string, query: ResultPageQuery) => { const pending = deferred<ResultPage<string>>(); requests.push({ id, query, pending }); return pending.promise; };
  const hook = renderHook(({ id, search }) => useServerPage<string>(id, { search }, load, 10000), { initialProps: { id: 'A', search: '' } });
  await act(async () => requests[0].pending.resolve(page(['first-A'], 10000)));
  act(() => hook.result.current.setPage(199));
  expect(hook.result.current.items).toEqual([]);
  expect(requests[1].query).toMatchObject({ offset: 9950, limit: 50 });
  hook.rerender({ id: 'B', search: '' });
  hook.rerender({ id: 'A', search: '' });
  expect(hook.result.current.items).toEqual([]);
  await act(async () => { requests[1].pending.resolve(page(['stale-page'], 10000, 9950)); requests[2].pending.resolve(page(['B'])); });
  expect(hook.result.current.items).toEqual([]);
  await act(async () => requests[3].pending.resolve(page(['new-A'], 10000)));
  expect(hook.result.current.items).toEqual(['new-A']);
  hook.rerender({ id: 'A', search: 'new' });
  expect(hook.result.current.items).toEqual([]);
  expect(hook.result.current.page).toBe(0);
});

test('loading pagination announces the pending page without presenting metadata hints as filtered counts', () => {
  render(<ResultPagination label="findings" pagination={{ page: 0, pageCount: 6, pageSize: 50, total: 300, start: 0, end: 50, loading: true }} onPageChange={() => {}} />);
  expect(screen.getByRole('status')).toHaveTextContent('Loading page 1');
  expect(screen.getByRole('status')).not.toHaveTextContent('of 300');
  expect(screen.getByRole('button', { name: 'Last page of findings' })).toBeDisabled();
});
