import { act, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, test, vi } from 'vitest';
import { api } from '../lib/api';
import { useAppStore } from '../lib/stores';
import type { CanonicalRun } from '../lib/types';
import { ExportCenterPage } from './ExportCenter';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }));
function run(id: string, kind: CanonicalRun['kind'], state: CanonicalRun['state'] = 'completed'): CanonicalRun {
  return { id, kind, state, targetLabel: id, attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] };
}
beforeEach(() => {
  useAppStore.setState({ page: 'dashboard', exportHandoff: null });
  vi.spyOn(api, 'previewRunExport').mockReturnValue(new Promise(() => {}));
});

test('a receipt opens export for its exact run even when another kind is newer', async () => {
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('newer-source', 'source'), run('saved-image', 'image')]);
  useAppStore.getState().openExport('saved-image');
  render(<ExportCenterPage />);
  await waitFor(() => expect(api.previewRunExport).toHaveBeenCalledWith('saved-image', 'oxaudit-json'));
  expect(screen.getByLabelText('Saved run')).toHaveValue('saved-image');
  expect(api.previewRunExport).not.toHaveBeenCalledWith('newer-source', 'oxaudit-json');
  expect(useAppStore.getState().exportHandoff).toBeNull();
});

test('an explicitly requested receipt outside the recent list is still selected and a mounted page accepts another receipt', async () => {
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('newer-source', 'source')]);
  useAppStore.getState().openExport('older-history');
  render(<ExportCenterPage />);
  expect(await screen.findByRole('option', { name: 'Selected saved run · older-history' })).toBeInTheDocument();
  expect(screen.getByLabelText('Saved run')).toHaveValue('older-history');
  await act(async () => useAppStore.getState().openExport('partial-image'));
  await waitFor(() => expect(api.previewRunExport).toHaveBeenCalledWith('partial-image', 'oxaudit-json'));
  expect(screen.getByLabelText('Saved run')).toHaveValue('partial-image');
});
