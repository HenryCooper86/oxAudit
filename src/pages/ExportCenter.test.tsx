import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { open, save } from '@tauri-apps/plugin-dialog';
import { beforeEach, expect, test, vi } from 'vitest';
import { api } from '../lib/api';
import { useAppStore, useToastStore } from '../lib/stores';
import type { CanonicalRun, ExportPreview, ImportPreview } from '../lib/types';
import { ExportCenterPage } from './ExportCenter';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }));
function run(id: string, kind: CanonicalRun['kind'], state: CanonicalRun['state'] = 'completed'): CanonicalRun {
  return { id, kind, state, targetLabel: id, attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] };
}
const exportPreview: ExportPreview = {
  format: 'oxaudit-json', mediaType: 'application/json', suggestedFileName: 'saved-source.json',
  valid: true, warnings: [], artifacts: 1, components: 2, observations: 0,
  content: '{"runId":"saved-source"}', truncated: false,
};
const importPreview: ImportPreview = {
  format: 'cyclonedx', mediaType: 'application/json', fileName: 'inventory.json', contentSha256: 'sha256:inventory',
  componentRecords: 2, findingRecords: 0, reviewRecords: 0, conflictCount: 0, conflicts: [],
  unmappedCount: 0, unmappedRecords: [], warnings: [], canImportInventory: true,
  mappedClaimCount: 0, mappedClaims: [], canImportExternalClaims: false,
};
const dialogFailures = [
  { name: 'a rejected dialog', fail: () => Promise.reject('File dialog unavailable') },
  { name: 'a synchronous dialog refusal', fail: () => { throw 'File dialog unavailable'; } },
];
beforeEach(() => {
  vi.mocked(open).mockReset();
  vi.mocked(save).mockReset();
  useAppStore.setState({ page: 'dashboard', exportHandoff: null });
  useToastStore.setState({ toasts: [] });
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

test.each(dialogFailures)('export surfaces $name and a subsequent save clears the failure', async ({ fail }) => {
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('saved-source', 'source')]);
  vi.mocked(api.previewRunExport).mockResolvedValue(exportPreview);
  vi.spyOn(api, 'writeRunExport').mockResolvedValue(undefined);
  vi.mocked(save).mockImplementationOnce(fail).mockResolvedValueOnce('/exports/saved-source.json');
  render(<ExportCenterPage />);

  await userEvent.click(await screen.findByRole('button', { name: 'Save export…' }));
  expect(await screen.findByText('File dialog unavailable')).toBeInTheDocument();
  expect(api.writeRunExport).not.toHaveBeenCalled();
  expect(useToastStore.getState().toasts).toEqual([
    expect.objectContaining({ kind: 'error', message: 'The export could not be saved' }),
  ]);

  await userEvent.click(screen.getByRole('button', { name: 'Save export…' }));
  await waitFor(() => expect(useToastStore.getState().toasts).toContainEqual(
    expect.objectContaining({ kind: 'success', message: 'Saved oxAudit JSON' }),
  ));
  expect(api.writeRunExport).toHaveBeenCalledWith('saved-source', 'oxaudit-json', '/exports/saved-source.json');
  expect(screen.queryByText('File dialog unavailable')).not.toBeInTheDocument();
});

test.each(dialogFailures)('import surfaces $name and allows choosing another report', async ({ fail }) => {
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([]);
  vi.spyOn(api, 'previewReportImport').mockResolvedValue(importPreview);
  vi.mocked(open).mockImplementationOnce(fail).mockResolvedValueOnce('/reports/inventory.json');
  render(<ExportCenterPage />);

  await userEvent.click(screen.getByRole('button', { name: 'Choose report…' }));
  expect(await screen.findByText('File dialog unavailable')).toBeInTheDocument();
  expect(api.previewReportImport).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Choose report…' })).toBeEnabled();

  await userEvent.click(screen.getByRole('button', { name: 'Choose report…' }));
  expect(await screen.findByText('inventory.json')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Import separate inventory' })).toBeEnabled();
  expect(api.previewReportImport).toHaveBeenCalledWith('/reports/inventory.json');
  expect(screen.queryByText('File dialog unavailable')).not.toBeInTheDocument();
});
