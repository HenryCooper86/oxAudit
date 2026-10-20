import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { open, save } from '@tauri-apps/plugin-dialog';
import { beforeEach, expect, test, vi } from 'vitest';
import { api } from '../lib/api';
import { useAppStore, useToastStore } from '../lib/stores';
import type { CanonicalRun, ExportPreview, ImportPreview } from '../lib/types';
import { ExportCenterPage } from './ExportCenter';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }));
const transport = vi.hoisted(() => ({ serverMode: false }));
vi.mock('../lib/transport', () => ({ get serverMode() { return transport.serverMode; }, httpInvoke: vi.fn() }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

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
const externalPreview: ImportPreview = {
  ...importPreview, format: 'openvex', fileName: 'external-claims.json', contentSha256: 'sha256:external',
  componentRecords: 0, findingRecords: 1, canImportInventory: false,
  mappedClaimCount: 1, canImportExternalClaims: true,
  mappedClaims: [{
    recordId: 'claim-1', claimKind: 'vex', producer: 'External supplier',
    ruleId: null, vulnerabilityId: 'CVE-2026-12345', subjectIds: ['pkg:npm/example@1.0.0'],
    status: 'not_affected', summary: 'Supplier claim', location: null, trust: 'external-unverified',
  }],
};
const dialogFailures = [
  { name: 'a rejected dialog', fail: () => Promise.reject('File dialog unavailable') },
  { name: 'a synchronous dialog refusal', fail: () => { throw 'File dialog unavailable'; } },
];
beforeEach(() => {
  transport.serverMode = false;
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

test('a failed saved-run load can recover without leaving Export Center', async () => {
  vi.spyOn(api, 'listCanonicalRuns')
    .mockRejectedValueOnce('Database temporarily unavailable')
    .mockResolvedValueOnce([run('saved-source', 'source')]);
  vi.mocked(api.previewRunExport).mockResolvedValue(exportPreview);
  render(<ExportCenterPage />);

  await userEvent.click(await screen.findByRole('button', { name: 'Retry loading runs' }));
  expect(await screen.findByRole('button', { name: 'Save export…' })).toBeEnabled();
  expect(screen.getByLabelText('Saved run')).toHaveValue('saved-source');
  expect(screen.getByText(exportPreview.content)).toBeInTheDocument();
  expect(screen.queryByText('Database temporarily unavailable')).not.toBeInTheDocument();
});

test('a failed preview can recover for the same run and format after editing the destination', async () => {
  transport.serverMode = true;
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('saved-source', 'source')]);
  vi.mocked(api.previewRunExport)
    .mockRejectedValueOnce('Preview temporarily unavailable')
    .mockResolvedValueOnce(exportPreview);
  render(<ExportCenterPage />);

  await screen.findByRole('button', { name: 'Retry preview' });
  fireEvent.change(screen.getByLabelText('Export file on server'), { target: { value: '/reports/source.json' } });
  await userEvent.click(screen.getByRole('button', { name: 'Retry preview' }));
  expect(await screen.findByRole('button', { name: 'Save to server' })).toBeEnabled();
  expect(screen.getByLabelText('Saved run')).toHaveValue('saved-source');
  expect(screen.getByLabelText('Format')).toHaveValue('oxaudit-json');
  expect(screen.getByText(exportPreview.content)).toBeInTheDocument();
  expect(screen.queryByText('Preview temporarily unavailable')).not.toBeInTheDocument();
});

test('loading an exact receipt does not hide a separate run-list failure', async () => {
  vi.spyOn(api, 'listCanonicalRuns')
    .mockRejectedValueOnce('Run list temporarily unavailable')
    .mockResolvedValueOnce([run('saved-source', 'source')]);
  vi.mocked(api.previewRunExport).mockResolvedValue(exportPreview);
  useAppStore.getState().openExport('saved-source');
  render(<ExportCenterPage />);

  expect(await screen.findByRole('button', { name: 'Save export…' })).toBeEnabled();
  await userEvent.click(await screen.findByRole('button', { name: 'Retry loading runs' }));
  await waitFor(() => expect(screen.queryByText('Run list temporarily unavailable')).not.toBeInTheDocument());
  expect(screen.getByLabelText('Saved run')).toHaveValue('saved-source');
  expect(screen.getByRole('button', { name: 'Save export…' })).toBeEnabled();
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
  expect(useToastStore.getState().toasts).toContainEqual(expect.objectContaining({ kind: 'error' }));

  await userEvent.click(screen.getByRole('button', { name: 'Save export…' }));
  await waitFor(() => expect(useToastStore.getState().toasts).toContainEqual(
    expect.objectContaining({ kind: 'success' }),
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
  expect(await screen.findByRole('button', { name: 'Import separate inventory' })).toBeEnabled();
  expect(api.previewReportImport).toHaveBeenCalledWith('/reports/inventory.json');
  expect(screen.queryByText('File dialog unavailable')).not.toBeInTheDocument();
});

test('server inspection requires a nonblank path and never opens a native picker', async () => {
  transport.serverMode = true;
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([]);
  vi.spyOn(api, 'previewReportImport').mockResolvedValue(importPreview);
  render(<ExportCenterPage />);

  const inspect = screen.getByRole('button', { name: 'Inspect report' });
  expect(inspect).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Report file on server'), { target: { value: '   ' } });
  expect(inspect).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Report file on server'), { target: { value: ' /reports/inventory.json ' } });
  await userEvent.click(inspect);

  expect(await screen.findByRole('button', { name: 'Import separate inventory' })).toBeEnabled();
  expect(screen.getByText(/SHA-256 sha256:inventory/)).toBeInTheDocument();
  expect(api.previewReportImport).toHaveBeenCalledWith('/reports/inventory.json');
  expect(open).not.toHaveBeenCalled();
});

test.each(['another path', 'A to B to A'])(
  'a deferred server import preview cannot return after editing to %s', async (change) => {
    transport.serverMode = true;
    const pending = deferred<ImportPreview>();
    vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([]);
    vi.spyOn(api, 'previewReportImport').mockReturnValueOnce(pending.promise).mockResolvedValue(importPreview);
    vi.spyOn(api, 'importInventoryReport');
    render(<ExportCenterPage />);
    const path = screen.getByLabelText('Report file on server');
    fireEvent.change(path, { target: { value: '/reports/A.json' } });
    await userEvent.dblClick(screen.getByRole('button', { name: 'Inspect report' }));
    expect(screen.getByRole('button', { name: 'Inspecting…' })).toBeDisabled();
    expect(api.previewReportImport).toHaveBeenCalledTimes(1);
    fireEvent.change(path, { target: { value: '/reports/B.json' } });
    if (change === 'A to B to A') fireEvent.change(path, { target: { value: '/reports/A.json' } });

    await act(async () => pending.resolve({
      ...importPreview, fileName: 'obsolete-preview.json', contentSha256: 'sha256:obsolete',
    }));
    expect(screen.queryByText(/obsolete-preview.json/)).not.toBeInTheDocument();
    expect(screen.queryByText(/sha256:obsolete/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Import separate inventory' })).not.toBeInTheDocument();
    expect(api.importInventoryReport).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Inspect report' })).toBeEnabled();

    await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
    expect(await screen.findByRole('button', { name: 'Import separate inventory' })).toBeEnabled();
    expect(api.previewReportImport).toHaveBeenLastCalledWith(
      change === 'A to B to A' ? '/reports/A.json' : '/reports/B.json',
    );
  },
);

test.each(['another path', 'A to B to A'])(
  'a deferred server preview error stays obsolete after editing to %s', async (change) => {
    transport.serverMode = true;
    const pending = deferred<ImportPreview>();
    vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([]);
    vi.spyOn(api, 'previewReportImport').mockReturnValueOnce(pending.promise).mockResolvedValue(importPreview);
    render(<ExportCenterPage />);
    const path = screen.getByLabelText('Report file on server');
    fireEvent.change(path, { target: { value: '/reports/A.json' } });
    await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
    fireEvent.change(path, { target: { value: '/reports/B.json' } });
    if (change === 'A to B to A') fireEvent.change(path, { target: { value: '/reports/A.json' } });

    await act(async () => pending.reject('Obsolete report cannot be read'));
    expect(screen.queryByText('Obsolete report cannot be read')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Inspect report' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Import separate inventory' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
    expect(await screen.findByRole('button', { name: 'Import separate inventory' })).toBeEnabled();
    expect(screen.queryByText('Obsolete report cannot be read')).not.toBeInTheDocument();
  },
);

test.each(['another path', 'A to B to A'])('editing an inspected path binds a fresh hash to %s', async (change) => {
  transport.serverMode = true;
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([]);
  vi.spyOn(api, 'previewReportImport').mockResolvedValueOnce(importPreview).mockResolvedValueOnce({
    ...importPreview, contentSha256: 'sha256:reinspected',
  });
  vi.spyOn(api, 'importInventoryReport').mockResolvedValue(run('authoritative-inventory', 'import'));
  render(<ExportCenterPage />);
  const path = screen.getByLabelText('Report file on server');
  fireEvent.change(path, { target: { value: '/reports/inventory.json' } });
  await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
  expect(await screen.findByRole('button', { name: 'Import separate inventory' })).toBeEnabled();

  fireEvent.change(path, { target: { value: '/reports/other.json' } });
  expect(screen.queryByRole('button', { name: 'Import separate inventory' })).not.toBeInTheDocument();
  expect(screen.queryByText(/SHA-256 sha256:inventory/)).not.toBeInTheDocument();
  if (change === 'A to B to A') fireEvent.change(path, { target: { value: '/reports/inventory.json' } });
  expect(screen.queryByRole('button', { name: 'Import separate inventory' })).not.toBeInTheDocument();
  expect(api.importInventoryReport).not.toHaveBeenCalled();

  await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Import separate inventory' }));
  expect(await screen.findByRole('option', { name: /authoritative-inventory/ })).toBeInTheDocument();
  expect(screen.getByLabelText('Saved run')).toHaveValue('authoritative-inventory');
  expect(api.importInventoryReport).toHaveBeenCalledExactlyOnceWith(
    change === 'A to B to A' ? '/reports/inventory.json' : '/reports/other.json', 'sha256:reinspected',
  );
});

test('an import failure for an edited-away path cannot restore its error or inspected hash', async () => {
  transport.serverMode = true;
  const pending = deferred<CanonicalRun>();
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([]);
  vi.spyOn(api, 'previewReportImport').mockResolvedValueOnce(importPreview).mockResolvedValueOnce({
    ...importPreview, contentSha256: 'sha256:current',
  });
  vi.spyOn(api, 'importInventoryReport').mockReturnValueOnce(pending.promise).mockResolvedValueOnce(run('current-inventory', 'import'));
  render(<ExportCenterPage />);
  const path = screen.getByLabelText('Report file on server');
  fireEvent.change(path, { target: { value: '/reports/old.json' } });
  await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Import separate inventory' }));
  expect(api.importInventoryReport).toHaveBeenCalledWith('/reports/old.json', 'sha256:inventory');
  fireEvent.change(path, { target: { value: '/reports/current.json' } });
  expect(screen.queryByRole('button', { name: 'Import separate inventory' })).not.toBeInTheDocument();
  await act(async () => pending.reject('Obsolete inventory import failed'));

  expect(screen.queryByText('Obsolete inventory import failed')).not.toBeInTheDocument();
  expect(screen.queryByText(/SHA-256 sha256:inventory/)).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Inspect report' })).toBeEnabled();
  await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
  await userEvent.click(await screen.findByRole('button', { name: 'Import separate inventory' }));
  expect(await screen.findByRole('option', { name: /current-inventory/ })).toBeInTheDocument();
  expect(api.importInventoryReport).toHaveBeenLastCalledWith('/reports/current.json', 'sha256:current');
  expect(screen.queryByText('Obsolete inventory import failed')).not.toBeInTheDocument();
});

test('a failed inventory import can retry without duplicate pending work or optimistic durable runs', async () => {
  transport.serverMode = true;
  const first = deferred<CanonicalRun>();
  const retry = deferred<CanonicalRun>();
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('local-evidence', 'source')]);
  vi.spyOn(api, 'previewReportImport').mockResolvedValue({
    ...importPreview, mappedClaimCount: 1, mappedClaims: externalPreview.mappedClaims, canImportExternalClaims: true,
  });
  vi.spyOn(api, 'importInventoryReport').mockReturnValueOnce(first.promise).mockReturnValueOnce(retry.promise);
  vi.spyOn(api, 'importExternalReport');
  render(<ExportCenterPage />);
  fireEvent.change(screen.getByLabelText('Report file on server'), { target: { value: '/reports/inventory.json' } });
  await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
  const inventory = await screen.findByRole('button', { name: 'Import separate inventory' });
  await userEvent.dblClick(inventory);
  expect(inventory).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Retain external claims' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Retain external claims' }));
  expect(api.importInventoryReport).toHaveBeenCalledTimes(1);
  expect(api.importExternalReport).not.toHaveBeenCalled();
  expect(screen.getByLabelText('Saved run')).toHaveValue('local-evidence');
  expect(screen.queryByRole('option', { name: /server-inventory/ })).not.toBeInTheDocument();

  await act(async () => first.reject('Inventory changed since inspection'));
  expect(await screen.findByText('Inventory changed since inspection')).toBeInTheDocument();
  expect(inventory).toBeEnabled();
  await userEvent.dblClick(inventory);
  expect(api.importInventoryReport).toHaveBeenCalledTimes(2);
  expect(screen.queryByText('Inventory changed since inspection')).not.toBeInTheDocument();
  expect(screen.queryByRole('option', { name: /server-inventory/ })).not.toBeInTheDocument();
  await act(async () => retry.resolve(run('server-inventory', 'import')));
  expect(await screen.findByRole('option', { name: /server-inventory/ })).toBeInTheDocument();
  expect(screen.getByLabelText('Saved run')).toHaveValue('local-evidence');
  expect(api.importInventoryReport).toHaveBeenLastCalledWith('/reports/inventory.json', 'sha256:inventory');
  expect(inventory).toBeEnabled();
});

test('external-only claims retain their unverified boundary and a failed retention can retry', async () => {
  transport.serverMode = true;
  const first = deferred<CanonicalRun>();
  const retry = deferred<CanonicalRun>();
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('local-evidence', 'source')]);
  vi.spyOn(api, 'previewReportImport').mockResolvedValue(externalPreview);
  vi.spyOn(api, 'importExternalReport').mockReturnValueOnce(first.promise).mockReturnValueOnce(retry.promise);
  vi.spyOn(api, 'importInventoryReport');
  render(<ExportCenterPage />);
  fireEvent.change(screen.getByLabelText('Report file on server'), { target: { value: '/reports/external.json' } });
  await userEvent.click(screen.getByRole('button', { name: 'Inspect report' }));
  const retain = await screen.findByRole('button', { name: 'Retain external claims' });
  expect(screen.getByText('CVE-2026-12345')).toBeInTheDocument();
  expect(screen.getByText('external-unverified')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Import separate inventory' })).not.toBeInTheDocument();
  await userEvent.dblClick(retain);
  expect(retain).toBeDisabled();
  expect(api.importExternalReport).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('option', { name: /retained-claims/ })).not.toBeInTheDocument();
  await act(async () => first.reject('External report changed since inspection'));
  expect(await screen.findByText('External report changed since inspection')).toBeInTheDocument();

  await userEvent.dblClick(retain);
  expect(api.importExternalReport).toHaveBeenCalledTimes(2);
  expect(screen.queryByText('External report changed since inspection')).not.toBeInTheDocument();
  await act(async () => retry.resolve(run('retained-claims', 'external_evidence')));
  expect(await screen.findByRole('option', { name: /external_evidence.*retained-claims/ })).toBeInTheDocument();
  expect(screen.getByRole('option', { name: /source.*local-evidence/ })).toBeInTheDocument();
  expect(screen.getByLabelText('Saved run')).toHaveValue('local-evidence');
  expect(screen.getByText('external-unverified')).toBeInTheDocument();
  expect(api.importExternalReport).toHaveBeenLastCalledWith('/reports/external.json', 'sha256:external');
  expect(api.importInventoryReport).not.toHaveBeenCalled();
  expect(retain).toBeEnabled();
});


test('a server export failure clears on retry and blocks duplicate writes while pending', async () => {
  transport.serverMode = true;
  const first = deferred<void>();
  const retry = deferred<void>();
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('saved-source', 'source')]);
  vi.mocked(api.previewRunExport).mockResolvedValue(exportPreview);
  vi.spyOn(api, 'writeRunExport').mockReturnValueOnce(first.promise).mockReturnValueOnce(retry.promise);
  render(<ExportCenterPage />);
  const button = await screen.findByRole('button', { name: 'Save to server' });
  expect(button).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Export file on server'), { target: { value: '   ' } });
  expect(button).toBeDisabled();
  fireEvent.change(await screen.findByLabelText('Export file on server'), { target: { value: '/exports/full.json' } });
  await userEvent.dblClick(await screen.findByRole('button', { name: 'Save to server' }));
  expect(screen.getByRole('button', { name: /^Sav/ })).toBeDisabled();
  expect(api.writeRunExport).toHaveBeenCalledTimes(1);
  await act(async () => first.reject('Export directory is read-only'));
  expect(await screen.findByText('Export directory is read-only')).toBeInTheDocument();
  await userEvent.dblClick(screen.getByRole('button', { name: 'Save to server' }));
  expect(api.writeRunExport).toHaveBeenCalledTimes(2);
  expect(screen.queryByText('Export directory is read-only')).not.toBeInTheDocument();
  await act(async () => retry.resolve());
  expect(screen.getByRole('status')).toHaveTextContent('/exports/full.json');
  expect(screen.getByRole('button', { name: 'Save to server' })).toBeEnabled();
});

test('an already-started server write keeps its captured run, format, and saved-path receipt', async () => {
  transport.serverMode = true;
  const pending = deferred<void>();
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('saved-source', 'source'), run('saved-image', 'image')]);
  vi.mocked(api.previewRunExport).mockResolvedValue(exportPreview);
  vi.spyOn(api, 'writeRunExport').mockReturnValueOnce(pending.promise);
  render(<ExportCenterPage />);
  fireEvent.change(await screen.findByLabelText('Export file on server'), { target: { value: '/exports/original.json' } });
  await userEvent.click(await screen.findByRole('button', { name: 'Save to server' }));
  expect(api.writeRunExport).toHaveBeenCalledExactlyOnceWith('saved-source', 'oxaudit-json', '/exports/original.json');
  await userEvent.selectOptions(screen.getByLabelText('Saved run'), 'saved-image');
  await userEvent.selectOptions(screen.getByLabelText('Format'), 'sarif');
  fireEvent.change(screen.getByLabelText('Export file on server'), { target: { value: '/exports/later.sarif' } });
  await act(async () => pending.resolve());

  expect(api.writeRunExport).toHaveBeenCalledExactlyOnceWith('saved-source', 'oxaudit-json', '/exports/original.json');
  expect(useToastStore.getState().toasts).toContainEqual(expect.objectContaining({
    kind: 'success', message: expect.stringContaining('/exports/original.json'),
  }));
  expect(useToastStore.getState().toasts).not.toContainEqual(expect.objectContaining({
    kind: 'success', message: expect.stringContaining('/exports/later.sarif'),
  }));
  expect(screen.getByLabelText('Saved run')).toHaveValue('saved-image');
  expect(screen.getByLabelText('Format')).toHaveValue('sarif');
});

test.each(['run', 'format', 'run A to B to A', 'format A to B to A', 'unmount'])(
  'a pending desktop save dialog cannot write after %s', async (change) => {
    const destination = deferred<string | null>();
    vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run('saved-source', 'source'), run('saved-image', 'image')]);
    vi.mocked(api.previewRunExport).mockResolvedValue(exportPreview);
    vi.spyOn(api, 'writeRunExport').mockResolvedValue(undefined);
    vi.mocked(save).mockReturnValue(destination.promise);
    const view = render(<ExportCenterPage />);
    const button = await screen.findByRole('button', { name: 'Save export…' });
    await userEvent.dblClick(button);
    expect(save).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: /^Sav/ })).toBeDisabled();

    if (change === 'unmount') view.unmount();
    else if (change.startsWith('run')) {
      await userEvent.selectOptions(screen.getByLabelText('Saved run'), 'saved-image');
      if (change.includes('A to B to A')) await userEvent.selectOptions(screen.getByLabelText('Saved run'), 'saved-source');
    } else {
      await userEvent.selectOptions(screen.getByLabelText('Format'), 'sarif');
      if (change.includes('A to B to A')) await userEvent.selectOptions(screen.getByLabelText('Format'), 'oxaudit-json');
    }
    await act(async () => destination.resolve('/exports/obsolete.json'));

    expect(api.writeRunExport).not.toHaveBeenCalled();
    expect(useToastStore.getState().toasts).not.toContainEqual(expect.objectContaining({ kind: 'success' }));
    if (change !== 'unmount') expect(await screen.findByRole('button', { name: 'Save export…' })).toBeEnabled();
  },
);
