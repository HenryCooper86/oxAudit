import { installPagingFixtures } from "../../tests/fixtures/pagedResults";
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, test, vi } from 'vitest';
import { api } from '../lib/api';
import { useAppStore } from '../lib/stores';
import { acquireScan, reconcileBackendWork, releaseScan, useScanWorkStore } from '../features/project-home/coordinator';
import { BinaryScanPage } from './BinaryScan';
import type { BinaryScanResult, BinaryScannersStatus } from '../lib/types';
const handlers = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock('../lib/events', () => ({ listen: async (name: string, callback: (event: { payload: unknown }) => void) => { handlers.set(name, callback); return () => handlers.delete(name); } }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
const tools: BinaryScannersStatus = {
  native: { available: true, program: 'native', version: null, source: null, message: 'built in' },
  cveBinTool: { available: false, program: null, version: null, source: null, message: null },
  grype: { available: false, program: null, version: null, source: null, message: null },
  docker: { available: false, program: null, version: null, source: null, message: null }, runtime: 'auto', canScan: true,
};
const result: BinaryScanResult = { target: '/project', components: [], summary: { components: 0, vulnerabilities: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, databaseLastUpdated: null, durationMs: 1, scanners: ['native'] };
beforeEach(() => {
  installPagingFixtures(api);
  vi.clearAllMocks(); handlers.clear();
  useAppStore.setState({ activeProject: '/project', pageStatus: {} });
  useScanWorkStore.setState({ active: null, check: null, backend: { active: null, recent: [] }, lastTargets: {}, recoveryError: null });
  vi.spyOn(api, 'binaryToolStatus').mockResolvedValue(tools);
  vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([]);
  vi.spyOn(api, 'scanWorkStatus').mockResolvedValue({ active: null, recent: [] });
  vi.spyOn(api, 'cancelScanWork').mockResolvedValue(true);
});

test('binary launch and progress belong to the same operation and scoped cancellation suppresses a delayed clean reply', async () => {
  let finish!: (value: BinaryScanResult) => void;
  const scan = vi.spyOn(api, 'scanBinaries').mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  render(<BinaryScanPage />);
  fireEvent.click(await screen.findByRole('button', { name: 'Run scan' }));
  await waitFor(() => expect(scan).toHaveBeenCalled());
  const operationId = useScanWorkStore.getState().active!.operationId;
  expect(scan).toHaveBeenCalledWith(expect.objectContaining({ path: '/project' }), false, operationId);
  await act(async () => handlers.get('binscan://progress')?.({ payload: { operationId: 'old-operation', message: 'old progress' } }));
  expect(screen.queryByText('old progress')).not.toBeInTheDocument();
  await act(async () => handlers.get('binscan://progress')?.({ payload: { operationId, message: 'Current scanner progress' } }));
  expect(screen.getAllByText('Current scanner progress').length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  await waitFor(() => expect(api.cancelScanWork).toHaveBeenCalledWith(operationId));
  await act(async () => finish(result));
  expect(useAppStore.getState().pageStatus['binary-scan']?.label).toMatch(/cancelled/i);
  expect(screen.queryByText('0 components · 0 CVEs')).not.toBeInTheDocument();
});

test('global recovered ownership blocks another binary launch', async () => {
  const id = acquireScan('image', 'registry/app', 'Scanning image')!;
  const scan = vi.spyOn(api, 'scanBinaries');
  render(<BinaryScanPage />);
  expect(await screen.findByRole('button', { name: 'Run scan' })).toBeDisabled();
  expect(scan).not.toHaveBeenCalled();
  await act(async () => releaseScan(id));
  expect(screen.getByRole('button', { name: 'Run scan' })).toBeEnabled();
});

test('binary target selection has explicit file and folder controls and unknown progress does not name an unused scanner', async () => {
  const scan = vi.spyOn(api, 'scanBinaries').mockReturnValue(new Promise(() => {}));
  render(<BinaryScanPage />);
  fireEvent.change(await screen.findByLabelText('Binary scan target'), { target: { value: '/candidate.bin' } });
  fireEvent.keyDown(screen.getByLabelText('Binary scan target'), { key: 'Enter' });
  expect(scan).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Choose file…' })).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Choose folder…' })).toBeEnabled();
  fireEvent.click(await screen.findByRole('button', { name: 'Run scan' }));
  const progress = await screen.findByRole('region', { name: 'Scan progress' });
  expect(progress).toHaveTextContent(/waiting for.*progress/i);
  expect(screen.queryByText('cve-bin-tool is running')).not.toBeInTheDocument();
});

test('binary recovery reloads a saved run after terminal work arrives', async () => {
  const scan = vi.spyOn(api, 'scanBinaries');
  render(<BinaryScanPage />);
  await screen.findByRole('button', { name: 'Run scan' });
  const restored = { ...result, summary: { ...result.summary, components: 29 } };
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([{ id: 'saved-binary', kind: 'binary', targetLabel: '/project', state: 'completed', attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  vi.spyOn(api, 'loadCanonicalProjection').mockResolvedValue(restored);
  await act(async () => reconcileBackendWork({ active: null, recent: [{ operationId: 'external', kind: 'binary', target: '/project', status: 'completed', runId: 'saved-binary', startedAtMs: 1, updatedAtMs: 2 }] }));
  expect(await screen.findByText('29 components · 0 CVEs')).toBeInTheDocument();
  expect(scan).not.toHaveBeenCalled();
});

test('binary reloads the saved A receipt after completing A, editing B, and returning to A without a backend revision', async () => {
  const saved = { ...result, target: '/project-a', summary: { ...result.summary, components: 29 } };
  useAppStore.setState({ activeProject: '/project-a' });
  const scan = vi.spyOn(api, 'scanBinaries').mockResolvedValue(saved);
  vi.spyOn(api, 'loadCanonicalProjection').mockResolvedValue(saved);
  render(<BinaryScanPage />);
  fireEvent.click(await screen.findByRole('button', { name: 'Run scan' }));
  expect(await screen.findByText('29 components · 0 CVEs')).toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole('button', { name: 'Run scan' })).toBeEnabled());
  const revision = useScanWorkStore.getState().recoveryRevision;
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([{ id: 'saved-binary-a', kind: 'binary', targetLabel: '/project-a', state: 'completed', attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [] }]);
  fireEvent.change(screen.getByLabelText('Binary scan target'), { target: { value: '/project-b' } });
  await waitFor(() => expect(screen.getByLabelText('Binary scan target')).toHaveValue('/project-b'));
  expect(screen.queryByText('29 components · 0 CVEs')).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Binary scan target'), { target: { value: '/project-a' } });
  expect(await screen.findByText('29 components · 0 CVEs')).toBeInTheDocument();
  expect(api.loadCanonicalProjectionMetadata).toHaveBeenCalledWith('saved-binary-a');
  expect(scan).toHaveBeenCalledTimes(1);
  expect(useScanWorkStore.getState().recoveryRevision).toBe(revision);
});
