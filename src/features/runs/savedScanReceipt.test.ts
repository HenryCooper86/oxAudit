import { beforeEach, expect, test, vi } from 'vitest';
import { api } from '../../lib/api';
import type { CanonicalRun } from '../../lib/types';
import { readSavedScanReceipt } from './savedScanReceipt';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
const run: CanonicalRun = { id: 'failed-image', kind: 'image', targetLabel: 'registry/app', state: 'failed', attempt: 1, createdAtMs: 1, updatedAtMs: 2, engineIds: [], rulePackIds: [], providerSnapshotIds: [], warnings: [{ code: 'imagePull', message: 'Image pull failed' }] };
beforeEach(() => { vi.spyOn(api, 'listCanonicalRuns').mockResolvedValue([run]); });
test('a failed attempt without a display projection still reports its canonical identity and failure', async () => {
  vi.spyOn(api, 'loadCanonicalProjection').mockRejectedValue(new Error('Projection unavailable'));
  const saved = await readSavedScanReceipt('image', 'registry/app');
  expect(saved.attempt).toMatchObject({ id: 'failed-image', state: 'failed' });
  expect(saved.data).toBeNull();
  expect(saved.loadError).toMatch(/Projection unavailable/);
});
test('projection state cannot supersede an authoritative incomplete receipt', async () => {
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([{ ...run, state: 'incomplete' }]);
  vi.spyOn(api, 'loadCanonicalProjection').mockResolvedValue({ runId: 'failed-image', state: 'completed' });
  expect((await readSavedScanReceipt('image', 'registry/app')).data).toMatchObject({ runId: 'failed-image', state: 'incomplete' });
});
test('a projection for the wrong run remains unavailable rather than being shown as the selected receipt', async () => {
  vi.mocked(api.listCanonicalRuns).mockResolvedValue([{ ...run, state: 'completed' }]);
  vi.spyOn(api, 'loadCanonicalProjection').mockResolvedValue({ runId: 'unrelated-image' });
  const saved = await readSavedScanReceipt('image', 'registry/app');
  expect(saved.data).toBeNull();
  expect(saved.loadError).toMatch(/different run/);
});
