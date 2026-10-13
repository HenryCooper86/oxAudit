import { create } from "zustand";
import type { VerificationRecord } from "../../lib/types";

interface VerificationWrites {
  pending: ReadonlySet<string>;
  receipts: ReadonlyMap<string, VerificationRecord>;
  begin(findingId: string): boolean;
  finish(findingId: string, record?: VerificationRecord): void;
  acknowledge(findingId: string, recordId: string): void;
}

/** Writes outlive a claim panel, including navigation away and back. */
export const useVerificationWrites = create<VerificationWrites>((set, get) => ({
  pending: new Set(),
  receipts: new Map(),
  begin: findingId => {
    if (get().pending.has(findingId)) return false;
    set(state => ({ pending: new Set([...state.pending, findingId]) }));
    return true;
  },
  finish: (findingId, record) => set(state => ({
    pending: new Set([...state.pending].filter(id => id !== findingId)),
    receipts: record ? new Map(state.receipts).set(findingId, record) : state.receipts,
  })),
  acknowledge: (findingId, recordId) => {
    if (get().receipts.get(findingId)?.id !== recordId) return;
    set(state => {
      const receipts = new Map(state.receipts);
      receipts.delete(findingId);
      return { receipts };
    });
  },
}));
