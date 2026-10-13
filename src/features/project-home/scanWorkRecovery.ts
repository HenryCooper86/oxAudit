import { useEffect } from "react";
import { listen } from "../../lib/events";
import { invalidateWorkStatusRequests, reconcileBackendWork, refreshScanWork, useScanWorkStore } from "./coordinator";

/** App-level subscriptions keep backend ownership alive across page navigation. */
export function useScanWorkRecovery(enabled = true): void {
  useEffect(() => {
    if (!enabled) return;
    let disposed = false;
    let subscriptionError: string | null = null;
    let refreshSequence = 0;
    let pendingRefresh: number | null = null;
    const stops: Array<() => void> = [];
    const refresh = async (forceRevision = false) => {
      // Polls must let slow responses settle. Otherwise each timer tick makes
      // the previous request stale forever. Reconnect/lag still take priority.
      if (!forceRevision && pendingRefresh !== null) return;
      const request = ++refreshSequence;
      pendingRefresh = request;
      try {
        await refreshScanWork(forceRevision);
        if (!disposed && subscriptionError) useScanWorkStore.setState({ recoveryError: subscriptionError });
      } finally {
        if (pendingRefresh === request) pendingRefresh = null;
      }
    };
    const subscribe = async (name: string, callback: (event: { payload: unknown }) => void) => {
      try {
        const stop = await listen(name, event => { if (!disposed) callback(event); });
        if (disposed) stop();
        else stops.push(stop);
      } catch (error) {
        subscriptionError = `Scan work updates unavailable: ${String(error)}`;
        if (!disposed) useScanWorkStore.setState({ recoveryError: subscriptionError });
      }
    };
    void Promise.all([
      subscribe("work://changed", event => reconcileBackendWork(event.payload)),
      subscribe("transport://reconnected", () => { void refresh(true); }),
      subscribe("transport://lagged", () => { void refresh(true); }),
    ]).then(() => { if (!disposed) void refresh(true); });
    // Poll active work as a fallback for lost terminal events or older peers
    // whose cancellation path does not publish an update.
    const timer = setInterval(() => {
      const state = useScanWorkStore.getState();
      if (state.active || state.recoveryError || subscriptionError) void refresh();
    }, 2_000);
    return () => { disposed = true; invalidateWorkStatusRequests(); clearInterval(timer); stops.forEach(stop => stop()); };
  }, [enabled]);
}
