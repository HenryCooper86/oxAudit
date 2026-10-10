/** Native events are runtime input, even when the TypeScript listener has a type. */
export function phaseProgress(payload: unknown, allowed: readonly string[]) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const row = payload as Record<string, unknown>;
  if (typeof row.phase !== "string" || !allowed.includes(row.phase)
    || (row.operationId !== undefined && typeof row.operationId !== "string")
    || (row.file !== undefined && typeof row.file !== "string")) return null;
  const counters = Number.isSafeInteger(row.done) && Number.isSafeInteger(row.total)
    && Number(row.done) >= 0 && Number(row.total) > 0 && Number(row.done) <= Number(row.total);
  return { operationId: row.operationId as string | undefined, phase: row.phase,
    ...(counters ? { done: Number(row.done), total: Number(row.total) } : {}),
    ...(typeof row.file === "string" ? { file: row.file } : {}) };
}
export function progressMessage(payload: unknown) {
  if (typeof payload === "string") return { operationId: undefined, message: payload };
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const row = payload as Record<string, unknown>;
  const message = typeof row.message === "string" ? row.message : row.line;
  return typeof row.operationId === "string" && typeof message === "string" ? { operationId: row.operationId, message } : null;
}
