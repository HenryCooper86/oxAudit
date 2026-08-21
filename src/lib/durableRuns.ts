import type { CanonicalRun, CanonicalRunKind } from "./types";

export function normalizedTarget(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  return normalized.length > 1 ? normalized.replace(/\/+$/, "") : normalized;
}

export function latestCompletedRun(
  runs: CanonicalRun[],
  kind: CanonicalRunKind,
  target: string,
): CanonicalRun | null {
  const expected = normalizedTarget(target);
  return (
    runs
      .filter(
        (run) =>
          run.kind === kind &&
          run.state === "completed" &&
          normalizedTarget(run.targetLabel) === expected,
      )
      .sort(
        (left, right) =>
          right.updatedAtMs - left.updatedAtMs || right.id.localeCompare(left.id),
      )[0] ?? null
  );
}
