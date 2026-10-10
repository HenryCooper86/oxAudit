import { vi } from "vitest";
import type { CanonicalProjectionMetadata, CanonicalProjectionSection, ResultPageQuery, SourceFindingsQuery } from "../../src/lib/types";

/** Transport fixtures return bounded rows while the complete fixture remains available for explicit actions. */
export function canonicalMetadata<T>(value: T): CanonicalProjectionMetadata<T> {
  const projection = structuredClone(value) as Record<string, any>;
  const sections: Partial<Record<CanonicalProjectionSection, number>> = {};
  const base = projection.result ?? projection;
  for (const section of ["dependencies", "vulnerabilities", "components", "layers", "findings", "blobs"] as const) {
    const owner = section === "layers" || section === "blobs" || section === "findings" ? projection : base;
    if (Array.isArray(owner[section])) { sections[section] = owner[section].length; owner[section] = []; }
  }
  if (base.semanticAnalysis) { sections.semanticFindings = base.semanticAnalysis.findings.length; base.semanticAnalysis.findings = []; }
  if (projection.findingBlobIds) projection.findingBlobIds = {};
  return { kind: "pagedProjection", projectionKind: "fixture", projection: projection as T, sections };
}
export function canonicalPage(value: any, section: CanonicalProjectionSection, query: ResultPageQuery = {}) {
  const base = value.result ?? value;
  let items: any[] = section === "semanticFindings" ? base.semanticAnalysis?.findings ?? [] : value[section] ?? base[section] ?? [];
  const total = items.length;
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  if (query.minimumSeverity && query.minimumSeverity !== "all") items = items.filter(row => row.vulnerabilities.some((v: any) => rank[v.severity] <= rank[query.minimumSeverity!]));
  if (query.severity && query.severity !== "all") items = items.filter(row => row.severity === query.severity);
  if (query.search) items = items.filter(row => JSON.stringify(row).toLowerCase().includes(query.search!.toLowerCase()));
  if (query.sort === "severity") items = [...items].sort((a, b) => rank[a.severity] - rank[b.severity] || a.filePath.localeCompare(b.filePath) || a.line - b.line);
  const filteredTotal = items.length, offset = query.offset ?? 0, limit = query.limit ?? 50;
  items = items.slice(offset, offset + limit);
  const findingBlobIds = Object.fromEntries(items.filter(row => value.findingBlobIds?.[row.id]).map(row => [row.id, value.findingBlobIds[row.id]]));
  return { items, total, filteredTotal, offset, limit, related: { findingBlobIds, blobs: (value.blobs ?? []).filter((blob: any) => Object.values(findingBlobIds).includes(blob.oid)) } };
}
export function sourceMetadata(value: any) { const { findings: _findings, ...metadata } = value; return metadata; }
export function sourcePage(value: any, query: SourceFindingsQuery = {}) {
  const all = value.findings as any[];
  const view = (row: any) => row.diffStatus === "resolved" ? "resolved" : ["falsePositive", "acceptedRisk", "suppressed"].includes(row.review?.state) ? "closed" : row.review?.state === "confirmed" || ["production", "infrastructure", "unknown"].includes(row.scope ?? "unknown") ? "open" : "otherScopes";
  const views = { open: 0, otherScopes: 0, closed: 0, resolved: 0 }, diffs = { new: 0, unchanged: 0, resolved: 0, notEvaluated: 0 };
  for (const row of all) { views[view(row) as keyof typeof views]++; diffs[(row.diffStatus ?? "notEvaluated") as keyof typeof diffs]++; }
  let rows = all.filter(row => (!query.view || query.view === "all" || view(row) === query.view) && (!query.newOnly || row.diffStatus === "new") && (!query.category || query.category === "all" || row.category === query.category) && (!query.scope || query.scope === "all" || row.scope === query.scope) && (!query.language || query.language === "all" || row.language === query.language) && (!query.filePaths || (row.observationRunId === value.runId && query.filePaths.includes(row.filePath))));
  const page = canonicalPage({ findings: rows }, "findings", query);
  return { ...page, total: all.length, viewCounts: views, diffCounts: diffs, languages: [...new Set(all.map(row => row.language))].sort() };
}

// Existing complete receipts are fixture suppliers, never invoked as transport requests by these doubles.
export function installPagingFixtures(api: any) {
  const fixture = (name: string, id: string) => api[name].getMockImplementation()?.(id);
  vi.spyOn(api, "loadCanonicalProjectionMetadata").mockImplementation(async (id: any) => canonicalMetadata(await fixture("loadCanonicalProjection", id)));
  vi.spyOn(api, "loadCanonicalProjectionPage").mockImplementation(async (id: any, section: any, query: any) => canonicalPage(await fixture("loadCanonicalProjection", id), section, query));
  vi.spyOn(api, "loadSourceRunMetadata").mockImplementation(async (id: any) => sourceMetadata(await fixture("loadSourceRun", id)));
  vi.spyOn(api, "loadSourceRunPage").mockImplementation(async (id: any, query: any) => sourcePage(await fixture("loadSourceRun", id), query));
}
