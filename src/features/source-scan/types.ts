import type { FindingScope, Severity } from "../../lib/types";

export type ResultView = "open" | "otherScopes" | "closed" | "resolved";

export type FindingsSort = "severity" | "file" | "rule";

export interface ResultsQuery {
  view: ResultView;
  newOnly?: boolean;
  category: "all" | "secret" | "vulnerability";
  severity: "all" | Severity;
  scope: "all" | FindingScope;
  language: "all" | string;
  search: string;
  sort: FindingsSort;
}

export type ViewCounts = Record<ResultView, number>;
