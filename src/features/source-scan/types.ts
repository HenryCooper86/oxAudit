import type { FindingScope, Severity } from "../../lib/types";

export type ResultView = "open" | "otherScopes" | "closed" | "resolved";

export interface ResultsQuery {
  view: ResultView;
  category: "all" | "secret" | "vulnerability";
  severity: "all" | Severity;
  scope: "all" | FindingScope;
  language: "all" | string;
  search: string;
}

export type ViewCounts = Record<ResultView, number>;
