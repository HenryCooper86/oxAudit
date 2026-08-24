// A string-literal union names allowed values. "secret" here is a category
// label, and the token after it is the next member of the union, not a value
// assigned to it.
export interface Finding {
  category: "secret" | "vulnerability";
  origin: "local" | "projectPolicy";
}

export type ResultsQuery = {
  category: "all" | "secret" | "vulnerability";
  scope: "all" | "production" | "development";
};
