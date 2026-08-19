import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { SeverityBadge } from "../src/components/SeverityBadge";

test("missing dependency severity renders UNKNOWN with neutral accessible styling", () => {
  const markup = renderToStaticMarkup(
    createElement(SeverityBadge, { severity: null }),
  );

  assert.match(markup, />unknown</i);
  assert.doesNotMatch(markup, />info</i);
  assert.match(markup, /text-sev-unknown\b/);
});

test("known dependency severity retains its compact label", () => {
  const markup = renderToStaticMarkup(
    createElement(SeverityBadge, { severity: "high" }),
  );

  assert.match(markup, />high</i);
  assert.match(markup, /text-sev-high\b/);
});
