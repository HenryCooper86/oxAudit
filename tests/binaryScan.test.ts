import assert from "node:assert/strict";
import test from "node:test";
import {
  filterComponents,
  highestSeverity,
  severityRank,
} from "../src/lib/binaryScan";
import type { BinaryComponent } from "../src/lib/types";

function component(product: string, severities: string[]): BinaryComponent {
  return {
    vendor: "v",
    product,
    version: "1.0",
    paths: [`/fw/lib/${product}.so`],
    vulnerabilities: severities.map((severity, index) => ({
      cveId: `CVE-2020-${index}${product.length}`,
      severity,
      score: null,
      cvssVersion: null,
      cvssVector: null,
      source: "NVD",
      remarks: null,
      epssProbability: null,
    })),
  };
}

const components = [
  component("openssl", ["critical", "high", "medium"]),
  component("zlib", ["high", "medium"]),
  component("curl", ["low"]),
  component("expat", []),
];

test("a component's badge reflects its worst CVE", () => {
  assert.equal(highestSeverity(components[0]), "critical");
  assert.equal(highestSeverity(components[1]), "high");
  assert.equal(highestSeverity(components[2]), "low");
});

test("a component with no CVEs reads as unknown rather than borrowing a rank", () => {
  assert.equal(highestSeverity(components[3]), "unknown");
});

test("an unrecognized severity does not outrank a real one", () => {
  const odd = component("odd", ["banana", "medium"]);
  assert.equal(highestSeverity(odd), "medium");
  assert.equal(severityRank("banana"), 0);
});

test("the filter is a floor, keeping everything at or above it", () => {
  const high = filterComponents(components, "high").map((c) => c.product);
  assert.deepEqual(high, ["openssl", "zlib"]);

  const critical = filterComponents(components, "critical").map((c) => c.product);
  assert.deepEqual(critical, ["openssl"]);
});

test("the floor is applied per CVE, so any qualifying finding keeps the component", () => {
  // zlib's worst is high; filtering at medium must still include it rather than
  // testing only the component's top severity.
  const medium = filterComponents(components, "medium").map((c) => c.product);
  assert.deepEqual(medium, ["openssl", "zlib"]);

  const low = filterComponents(components, "low").map((c) => c.product);
  assert.deepEqual(low, ["openssl", "zlib", "curl"]);
});

test("filtering to all keeps every component, including ones with no CVEs", () => {
  const all = filterComponents(components, "all").map((c) => c.product);
  assert.deepEqual(all, ["openssl", "zlib", "curl", "expat"]);
});

test("filtering returns a copy rather than the caller's array", () => {
  const all = filterComponents(components, "all");
  all.pop();
  assert.equal(components.length, 4, "the source list must not be mutated");
});
