import { expect, test } from "vitest";
import { remediationFor } from "./remediation";
test("shipped evaluation rules constrain JSON parsing to data input", () => {
  for (const rule of ["js-eval", "js-function-ctor"]) {
    const example = remediationFor(rule, "vulnerability");
    expect(example?.constraint).toMatch(/JSON data/);
    expect(example?.after).toContain("JSON.parse");
  }
});
test("execution and SQL examples preserve the important input boundary", () => {
  for (const rule of ["js-child-process", "js-exec-concat", "py-subprocess-shell", "py-os-system"]) expect(remediationFor(rule, "vulnerability")?.constraint).toMatch(/allowlist/);
  for (const rule of ["js-sql-concat", "py-sql-fstring", "py-sql-concat"]) expect(remediationFor(rule, "vulnerability")?.constraint).toMatch(/identifiers/);
  expect(remediationFor("unsupported", "vulnerability")).toBeUndefined();
});
test("secret example is generic rotation guidance, independent of detected content", () => {
  const example = remediationFor("generic-api-key", "secret");
  expect(example?.verify.join(" ")).toMatch(/Revoke/);
  expect(example?.after).toMatch(/process.env/);
});
