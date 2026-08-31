import assert from "node:assert/strict";
import test from "node:test";

import {
  missingSigningEnvironment,
  requiredSigningEnvironment,
} from "../tools/require-release-signing.mjs";

test("Linux releases do not require native signing secrets", () => {
  assert.deepEqual(requiredSigningEnvironment("Linux"), []);
  assert.deepEqual(missingSigningEnvironment("Linux", {}), []);
});

test("macOS releases require the complete signing and notarization set", () => {
  const required = [
    "APPLE_CERTIFICATE",
    "APPLE_CERTIFICATE_PASSWORD",
    "APPLE_SIGNING_IDENTITY",
    "APPLE_ID",
    "APPLE_PASSWORD",
    "APPLE_TEAM_ID",
  ];
  assert.deepEqual(requiredSigningEnvironment("macOS"), required);
  assert.deepEqual(missingSigningEnvironment("macOS", {}), required);

  const environment = Object.fromEntries(required.map((name) => [name, "configured"]));
  assert.deepEqual(missingSigningEnvironment("macOS", environment), []);
});

test("Windows releases require the certificate and its password", () => {
  const required = ["WINDOWS_CERTIFICATE", "WINDOWS_CERTIFICATE_PASSWORD"];
  assert.deepEqual(requiredSigningEnvironment("Windows"), required);
  assert.deepEqual(missingSigningEnvironment("Windows", {}), required);
  assert.deepEqual(
    missingSigningEnvironment("Windows", { WINDOWS_CERTIFICATE: "configured" }),
    ["WINDOWS_CERTIFICATE_PASSWORD"],
  );
});

test("blank signing values are treated as missing", () => {
  assert.deepEqual(
    missingSigningEnvironment("Windows", {
      WINDOWS_CERTIFICATE: "   ",
      WINDOWS_CERTIFICATE_PASSWORD: "configured",
    }),
    ["WINDOWS_CERTIFICATE"],
  );
});
