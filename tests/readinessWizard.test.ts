import assert from "node:assert/strict";
import { test } from "node:test";
import {
  completeReadinessWizard,
  isReadinessWizardComplete,
  READINESS_WIZARD_STORAGE_KEY,
} from "../src/lib/readinessWizard";

test("first-launch readiness completion is versioned and persisted", () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  };

  assert.equal(isReadinessWizardComplete(storage), false);
  completeReadinessWizard(storage);
  assert.equal(values.get(READINESS_WIZARD_STORAGE_KEY), "true");
  assert.equal(isReadinessWizardComplete(storage), true);
});

test("restricted storage fails open without crashing first launch", () => {
  const storage = {
    getItem: () => {
      throw new Error("denied");
    },
    setItem: () => {
      throw new Error("denied");
    },
  };
  assert.equal(isReadinessWizardComplete(storage), false);
  assert.doesNotThrow(() => completeReadinessWizard(storage));
});
