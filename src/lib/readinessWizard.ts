export const READINESS_WIZARD_STORAGE_KEY =
  "oxaudit.readinessWizard.completed.v1";
export const READINESS_WIZARD_OPEN_EVENT = "oxaudit:open-readiness-wizard";

export function isReadinessWizardComplete(storage: Pick<Storage, "getItem">): boolean {
  try {
    return storage.getItem(READINESS_WIZARD_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

export function completeReadinessWizard(
  storage: Pick<Storage, "setItem">,
): void {
  try {
    storage.setItem(READINESS_WIZARD_STORAGE_KEY, "true");
  } catch {
    // Storage can be unavailable in hardened WebViews; the wizard still closes.
  }
}

export function requestReadinessWizard(): void {
  window.dispatchEvent(new Event(READINESS_WIZARD_OPEN_EVENT));
}
