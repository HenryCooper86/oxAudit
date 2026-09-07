import type { CommandError, ErrorCode } from "./types";

const ERROR_CODES = new Set<ErrorCode>([
  "baselineIncompatible",
  "invalidTarget",
  "scanCancelled",
  "scanFailed",
  "scanAlreadyRunning",
  "persistenceUnavailable",
  "policyInvalid",
  "policyWriteFailed",
  "reviewInvalid",
  "notFound",
  "credentialUnavailable",
  "credentialRollbackFailed",
  "migrationFailed",
  "dataOperationFailed",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function safeMessage(value: unknown): string {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (value instanceof Error && value.message.trim()) return value.message.trim();
  if (isRecord(value) && typeof value.message === "string" && value.message.trim()) {
    return value.message.trim();
  }
  return "The scan could not be completed.";
}

export function normalizeCommandError(value: unknown): CommandError {
  if (
    isRecord(value) &&
    typeof value.code === "string" &&
    ERROR_CODES.has(value.code as ErrorCode) &&
    typeof value.message === "string" &&
    typeof value.retryable === "boolean"
  ) {
    return {
      code: value.code as ErrorCode,
      message: value.message.trim() || "The operation could not be completed.",
      detail: typeof value.detail === "string" ? value.detail : null,
      retryable: value.retryable,
    };
  }

  return {
    code: "scanFailed",
    message: safeMessage(value),
    detail: null,
    retryable: true,
  };
}
