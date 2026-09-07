// Inert scan fixture. Do not import or execute this file.
// Contract: input is JSON data supplied by a caller.
export function parsePayload(input) {
  const value = JSON.parse(input);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Expected a JSON object");
  }
  return value;
}
