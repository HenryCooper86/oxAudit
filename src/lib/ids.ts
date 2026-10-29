/**
 * Random identifiers that work outside secure contexts.
 *
 * `crypto.randomUUID` only exists in secure contexts (https, localhost, the
 * Tauri webview). The headless server is often reached over plain
 * http://<lan-ip>, where it is undefined, so fall back to a v4 UUID built
 * from `crypto.getRandomValues`, which is available everywhere.
 */
export function newId(): string {
  const c = globalThis.crypto;
  if (typeof c?.randomUUID === "function") return c.randomUUID();
  const bytes = new Uint8Array(16);
  c.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
