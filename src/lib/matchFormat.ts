/** Bytes of a hex string; an odd or non-hex tail is ignored rather than guessed. */
export function hexBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let index = 0; index + 1 < hex.length; index += 2) {
    const value = Number.parseInt(hex.slice(index, index + 2), 16);
    if (Number.isNaN(value) || !/^[0-9a-f]{2}$/i.test(hex.slice(index, index + 2))) break;
    bytes.push(value);
  }
  return bytes;
}

/** `de ad be ef` */
export function spacedHex(hex: string): string {
  return hexBytes(hex).map(byte => byte.toString(16).padStart(2, "0")).join(" ");
}

/** Printable ASCII as is, every other byte as a dot. Always plain text. */
export function printableAscii(hex: string): string {
  return hexBytes(hex).map(byte => byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".").join("");
}

/** `0x1f40 (8000)` */
export function offsetLabel(offset: number): string {
  return `0x${offset.toString(16)} (${offset.toLocaleString("en-US")})`;
}
