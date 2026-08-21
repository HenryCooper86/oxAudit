export interface SearchSegment {
  text: string;
  match: boolean;
}

export function normalizeSearchQuery(value: string): string {
  return value.trim();
}

export function splitSearchMatches(text: string, rawQuery: string): SearchSegment[] {
  const query = normalizeSearchQuery(rawQuery);
  if (!query) return [{ text, match: false }];

  const lowerText = text.toLocaleLowerCase();
  const lowerQuery = query.toLocaleLowerCase();
  const segments: SearchSegment[] = [];
  let cursor = 0;

  while (cursor < text.length) {
    const index = lowerText.indexOf(lowerQuery, cursor);
    if (index < 0) break;
    if (index > cursor) {
      segments.push({ text: text.slice(cursor, index), match: false });
    }
    segments.push({
      text: text.slice(index, index + query.length),
      match: true,
    });
    cursor = index + query.length;
  }

  if (cursor < text.length) {
    segments.push({ text: text.slice(cursor), match: false });
  }
  return segments.length > 0 ? segments : [{ text, match: false }];
}

export function nextSearchIndex(
  current: number,
  total: number,
  direction: 1 | -1,
): number {
  if (total <= 0) return 0;
  return (current + direction + total) % total;
}
