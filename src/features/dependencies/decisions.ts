import type { DependencyPath, Vulnerability } from '../../lib/types';

export type UpgradeGroup = {
  key: string;
  advisories: Vulnerability[];
  paths: DependencyPath[];
  candidate: string | null;
  classification: string;
  command: string | null;
  checklist: string;
};

/** Numeric comparison result; `null` means the comparator refused to guess. */
export type VersionOrdering = -1 | 0 | 1;

/**
 * Comparator families mirroring src-tauri/src/advisories/versioning.rs —
 * one per ecosystem version specification, each lenient about the spellings
 * real lockfiles contain. A comparator returns `null` when it refuses to
 * guess (unparseable version, unknown Maven qualifier); callers treat `null`
 * as undetermined and never silently drop the advisory.
 */
export type VersionFamily = 'semver' | 'pep440' | 'debian' | 'maven' | 'gem' | 'loose';

/**
 * Pick the comparator for an ecosystem's native (OSV `ECOSYSTEM`) versions.
 * Mirrors `versioning::family_for`; `null` when matching would be a guess.
 * Distro ecosystems (Debian:*, Ubuntu:*, Alpine:*) use the epoch-based
 * Debian policy comparator.
 */
export function versionFamilyForEcosystem(ecosystem: string): VersionFamily | null {
  switch (ecosystem) {
    case 'PyPI': return 'pep440';
    case 'Maven': return 'maven';
    case 'RubyGems': return 'gem';
    case 'npm': case 'crates.io': case 'Go': return 'semver';
    case 'Packagist': case 'NuGet': return 'loose';
    default:
      return /^(?:Debian|Ubuntu|Alpine):/.test(ecosystem) ? 'debian' : null;
  }
}

export function compareVersions(family: VersionFamily, a: string, b: string): VersionOrdering | null {
  switch (family) {
    case 'semver': return compareSemver(a, b);
    case 'pep440': return comparePep440(a, b);
    case 'debian': return compareDebian(a, b);
    case 'maven': return compareMaven(a, b);
    case 'gem': return compareGem(a, b);
    case 'loose': return compareLoose(a, b);
  }
}

const cmpNum = (x: number, y: number): VersionOrdering => x < y ? -1 : x > y ? 1 : 0;
const cmpStr = (x: string, y: string): VersionOrdering => x < y ? -1 : x > y ? 1 : 0;

/** Mirror Rust's `str::parse::<u64>`: ASCII digits only, no sign, bounded. */
function parseU64(raw: string): number | null {
  if (!/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

// --- semver.org ordering, lenient about leading v, missing segments, build metadata ---

type SemverPreIdent = { kind: 'num'; value: number } | { kind: 'alpha'; value: string };
type SemverVersion = { major: number; minor: number; patch: number; pre: SemverPreIdent[] };

function parseSemver(raw: string): SemverVersion | null {
  const s = raw.trim().replace(/^[vV=]+/, '');
  const withoutBuild = s.split('+')[0];
  const dash = withoutBuild.indexOf('-');
  const core = dash === -1 ? withoutBuild : withoutBuild.slice(0, dash);
  const preRaw = dash === -1 ? '' : withoutBuild.slice(dash + 1);
  const numbers = core.split('.');
  if (numbers.length > 3) return null;
  const major = parseU64(numbers[0] ?? '');
  if (major === null) return null;
  const minor = numbers.length > 1 ? parseU64(numbers[1]) : 0;
  if (minor === null) return null;
  const patch = numbers.length > 2 ? parseU64(numbers[2]) : 0;
  if (patch === null) return null;
  const pre: SemverPreIdent[] = [];
  if (preRaw !== '') {
    for (const ident of preRaw.split('.')) {
      if (ident === '') return null;
      const numeric = parseU64(ident);
      if (numeric !== null) pre.push({ kind: 'num', value: numeric });
      else if (/^[A-Za-z0-9-]+$/.test(ident)) pre.push({ kind: 'alpha', value: ident });
      else return null;
    }
  }
  return { major, minor, patch, pre };
}

function compareSemver(a: string, b: string): VersionOrdering | null {
  const pa = parseSemver(a), pb = parseSemver(b);
  if (!pa || !pb) return null;
  const release = cmpNum(pa.major, pb.major) || cmpNum(pa.minor, pb.minor) || cmpNum(pa.patch, pb.patch);
  if (release !== 0) return release;
  // A release outranks any of its own prereleases.
  if (!pa.pre.length || !pb.pre.length) return pa.pre.length === pb.pre.length ? 0 : pa.pre.length ? -1 : 1;
  for (let index = 0; index < Math.min(pa.pre.length, pb.pre.length); index++) {
    const x = pa.pre[index], y = pb.pre[index];
    // Numeric identifiers always have lower precedence.
    const order = x.kind === 'num' && y.kind === 'num' ? cmpNum(x.value, y.value)
      : x.kind === 'alpha' && y.kind === 'alpha' ? cmpStr(x.value, y.value)
      : x.kind === 'num' ? -1 : 1;
    if (order !== 0) return order;
  }
  return cmpNum(pa.pre.length, pb.pre.length);
}

// --- PEP 440 ordering: epochs, trailing zeros insignificant, dev < pre < release < post, locals ---

type Pep440Marker = { kind: 'pre'; phase: number } | { kind: 'post' } | { kind: 'dev' };
type Pep440Version = {
  epoch: number;
  release: number[];
  pre: [number, number] | null;
  post: number | null;
  dev: number | null;
  local: Array<{ kind: 'num'; value: number } | { kind: 'text'; value: string }>;
};

/** Longest-first so `rc` is never read as the post marker `r`. */
const PEP440_MARKERS: Array<[string, Pep440Marker]> = [
  ['preview', { kind: 'pre', phase: 2 }],
  ['alpha', { kind: 'pre', phase: 0 }],
  ['beta', { kind: 'pre', phase: 1 }],
  ['post', { kind: 'post' }],
  ['pre', { kind: 'pre', phase: 2 }],
  ['rev', { kind: 'post' }],
  ['dev', { kind: 'dev' }],
  ['rc', { kind: 'pre', phase: 2 }],
  ['a', { kind: 'pre', phase: 0 }],
  ['b', { kind: 'pre', phase: 1 }],
  ['c', { kind: 'pre', phase: 2 }],
  ['r', { kind: 'post' }],
];
const PEP440_SEPARATORS = ['.', '-', '_'];

function parsePep440(raw: string): Pep440Version | null {
  let s = raw.trim().replace(/^[vV]+/, '').toLowerCase();
  let localRaw = '';
  const plus = s.indexOf('+');
  if (plus !== -1) { localRaw = s.slice(plus + 1); s = s.slice(0, plus); }
  let epoch = 0;
  const bang = s.indexOf('!');
  if (bang !== -1) {
    const parsed = parseU64(s.slice(0, bang));
    if (parsed === null) return null;
    epoch = parsed;
    s = s.slice(bang + 1);
  }
  // Release digits run until the first marker; one separator directly before
  // a marker belongs to the marker, never to the release.
  let releaseEnd = s.length;
  for (let index = 0; index < s.length; index++) {
    const c = s[index];
    if (!(c >= '0' && c <= '9') && c !== '.') { releaseEnd = index; break; }
  }
  let releasePart = s.slice(0, releaseEnd);
  for (const separator of PEP440_SEPARATORS) {
    if (releasePart.endsWith(separator)) { releasePart = releasePart.slice(0, -1); break; }
  }
  const release: number[] = [];
  for (const segment of releasePart.split('.')) {
    const parsed = parseU64(segment);
    if (parsed === null) return null;
    release.push(parsed);
  }
  let pre: [number, number] | null = null;
  let post: number | null = null;
  let dev: number | null = null;
  let tail = s.slice(releaseEnd);
  while (tail.length) {
    // One optional separator may sit directly before a marker.
    let candidate = tail;
    for (const separator of PEP440_SEPARATORS) {
      if (candidate.startsWith(separator)) { candidate = candidate.slice(separator.length); break; }
    }
    let matched = false;
    for (const [marker, kind] of PEP440_MARKERS) {
      if (!candidate.startsWith(marker)) continue;
      const after = candidate.slice(marker.length);
      const digits = /^\d*/.exec(after)![0];
      const parsed = digits === '' ? 0 : parseU64(digits);
      if (parsed === null) return null;
      // A version carrying the same marker twice is not a spelling PEP 440 normalizes.
      if (kind.kind === 'pre' && pre === null) pre = [kind.phase, parsed];
      else if (kind.kind === 'post' && post === null) post = parsed;
      else if (kind.kind === 'dev' && dev === null) dev = parsed;
      else return null;
      tail = after.slice(digits.length);
      matched = true;
      break;
    }
    if (!matched) return null;
  }
  const local: Pep440Version['local'] = [];
  if (localRaw !== '') {
    for (const segment of localRaw.split('.')) {
      const parsed = parseU64(segment);
      if (parsed !== null) local.push({ kind: 'num', value: parsed });
      else if (/^[A-Za-z0-9]*$/.test(segment)) local.push({ kind: 'text', value: segment });
      else return null;
    }
  }
  return { epoch, release, pre, post, dev, local };
}

/** PEP 440: trailing zero release segments are insignificant. */
function trimmedRelease(release: number[]): number[] {
  let end = release.length;
  while (end > 0 && release[end - 1] === 0) end--;
  return release.slice(0, end);
}

function compareNumArrays(a: number[], b: number[]): VersionOrdering {
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return cmpNum(a[index], b[index]);
  }
  return cmpNum(a.length, b.length);
}

function comparePep440(a: string, b: string): VersionOrdering | null {
  const pa = parsePep440(a), pb = parsePep440(b);
  if (!pa || !pb) return null;
  const order = cmpNum(pa.epoch, pb.epoch) || compareNumArrays(trimmedRelease(pa.release), trimmedRelease(pb.release));
  if (order !== 0) return order;
  // A dev-only version (no pre, no post) sorts before pre-releases; a bare
  // release sorts after them; no post sorts before any post; a dev release
  // sorts below the same version without one.
  const preKey = (v: Pep440Version): [number, number, number] =>
    v.pre ? [0, v.pre[0], v.pre[1]] : v.post === null && v.dev !== null ? [-1, 0, 0] : [1, 0, 0];
  const postKey = (v: Pep440Version): [number, number] => v.post === null ? [-1, 0] : [0, v.post];
  const devKey = (v: Pep440Version): [number, number] => v.dev === null ? [1, 0] : [0, v.dev];
  const keys = compareNumArrays(preKey(pa), preKey(pb)) || compareNumArrays(postKey(pa), postKey(pb)) || compareNumArrays(devKey(pa), devKey(pb));
  if (keys !== 0) return keys;
  // A local version sorts above the bare release.
  if (!pa.local.length || !pb.local.length) return pa.local.length === pb.local.length ? 0 : pa.local.length ? 1 : -1;
  for (let index = 0; index < Math.min(pa.local.length, pb.local.length); index++) {
    const x = pa.local[index], y = pb.local[index];
    // Numeric local segments sort above alphanumeric ones.
    const localOrder = x.kind === 'num' && y.kind === 'num' ? cmpNum(x.value, y.value)
      : x.kind === 'text' && y.kind === 'text' ? cmpStr(x.value, y.value)
      : x.kind === 'num' ? 1 : -1;
    if (localOrder !== 0) return localOrder;
  }
  return cmpNum(pa.local.length, pb.local.length);
}

// --- Debian policy §5.6.12: [epoch:]upstream[-revision] compared part by part ---

function splitDebian(version: string): [number, string, string] {
  let epoch = 0;
  let rest = version;
  const colon = version.indexOf(':');
  if (colon !== -1) {
    epoch = parseU64(version.slice(0, colon)) ?? 0;
    rest = version.slice(colon + 1);
  }
  const dash = rest.lastIndexOf('-');
  return dash === -1 ? [epoch, rest, ''] : [epoch, rest.slice(0, dash), rest.slice(dash + 1)];
}

/** `~` sorts before everything (including the end of the part), letters
 * before non-letters, everything else by code point past the letters. */
function debianFragmentOrder(s: string): number {
  if (!s.length) return 0;
  const cp = s.codePointAt(0)!;
  if (cp === 0x7e) return -1;
  if ((cp >= 65 && cp <= 90) || (cp >= 97 && cp <= 122)) return cp;
  return cp + 256;
}

function compareDebianFragment(a: string, b: string): VersionOrdering {
  const isDigit = (c: string) => c >= '0' && c <= '9';
  const takeNumber = (s: string, start: number): [number, number] => {
    let end = start;
    while (end < s.length && isDigit(s[end])) end++;
    const digits = s.slice(start, end).replace(/^0+/, '');
    return [digits === '' ? 0 : parseU64(digits) ?? Number.MAX_SAFE_INTEGER, end];
  };
  let ia = 0, ib = 0;
  for (;;) {
    const restA = a.slice(ia), restB = b.slice(ib);
    if (!restA.length && !restB.length) return 0;
    if ((restA.length > 0 && isDigit(restA[0])) || (restB.length > 0 && isDigit(restB[0]))) {
      const [numA, nextA] = takeNumber(a, ia);
      const [numB, nextB] = takeNumber(b, ib);
      if (numA !== numB) return cmpNum(numA, numB);
      ia = nextA; ib = nextB;
      continue;
    }
    const orderA = debianFragmentOrder(restA), orderB = debianFragmentOrder(restB);
    if (orderA !== orderB) return cmpNum(orderA, orderB);
    if (restA.length) ia += restA.codePointAt(0)! > 0xffff ? 2 : 1;
    if (restB.length) ib += restB.codePointAt(0)! > 0xffff ? 2 : 1;
  }
}

function compareDebian(a: string, b: string): VersionOrdering | null {
  const [epochA, upstreamA, revisionA] = splitDebian(a);
  const [epochB, upstreamB, revisionB] = splitDebian(b);
  return cmpNum(epochA, epochB) || compareDebianFragment(upstreamA, upstreamB) || compareDebianFragment(revisionA, revisionB);
}

// --- Maven ComparableVersion: qualifier ranks alpha < beta < milestone < rc < snapshot < release < sp ---

type MavenItem = { kind: 'int'; value: number } | { kind: 'qualifier'; rank: number; num: number };

/** Rank 6 pads a version that ends before the other side's qualifier. */
const MAVEN_RELEASE_RANK = 6;
/** Known qualifiers longest-first, so `alpha` is never read as `a`. */
const MAVEN_QUALIFIERS: Array<[string, number]> = [
  ['milestone', 3], ['snapshot', 5], ['release', MAVEN_RELEASE_RANK], ['alpha', 1],
  ['final', MAVEN_RELEASE_RANK], ['beta', 2], ['cr', 4], ['ga', MAVEN_RELEASE_RANK],
  ['sp', 7], ['rc', 4], ['a', 1], ['b', 2], ['m', 3],
];

function mavenQualifierRank(token: string): [number, number] | null {
  const lower = token.toLowerCase();
  for (const [qualifier, rank] of MAVEN_QUALIFIERS) {
    if (!lower.startsWith(qualifier)) continue;
    const rest = lower.slice(qualifier.length);
    if (rest === '') return [rank, 0];
    const parsed = parseU64(rest);
    return parsed === null ? null : [rank, parsed];
  }
  return null;
}

function tokenizeMaven(version: string): MavenItem[] | null {
  const items: MavenItem[] = [];
  for (const token of version.split(/[.-]/)) {
    if (token === '') continue;
    const parsed = parseU64(token);
    if (parsed !== null) items.push({ kind: 'int', value: parsed });
    else {
      const qualifier = mavenQualifierRank(token);
      // Unknown qualifiers are refused rather than guessed.
      if (qualifier === null) return null;
      items.push({ kind: 'qualifier', rank: qualifier[0], num: qualifier[1] });
    }
  }
  return items;
}

function compareMaven(a: string, b: string): VersionOrdering | null {
  const ta = tokenizeMaven(a), tb = tokenizeMaven(b);
  if (!ta || !tb) return null;
  let order: VersionOrdering = 0;
  for (let index = 0; index < Math.max(ta.length, tb.length); index++) {
    const x = ta[index], y = tb[index];
    if (!x && !y) break;
    if (x?.kind === 'int' && y?.kind === 'int') order = cmpNum(x.value, y.value);
    else if (x?.kind === 'qualifier' && y?.kind === 'qualifier') order = cmpNum(x.rank, y.rank) || cmpNum(x.num, y.num);
    // An integer token outranks every qualifier token at the same position.
    else if (x?.kind === 'int' && y) order = 1;
    else if (x && y) order = -1;
    // A version that ran out of items is padded: with 0 when the other side
    // has an integer, with the release rank when it has a qualifier.
    else if (!x && y?.kind === 'int') order = cmpNum(0, y.value);
    else if (!x && y?.kind === 'qualifier') order = cmpNum(MAVEN_RELEASE_RANK, y.rank) || cmpNum(0, y.num);
    else if (x?.kind === 'int') order = cmpNum(x.value, 0);
    else if (x?.kind === 'qualifier') order = cmpNum(x.rank, MAVEN_RELEASE_RANK) || cmpNum(x.num, 0);
    if (order !== 0) return order;
  }
  return order;
}

// --- RubyGems Gem::Version: dotted segments, prerelease strings sort below numbers ---

type GemSegment = { kind: 'num'; value: number } | { kind: 'str'; value: string };

function parseGem(raw: string): GemSegment[] | null {
  const s = raw.trim().replace(/^[vV]+/, '');
  const segments: GemSegment[] = [];
  for (const segment of s.split('.')) {
    if (segment === '') return null;
    const parsed = parseU64(segment);
    if (parsed !== null) segments.push({ kind: 'num', value: parsed });
    else if (/^[A-Za-z0-9]+$/.test(segment)) segments.push({ kind: 'str', value: segment.toLowerCase() });
    else return null;
  }
  return segments.length ? segments : null;
}

function compareGem(a: string, b: string): VersionOrdering | null {
  const trim = (segments: GemSegment[]) => {
    const out = [...segments];
    while (out.length && out[out.length - 1].kind === 'num' && out[out.length - 1].value === 0) out.pop();
    return out;
  };
  const ta = parseGem(a), tb = parseGem(b);
  if (!ta || !tb) return null;
  const sa = trim(ta), sb = trim(tb);
  for (let index = 0; index < Math.min(sa.length, sb.length); index++) {
    const x = sa[index], y = sb[index];
    // Prerelease strings sort below numbers at the same position.
    const order = x.kind === 'num' && y.kind === 'num' ? cmpNum(x.value, y.value)
      : x.kind === 'str' && y.kind === 'str' ? cmpStr(x.value, y.value)
      : x.kind === 'num' ? 1 : -1;
    if (order !== 0) return order;
  }
  // One version is a prefix of the other after zero-trimming. The longer
  // side's remaining segments decide: a string segment makes it a prerelease
  // of the shorter release; a positive number makes it greater.
  const aLonger = sa.length > sb.length;
  const longer = aLonger ? sa : sb;
  for (const segment of longer.slice(Math.min(sa.length, sb.length))) {
    if (segment.kind === 'str') return aLonger ? -1 : 1;
    if (segment.value !== 0) return aLonger ? 1 : -1;
  }
  return 0;
}

// --- Loose: NuGet/Composer dotted numeric pins (up to four segments) plus a prerelease suffix ---

type LooseVersion = { release: [number, number, number, number]; pre: string | null };

function parseLoose(raw: string): LooseVersion | null {
  const s = raw.trim().replace(/^[vV]+/, '');
  const dash = s.indexOf('-'), plus = s.indexOf('+');
  const firstSep = dash === -1 ? plus : plus === -1 ? dash : Math.min(dash, plus);
  let core = s, pre: string | null = null;
  if (firstSep !== -1 && dash !== -1) {
    core = s.slice(0, firstSep);
    let suffix = s.slice(firstSep + 1);
    const suffixPlus = suffix.indexOf('+');
    if (suffixPlus !== -1) suffix = suffix.slice(0, suffixPlus);
    pre = suffix;
  } else if (plus !== -1) {
    core = s.slice(0, plus);
  }
  const tokens = core.split('.');
  if (tokens.length > 4) return null;
  const parts: number[] = [];
  for (let index = 0; index < Math.min(tokens.length, 3); index++) {
    const parsed = parseU64(tokens[index]);
    if (parsed === null) return null;
    parts.push(parsed);
  }
  while (parts.length < 3) parts.push(0);
  let revision = -1;
  if (tokens.length === 4) {
    const parsed = parseU64(tokens[3]);
    if (parsed === null) return null;
    revision = parsed;
  }
  return { release: [parts[0], parts[1], parts[2], revision], pre };
}

function compareLoose(a: string, b: string): VersionOrdering | null {
  const pa = parseLoose(a), pb = parseLoose(b);
  if (!pa || !pb) return null;
  const release = cmpNum(pa.release[0], pb.release[0]) || cmpNum(pa.release[1], pb.release[1]) || cmpNum(pa.release[2], pb.release[2]);
  if (release !== 0) return release;
  // A release outranks its prereleases; prerelease suffixes compare lexically.
  if (pa.pre !== null || pb.pre !== null) {
    if (pa.pre === null) return 1;
    if (pb.pre === null) return -1;
    const preOrder = cmpStr(pa.pre, pb.pre);
    if (preOrder !== 0) return preOrder;
  }
  return cmpNum(pa.release[3], pb.release[3]);
}

/** OSV evaluation over matching records: versions union ranges, with sorted events
 * and an independent (union) limit gate. Unknown in any supplied semantics blocks proof. */
export function affectedBy(v: Vulnerability, candidate: string): boolean | null {
  const evidence = v.affectedEvidence;
  if (!evidence || evidence.ecosystem !== v.ecosystem || evidence.packageName !== v.packageName || !evidence.records.length) return null;
  let affected = false;
  for (const record of evidence.records) {
    if (record.package?.ecosystem !== v.ecosystem || record.package?.name !== v.packageName) return null;
    if (record.versions !== undefined && !Array.isArray(record.versions)) return null;
    if (record.versions?.length) {
      const family = versionFamilyForEcosystem(v.ecosystem);
      if (!family) return null;
      for (const value of record.versions) {
        const order = typeof value === 'string' ? compareVersions(family, candidate, value) : null;
        if (order === null) return null;
        if (order === 0) affected = true;
      }
    }
    if (record.ranges !== undefined && !Array.isArray(record.ranges)) return null;
    if (!(record.ranges?.length || record.versions?.length)) return null;
    for (const range of record.ranges ?? []) {
      if (!range || !Array.isArray(range.events) || !range.events.length) return null;
      const family = range.type === 'SEMVER' ? 'semver'
        : range.type === 'ECOSYSTEM' ? versionFamilyForEcosystem(v.ecosystem)
        : null;
      if (!family || compareVersions(family, candidate, candidate) === null) return null;
      const transitions: Array<{ kind: string; version: string; zero: boolean }> = [];
      const limits: Array<string | '*'> = [];
      for (const event of range.events) {
        if (!event || typeof event !== 'object' || Object.keys(event).length !== 1) return null;
        const [kind, value] = Object.entries(event)[0];
        if (!['introduced','fixed','last_affected','limit'].includes(kind)) return null;
        if (kind === 'limit' && value === '*') { limits.push('*'); continue; }
        if (typeof value !== 'string') return null;
        if (kind === 'introduced' && value === '0') { transitions.push({ kind, version: value, zero: true }); continue; }
        if (compareVersions(family, value, value) === null) return null;
        if (kind === 'limit') limits.push(value);
        else transitions.push({ kind, version: value, zero: false });
      }
      if (!transitions.some(e=>e.kind==='introduced') || (transitions.some(e=>e.kind==='fixed') && transitions.some(e=>e.kind==='last_affected'))) return null;
      const orderEvents = (x: { version: string; zero: boolean }, y: { version: string; zero: boolean }): VersionOrdering =>
        x.zero ? (y.zero ? 0 : -1) : y.zero ? 1 : compareVersions(family, x.version, y.version)!;
      transitions.sort(orderEvents);
      // Simultaneous status transitions are ambiguous; do not guess tie order.
      if (transitions.some((e,i)=>i>0 && orderEvents(e,transitions[i-1])===0)) return null;
      let included = false;
      for (const event of transitions) {
        const order = event.zero ? 1 : compareVersions(family, candidate, event.version);
        if (order === null) return null;
        if (event.kind==='introduced' && order>=0) included=true;
        if (event.kind==='fixed' && order>=0) included=false;
        if (event.kind==='last_affected' && order>0) included=false;
      }
      const beforeLimit=!limits.length || limits.some(limit=>limit==='*' || compareVersions(family, candidate, limit)! < 0);
      if (beforeLimit && included) affected=true;
    }
  }
  return affected;
}
function suppliedFixes(v: Vulnerability): string[] {
  const fixes: string[]=[];
  for (const record of v.affectedEvidence?.records ?? []) {
    if (!record || !Array.isArray(record.ranges)) continue;
    for (const range of record.ranges) {
      if (!range || !Array.isArray(range.events)) continue;
      for (const event of range.events) {
        if (event && typeof event.fixed==='string') fixes.push(event.fixed);
      }
    }
  }
  return fixes;
}
/** Classify the version jump by the first differing dotted-numeric segment. */
function classifyChange(installed: string, candidate: string): string {
  const segments = (raw: string): number[] | null => {
    const match = /^[vV]?(\d+(?:\.\d+)*)/.exec(raw.trim());
    if (!match) return null;
    const parts = match[1].split('.').map(Number);
    return parts.every(Number.isSafeInteger) ? parts : null;
  };
  const from = segments(installed), to = segments(candidate);
  if (!from || !to) return 'unknown';
  for (let index = 0; index < Math.max(from.length, to.length); index++) {
    if ((from[index] ?? 0) !== (to[index] ?? 0)) return index === 0 ? 'major' : index === 1 ? 'minor' : 'patch';
  }
  return 'patch';
}
const safeName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
function directCommand(group: UpgradeGroup): string | null {
  const v=group.advisories[0];
  if (!group.candidate || !group.paths.length || !v.lockfile.endsWith('/package-lock.json')) return null;
  if (group.advisories.some(a=>a.occurrence?.localWorkspace || a.occurrence?.status!=='available' || a.occurrence.warnings.length>0)) return null;
  const first=group.paths[0].chain[0];
  if (!first || !safeName.test(first.name) || first.name!==v.packageName) return null;
  const flag={runtime:'--save-prod',dev:'--save-dev',optional:'--save-optional'}[first.dependencyType];
  if (!flag || group.paths.some(p=>p.chain.length!==1 || p.chain[0].name!==first.name || p.chain[0].dependencyType!==first.dependencyType || p.chain[0].installPath!==v.occurrence?.installPath || !/^[~^]?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(p.chain[0].declared))) return null;
  const workspace=group.paths[0].workspace;
  if (workspace && (!/^[a-zA-Z0-9_@./-]+$/.test(workspace) || workspace.startsWith('/') || workspace.split('/').some(p=>!p || p==='..' || p==='.'))) return null;
  return `npm install --ignore-scripts ${flag}${workspace ? ` --workspace '${workspace}'` : ''} -- '${first.name}@${group.candidate}'`;
}
export function vulnerabilityKey(v: Vulnerability): string {
  return JSON.stringify([v.id,v.ecosystem,v.packageName,v.installedVersion,v.lockfile,v.occurrence?.installPath ?? null]);
}
export function upgradeGroups(vulnerabilities: Vulnerability[]): UpgradeGroup[] {
  const groups=new Map<string,UpgradeGroup>();
  for (const v of vulnerabilities) {
    const paths=v.occurrence?.paths.length ? v.occurrence.paths : [null];
    for (const path of paths) {
      const key=JSON.stringify([v.ecosystem,v.packageName,v.installedVersion,v.lockfile,v.occurrence?.installPath ?? null,path?.workspace ?? null,path?.entryPoint ?? null]);
      let group=groups.get(key);
      if (!group) { group={key,advisories:[],paths:[],candidate:null,classification:'unknown',command:null,checklist:''};groups.set(key,group); }
      if (!group.advisories.includes(v)) group.advisories.push(v);
      if (path && !group.paths.some(p=>JSON.stringify(p)===JSON.stringify(path))) group.paths.push(path);
    }
  }
  for (const group of groups.values()) {
    const v=group.advisories[0];
    const family=versionFamilyForEcosystem(v.ecosystem);
    if (family && compareVersions(family,v.installedVersion,v.installedVersion)!==null && group.advisories.every(advisory=>affectedBy(advisory,v.installedVersion)===true)) {
      // The lowest fixed version strictly above the installed one, per the
      // ecosystem comparator; fixed strings the comparator refuses are not candidates.
      const fixes=[...new Set(group.advisories.flatMap(suppliedFixes))]
        .filter(fix=>{ const order=compareVersions(family,fix,v.installedVersion); return order!==null && order>0; })
        .sort((a,b)=>compareVersions(family,a,b)!);
      group.candidate=fixes.find(fix=>group.advisories.every(advisory=>affectedBy(advisory,fix)===false)) ?? null;
      if (group.candidate) group.classification=classifyChange(v.installedVersion,group.candidate);
    }
    group.command=directCommand(group);
    const origin=group.paths[0];
    group.checklist=[
      `Review ${v.packageName}@${v.installedVersion} in ${v.lockfile} (${v.occurrence?.installPath ?? 'installation path unknown'}).`,
      origin ? `Review manifest ${origin.workspace || 'root'} and update entry point ${origin.entryPoint}${group.paths.some(p=>p.chain.length>1)?'; select a parent release that updates the affected transitive package':''}.` : 'Establish the dependency chain and direct manifest entry point; relationship evidence is unknown.',
      group.candidate ? `Advisory candidate ${group.candidate} clears the supplied supported ranges; verify release availability and project compatibility.` : 'Manual decision: no supplied candidate is proven to clear all advisory ranges. Review each advisory fix.',
      `Related advisories: ${[...new Set(group.advisories.map(a=>a.id))].join(', ')}.`,
      'Review manifest and lockfile changes, run project checks, then Recheck dependencies in oxAudit.'
    ].join('\n');
  }
  return [...groups.values()];
}
