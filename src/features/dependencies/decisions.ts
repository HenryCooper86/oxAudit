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
 * guess (an unparseable version, a number past the integer width the Rust
 * side parses into); callers treat `null` as undetermined and never silently
 * drop the advisory. The two implementations are held together by the shared
 * vectors in src-tauri/tests/fixtures/version-ordering-vectors.json, which
 * both test suites run.
 */
export type VersionFamily = 'semver' | 'pep440' | 'debian' | 'maven' | 'gem' | 'loose' | 'pub';

/**
 * Pick the comparator for an OSV range. Mirrors `versioning::family_for`:
 * `SEMVER` ranges are SemVer, `ECOSYSTEM` ranges take the ecosystem's own
 * family, anything else (`GIT`) is `null` because matching would be a guess.
 */
export function versionFamilyFor(rangeType: string, ecosystem: string): VersionFamily | null {
  switch (rangeType) {
    case 'SEMVER': return 'semver';
    case 'ECOSYSTEM': return versionFamilyForEcosystem(ecosystem);
    default: return null;
  }
}

/**
 * Pick the comparator for an ecosystem's native (OSV `ECOSYSTEM`) versions.
 * Mirrors the `ECOSYSTEM` arm of `versioning::family_for`; `null` when
 * matching would be a guess. Hex is SemVer 2.0 (build metadata ignored); Pub
 * is SemVer with build metadata ordered after the release. Wolfi, Chainguard
 * and the distro ecosystems (Debian, Ubuntu, Alpine — with or without a
 * `:release`) use the epoch-based Debian policy comparator. RPM distributions
 * (Rocky Linux, AlmaLinux, Red Hat, SUSE) need rpmvercmp, which neither side
 * implements, so they stay undetermined.
 */
export function versionFamilyForEcosystem(ecosystem: string): VersionFamily | null {
  switch (ecosystem) {
    case 'PyPI': return 'pep440';
    case 'Maven': return 'maven';
    case 'RubyGems': return 'gem';
    case 'npm': case 'crates.io': case 'Go': case 'Hex': return 'semver';
    case 'Pub': return 'pub';
    case 'Packagist': case 'NuGet': return 'loose';
    case 'Wolfi': case 'Chainguard': return 'debian';
    default: {
      // The release never changes the version scheme, so only the name
      // before the first `:` decides.
      const colon = ecosystem.indexOf(':');
      const distro = colon === -1 ? ecosystem : ecosystem.slice(0, colon);
      return distro === 'Debian' || distro === 'Ubuntu' || distro === 'Alpine' ? 'debian' : null;
    }
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
    case 'pub': return comparePub(a, b);
  }
}

const cmpNum = (x: number | bigint, y: number | bigint): VersionOrdering => x < y ? -1 : x > y ? 1 : 0;
const cmpStr = (x: string, y: string): VersionOrdering => x < y ? -1 : x > y ? 1 : 0;
/** `Ordering::reverse` without producing `-0`. */
const reverse = (order: VersionOrdering): VersionOrdering => order === 0 ? 0 : order === 1 ? -1 : 1;

const U64_MAX = 18446744073709551615n;
const I64_MAX = 9223372036854775807n;

/**
 * Mirror Rust's `str::parse::<u64>` exactly: an optional leading `+`, ASCII
 * digits, at most `u64::MAX`. Values are bigints so nothing past 2^53 loses
 * precision.
 */
function parseU64(raw: string): bigint | null {
  if (!/^\+?[0-9]+$/.test(raw)) return null;
  const value = BigInt(raw.replace(/^\+/, ''));
  return value <= U64_MAX ? value : null;
}

/** Digits only, then `parse::<u64>` — the Rust side's digit-checked parses. */
function parseDigitsU64(raw: string): bigint | null {
  return /^[0-9]+$/.test(raw) ? parseU64(raw) : null;
}

/** Rust's `str::trim` (Unicode White_Space): unlike `String#trim` it strips U+0085 and keeps U+FEFF. */
const RUST_WHITESPACE = `[${String.fromCharCode(0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000)}-${String.fromCharCode(0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000)}]`;
const RUST_TRIM = new RegExp(`^${RUST_WHITESPACE}+|${RUST_WHITESPACE}+$`, 'g');
const rustTrim = (s: string): string => s.replace(RUST_TRIM, '');

/** Rust's `to_ascii_lowercase`: non-ASCII characters are left alone. */
const asciiLower = (s: string): string => s.replace(/[A-Z]+/g, (run) => run.toLowerCase());

// --- semver.org ordering, lenient about leading v, missing segments, build metadata ---

type SemverIdent = { kind: 'num'; value: bigint } | { kind: 'alpha'; value: string };
type SemverVersion = { major: bigint; minor: bigint; patch: bigint; pre: SemverIdent[] };

/** Dot-separated identifiers, numeric where they parse as u64; `null` for an
 * empty identifier or a character outside `[0-9A-Za-z-]`. */
function parseSemverIdentifiers(raw: string): SemverIdent[] | null {
  const idents: SemverIdent[] = [];
  for (const ident of raw.split('.')) {
    if (ident === '') return null;
    const numeric = parseU64(ident);
    if (numeric !== null) idents.push({ kind: 'num', value: numeric });
    else if (/^[A-Za-z0-9-]+$/.test(ident)) idents.push({ kind: 'alpha', value: ident });
    else return null;
  }
  return idents;
}

function parseSemver(raw: string): SemverVersion | null {
  const s = rustTrim(raw).replace(/^[vV=]+/, '');
  const plus = s.indexOf('+');
  const withoutBuild = plus === -1 ? s : s.slice(0, plus);
  const dash = withoutBuild.indexOf('-');
  const core = dash === -1 ? withoutBuild : withoutBuild.slice(0, dash);
  const preRaw = dash === -1 ? '' : withoutBuild.slice(dash + 1);
  const numbers = core.split('.');
  if (numbers.length > 3) return null;
  const major = parseDigitsU64(numbers[0]);
  if (major === null) return null;
  const minor = numbers.length > 1 ? parseDigitsU64(numbers[1]) : 0n;
  if (minor === null) return null;
  const patch = numbers.length > 2 ? parseDigitsU64(numbers[2]) : 0n;
  if (patch === null) return null;
  const pre = preRaw === '' ? [] : parseSemverIdentifiers(preRaw);
  if (pre === null) return null;
  return { major, minor, patch, pre };
}

/** The build identifiers after `+`, empty when there are none; an empty or
 * malformed build is refused. */
function parseSemverBuild(raw: string): SemverIdent[] | null {
  const s = rustTrim(raw);
  const plus = s.indexOf('+');
  return plus === -1 ? [] : parseSemverIdentifiers(s.slice(plus + 1));
}

function compareSemverIdents(a: SemverIdent[], b: SemverIdent[]): VersionOrdering {
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    const x = a[index], y = b[index];
    // Numeric identifiers always have lower precedence.
    const order = x.kind === 'num' && y.kind === 'num' ? cmpNum(x.value, y.value)
      : x.kind === 'alpha' && y.kind === 'alpha' ? cmpStr(x.value, y.value)
      : x.kind === 'num' ? -1 : 1;
    if (order !== 0) return order;
  }
  return cmpNum(a.length, b.length);
}

function compareSemverParsed(a: SemverVersion, b: SemverVersion): VersionOrdering {
  const release = cmpNum(a.major, b.major) || cmpNum(a.minor, b.minor) || cmpNum(a.patch, b.patch);
  if (release !== 0) return release;
  // A release outranks any of its own prereleases.
  if (!a.pre.length || !b.pre.length) return a.pre.length === b.pre.length ? 0 : a.pre.length ? -1 : 1;
  return compareSemverIdents(a.pre, b.pre);
}

function compareSemver(a: string, b: string): VersionOrdering | null {
  const pa = parseSemver(a), pb = parseSemver(b);
  if (!pa || !pb) return null;
  return compareSemverParsed(pa, pb);
}

/**
 * Pub's `pub_semver` ordering: SemVer precedence, then build metadata as a
 * final tie-break. Unlike SemVer 2.0 the build is significant — a version
 * with one sorts after the same version without, and build identifiers
 * compare like prerelease ones, so `1.0.0-pre < 1.0.0-pre+build < 1.0.0 <
 * 1.0.0+build`. Mirrors `semver::compare_pub`.
 */
function comparePub(a: string, b: string): VersionOrdering | null {
  const pa = parseSemver(a), ba = parseSemverBuild(a);
  if (!pa || !ba) return null;
  const pb = parseSemver(b), bb = parseSemverBuild(b);
  if (!pb || !bb) return null;
  const order = compareSemverParsed(pa, pb);
  if (order !== 0) return order;
  if (!ba.length || !bb.length) return ba.length === bb.length ? 0 : ba.length ? 1 : -1;
  return compareSemverIdents(ba, bb);
}

// --- PEP 440 ordering: epochs, trailing zeros insignificant, dev < pre < release < post, locals ---

type Pep440Marker = { kind: 'pre'; phase: bigint } | { kind: 'post' } | { kind: 'dev' };
type Pep440Version = {
  epoch: bigint;
  release: bigint[];
  pre: [bigint, bigint] | null;
  post: bigint | null;
  dev: bigint | null;
  local: Array<{ kind: 'num'; value: bigint } | { kind: 'text'; value: string }>;
};

/** Longest-first so `rc` is never read as the post marker `r`. */
const PEP440_MARKERS: Array<[string, Pep440Marker]> = [
  ['preview', { kind: 'pre', phase: 2n }],
  ['alpha', { kind: 'pre', phase: 0n }],
  ['beta', { kind: 'pre', phase: 1n }],
  ['post', { kind: 'post' }],
  ['pre', { kind: 'pre', phase: 2n }],
  ['rev', { kind: 'post' }],
  ['dev', { kind: 'dev' }],
  ['rc', { kind: 'pre', phase: 2n }],
  ['a', { kind: 'pre', phase: 0n }],
  ['b', { kind: 'pre', phase: 1n }],
  ['c', { kind: 'pre', phase: 2n }],
  ['r', { kind: 'post' }],
];
const PEP440_SEPARATORS = ['.', '-', '_'];

function parsePep440(raw: string): Pep440Version | null {
  let s = asciiLower(rustTrim(raw).replace(/^[vV]+/, ''));
  let localRaw = '';
  const plus = s.indexOf('+');
  if (plus !== -1) { localRaw = s.slice(plus + 1); s = s.slice(0, plus); }
  let epoch = 0n;
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
  const release: bigint[] = [];
  for (const segment of releasePart.split('.')) {
    const parsed = parseU64(segment);
    if (parsed === null) return null;
    release.push(parsed);
  }
  let pre: [bigint, bigint] | null = null;
  let post: bigint | null = null;
  let dev: bigint | null = null;
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
      const digits = /^[0-9]*/.exec(after)![0];
      const parsed = digits === '' ? 0n : parseU64(digits);
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
function trimmedRelease(release: bigint[]): bigint[] {
  let end = release.length;
  while (end > 0 && release[end - 1] === 0n) end--;
  return release.slice(0, end);
}

function compareBigArrays(a: bigint[], b: bigint[]): VersionOrdering {
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return cmpNum(a[index], b[index]);
  }
  return cmpNum(a.length, b.length);
}

function comparePep440(a: string, b: string): VersionOrdering | null {
  const pa = parsePep440(a), pb = parsePep440(b);
  if (!pa || !pb) return null;
  const order = cmpNum(pa.epoch, pb.epoch) || compareBigArrays(trimmedRelease(pa.release), trimmedRelease(pb.release));
  if (order !== 0) return order;
  // A dev-only version (no pre, no post) sorts before pre-releases; a bare
  // release sorts after them; no post sorts before any post; a dev release
  // sorts below the same version without one.
  const preKey = (v: Pep440Version): bigint[] =>
    v.pre ? [0n, v.pre[0], v.pre[1]] : v.post === null && v.dev !== null ? [-1n, 0n, 0n] : [1n, 0n, 0n];
  const postKey = (v: Pep440Version): bigint[] => v.post === null ? [-1n, 0n] : [0n, v.post];
  const devKey = (v: Pep440Version): bigint[] => v.dev === null ? [1n, 0n] : [0n, v.dev];
  const keys = compareBigArrays(preKey(pa), preKey(pb)) || compareBigArrays(postKey(pa), postKey(pb)) || compareBigArrays(devKey(pa), devKey(pb));
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

function splitDebian(version: string): [bigint, string, string] {
  let epoch = 0n;
  let rest = version;
  const colon = version.indexOf(':');
  if (colon !== -1) {
    epoch = parseU64(version.slice(0, colon)) ?? 0n;
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
  // Digit runs compare numerically; a run past u64 saturates like the Rust side.
  const takeNumber = (s: string, start: number): [bigint, number] => {
    let end = start;
    while (end < s.length && isDigit(s[end])) end++;
    const digits = s.slice(start, end).replace(/^0+/, '');
    return [digits === '' ? 0n : parseU64(digits) ?? U64_MAX, end];
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

// --- Maven ComparableVersion, as the POM version order specification describes it ---
//
// Mirrors `versioning::maven`:
// - the version is lowercased and split into tokens at `.`, `-` and every
//   transition between digits and non-digits (a transition acts as `-`);
//   each token remembers its separator, and an empty token is `0`;
// - `a`/`b`/`m` directly followed by a digit mean alpha/beta/milestone, `cr`
//   means `rc`, and `ga`/`final`/`release` mean the release (`""`);
// - trailing null tokens (`0`, the release) are trimmed from the end, and
//   again before each remaining `-` group;
// - tokens compare pairwise, the shorter side padded with a null. With the
//   same separator numbers compare numerically (as digit strings, so any
//   width works), a qualifier sits below a number, and qualifiers order
//   `alpha < beta < milestone < rc = cr < snapshot < "" = ga = final =
//   release < sp < unknown`, unknown ones lexically among themselves. With
//   different separators, `.qualifier < -qualifier < -number < .number`.
// Unknown qualifiers (Guava's `-jre`, Jetty's `.v20210629`) therefore order
// the way Maven orders them; only an empty, whitespace-containing or
// non-ASCII version is refused.

type MavenToken = {
  separator: '.' | '-';
  /** A number is digits without leading zeroes (`"0"` for zero); a qualifier
   * is lowercased with aliases folded onto the canonical spelling. */
  kind: 'number' | 'qualifier';
  value: string;
};

/** Known qualifiers in order; `""` is the release. Anything else ranks after all of them. */
const MAVEN_KNOWN_QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];

function mavenQualifierRank(qualifier: string): number {
  const rank = MAVEN_KNOWN_QUALIFIERS.indexOf(qualifier);
  return rank === -1 ? MAVEN_KNOWN_QUALIFIERS.length : rank;
}

function compareMavenQualifiers(a: string, b: string): VersionOrdering {
  // Equal known ranks are equal strings (aliases are already folded), so the
  // lexical tie-break only ever orders unknown qualifiers.
  return cmpNum(mavenQualifierRank(a), mavenQualifierRank(b)) || cmpStr(a, b);
}

/** Leading-zero-free digit strings: longer is larger, then lexical. */
function compareDigitStrings(a: string, b: string): VersionOrdering {
  return cmpNum(a.length, b.length) || cmpStr(a, b);
}

/** Order across different separators: `.qualifier < -qualifier < -number < .number`. */
function mavenKindRank(token: MavenToken): number {
  if (token.kind === 'qualifier') return token.separator === '.' ? 0 : 1;
  return token.separator === '-' ? 2 : 3;
}

function compareMavenTokens(a: MavenToken, b: MavenToken): VersionOrdering {
  if (a.separator !== b.separator) return cmpNum(mavenKindRank(a), mavenKindRank(b));
  if (a.kind === 'number' && b.kind === 'number') return compareDigitStrings(a.value, b.value);
  if (a.kind === 'qualifier' && b.kind === 'qualifier') return compareMavenQualifiers(a.value, b.value);
  return a.kind === 'number' ? 1 : -1;
}

/** `token` against the null the shorter version is padded with: zero against
 * a number, the release against a qualifier — so `1 < 1.1`,
 * `1-snapshot < 1 < 1-sp`, and `1 < 1-jre`. */
function compareMavenToPadding(token: MavenToken): VersionOrdering {
  return token.kind === 'number' ? compareDigitStrings(token.value, '0') : compareMavenQualifiers(token.value, '');
}

const isMavenNull = (token: MavenToken): boolean => token.value === (token.kind === 'number' ? '0' : '');

function canonicalMavenQualifier(qualifier: string, followedByDigit: boolean): string {
  switch (qualifier) {
    case 'a': return followedByDigit ? 'alpha' : qualifier;
    case 'b': return followedByDigit ? 'beta' : qualifier;
    case 'm': return followedByDigit ? 'milestone' : qualifier;
    case 'cr': return 'rc';
    case 'ga': case 'final': case 'release': return '';
    default: return qualifier;
  }
}

/** Split one `.`/`-`-delimited segment at its digit/non-digit transitions;
 * every piece after the first is `-`-separated. */
function pushMavenSegment(tokens: MavenToken[], firstSeparator: '.' | '-', segment: string): void {
  if (segment === '') {
    tokens.push({ separator: firstSeparator, kind: 'number', value: '0' });
    return;
  }
  let separator = firstSeparator;
  const pieces = segment.match(/[0-9]+|[^0-9]+/g)!;
  pieces.forEach((piece, index) => {
    const digit = piece[0] >= '0' && piece[0] <= '9';
    tokens.push(digit
      ? { separator, kind: 'number', value: piece.replace(/^0+/, '') || '0' }
      // A non-digit run that is not the last piece stops at a digit.
      : { separator, kind: 'qualifier', value: canonicalMavenQualifier(piece, index < pieces.length - 1) });
    separator = '-';
  });
}

/** Trim trailing nulls from the end, then again before each remaining `-`
 * group, walking from the end to the start. The first token stays. */
function trimMavenNulls(tokens: MavenToken[]): void {
  let trimming = true;
  for (let index = tokens.length - 1; index >= 1; index--) {
    const startsGroup = tokens[index].separator === '-';
    if (trimming && isMavenNull(tokens[index])) tokens.splice(index, 1);
    else trimming = false;
    if (startsGroup) trimming = true;
  }
}

function parseMaven(raw: string): MavenToken[] | null {
  const trimmed = rustTrim(raw);
  // Printable ASCII only — checked before lowercasing so no non-ASCII
  // character can fold into an ASCII one.
  if (!/^[\x21-\x7e]+$/.test(trimmed)) return null;
  const version = trimmed.toLowerCase();
  const tokens: MavenToken[] = [];
  let separator: '.' | '-' = '.';
  let start = 0;
  for (;;) {
    let end = start;
    while (end < version.length && version[end] !== '.' && version[end] !== '-') end++;
    pushMavenSegment(tokens, separator, version.slice(start, end));
    if (end === version.length) break;
    separator = version[end] === '.' ? '.' : '-';
    start = end + 1;
  }
  trimMavenNulls(tokens);
  return tokens;
}

function compareMaven(a: string, b: string): VersionOrdering | null {
  const ta = parseMaven(a), tb = parseMaven(b);
  if (!ta || !tb) return null;
  for (let index = 0; index < Math.max(ta.length, tb.length); index++) {
    const x = ta[index], y = tb[index];
    const order = x && y ? compareMavenTokens(x, y)
      : x ? compareMavenToPadding(x)
      : reverse(compareMavenToPadding(y));
    if (order !== 0) return order;
  }
  return 0;
}

// --- RubyGems Gem::Version: dotted segments, prerelease strings sort below numbers ---

type GemSegment = { kind: 'num'; value: bigint } | { kind: 'str'; value: string };

function parseGem(raw: string): GemSegment[] | null {
  const s = rustTrim(raw).replace(/^[vV]+/, '');
  const segments: GemSegment[] = [];
  for (const segment of s.split('.')) {
    if (segment === '') return null;
    const parsed = parseU64(segment);
    if (parsed !== null) segments.push({ kind: 'num', value: parsed });
    else if (/^[A-Za-z0-9]+$/.test(segment)) segments.push({ kind: 'str', value: asciiLower(segment) });
    else return null;
  }
  return segments.length ? segments : null;
}

function compareGem(a: string, b: string): VersionOrdering | null {
  const trim = (segments: GemSegment[]) => {
    const out = [...segments];
    while (out.length && out[out.length - 1].kind === 'num' && out[out.length - 1].value === 0n) out.pop();
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
    if (segment.value !== 0n) return aLonger ? 1 : -1;
  }
  return 0;
}

// --- Loose: NuGet/Composer dotted numeric pins (up to four segments) plus a prerelease suffix ---

type LooseVersion = { release: [bigint, bigint, bigint, bigint]; pre: string | null };

function parseLoose(raw: string): LooseVersion | null {
  const s = rustTrim(raw).replace(/^[vV]+/, '');
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
  const parts: bigint[] = [];
  for (let index = 0; index < Math.min(tokens.length, 3); index++) {
    const parsed = parseDigitsU64(tokens[index]);
    if (parsed === null) return null;
    parts.push(parsed);
  }
  while (parts.length < 3) parts.push(0n);
  // The revision is an i64 on the Rust side, -1 when absent.
  let revision = -1n;
  if (tokens.length === 4) {
    const parsed = parseDigitsU64(tokens[3]);
    if (parsed === null || parsed > I64_MAX) return null;
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
      const family = typeof range.type === 'string' ? versionFamilyFor(range.type, v.ecosystem) : null;
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
