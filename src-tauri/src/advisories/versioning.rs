//! Local version comparison for advisory range evaluation.
//!
//! Online matching delegates to OSV's server, which owns ecosystem-correct
//! semantics. A local advisory database has no server, so this module carries
//! the comparison rules locally: one comparator per family, each derived from
//! the family's published specification, each lenient about the spellings real
//! lockfiles contain (leading `v`, missing patch segments, build metadata).
//!
//! A comparator returns `None` when it refuses to guess — an unparseable
//! version, or a construct the spec leaves to implementations (`dev-` branch
//! names); `family_for` likewise has no family for a scheme without a
//! comparator here (RPM). Callers treat `None` as *undetermined*, which keeps
//! the advisory (never silently drops it) and says so.

use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionFamily {
    SemVer,
    Pep440,
    Debian,
    Maven,
    Gem,
    /// Dotted-numeric with an optional prerelease suffix — the shape NuGet and
    /// Composer pin in practice. SemVer covers most of it; this handles the
    /// fourth revision segment NuGet allows.
    Loose,
    /// SemVer with build metadata ordered after the release, as Dart's
    /// `pub_semver` (and OSV's Pub ecosystem) compare it.
    Pub,
}

/// Pick the comparator for an OSV range. `range_type` is the OSV range type
/// (`SEMVER`, `ECOSYSTEM`, `GIT`); the ecosystem disambiguates `ECOSYSTEM`.
/// Returns `None` when matching would be a guess.
pub fn family_for(range_type: &str, ecosystem: &str) -> Option<VersionFamily> {
    match range_type {
        "SEMVER" => Some(VersionFamily::SemVer),
        "GIT" => None,
        "ECOSYSTEM" => match ecosystem {
            "PyPI" => Some(VersionFamily::Pep440),
            "Maven" => Some(VersionFamily::Maven),
            "RubyGems" => Some(VersionFamily::Gem),
            // Elixir's `Version` is SemVer 2.0, build metadata ignored.
            "npm" | "crates.io" | "Go" | "Hex" => Some(VersionFamily::SemVer),
            "Pub" => Some(VersionFamily::Pub),
            "Packagist" | "NuGet" => Some(VersionFamily::Loose),
            // apk-versioned distributions OSV names without a release. They
            // take the comparator Alpine uses.
            "Wolfi" | "Chainguard" => Some(VersionFamily::Debian),
            other => {
                // Distro ecosystems (Debian:*, Ubuntu:*, Alpine:*) all use
                // epoch-based comparison over the same character rules. The
                // release never changes the version scheme, so the bare names
                // ELF package notes carry (`Debian`, no release) share it.
                // RPM distributions (Rocky Linux, AlmaLinux, Red Hat, SUSE)
                // need rpmvercmp, which this module does not implement, so
                // they stay undetermined.
                let distro = other.split_once(':').map_or(other, |(name, _)| name);
                matches!(distro, "Debian" | "Ubuntu" | "Alpine").then_some(VersionFamily::Debian)
            }
        },
        _ => None,
    }
}

/// Whether `scope` names `ecosystem` itself or, as a bare distribution name
/// such as `Debian`, one of its release-qualified ecosystems (`Debian:12`).
///
/// OSV answers a bare distribution across every release, and the bare
/// distribution dump carries every release's records, so the local database
/// treats a bare name the same way in both directions: a bare query reads
/// every release's advisories, and a bare dump covers release queries.
pub fn ecosystem_within(scope: &str, ecosystem: &str) -> bool {
    scope == ecosystem
        || (!scope.is_empty()
            && !scope.contains(':')
            && ecosystem.len() > scope.len() + 1
            && ecosystem.starts_with(scope)
            && ecosystem.as_bytes()[scope.len()] == b':')
}

/// Normalize a package name the way the ecosystem's registry does, so a
/// lockfile spelling and the OSV spelling of the same package meet. PEP 503
/// for PyPI, case-folding for npm; everything else matches exactly.
pub fn normalize_package(ecosystem: &str, name: &str) -> String {
    match ecosystem {
        "PyPI" => {
            let folded = name.to_ascii_lowercase();
            folded.replace(['-', '_', '.'], "-")
        }
        "npm" => name.to_ascii_lowercase(),
        _ => name.to_string(),
    }
}

pub fn compare(family: VersionFamily, a: &str, b: &str) -> Option<Ordering> {
    match family {
        VersionFamily::SemVer => semver::compare(a, b),
        VersionFamily::Pep440 => pep440::compare(a, b),
        VersionFamily::Debian => debian::compare(a, b),
        VersionFamily::Maven => maven::compare(a, b),
        VersionFamily::Gem => gem::compare(a, b),
        VersionFamily::Loose => loose::compare(a, b),
        VersionFamily::Pub => semver::compare_pub(a, b),
    }
}

pub mod semver {
    //! semver.org ordering with the leniency real pins need: a leading `v`
    //! (Go), missing minor/patch (npm shorthands), build metadata ignored.

    use std::cmp::Ordering;

    #[derive(Debug, PartialEq, Eq)]
    pub struct Version {
        pub major: u64,
        pub minor: u64,
        pub patch: u64,
        /// Dot-separated prerelease identifiers, empty when this is a release.
        pub pre: Vec<PreIdent>,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub enum PreIdent {
        Num(u64),
        Alpha(String),
    }

    pub fn parse(raw: &str) -> Option<Version> {
        let s = raw.trim().trim_start_matches(['v', 'V', '=']);
        let without_build = s.split_once('+').map_or(s, |(core, _)| core);
        let (core, pre_raw) = match without_build.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (without_build, None),
        };
        let mut numbers = core.split('.');
        let major = parse_num(numbers.next()?)?;
        let minor = match numbers.next() {
            None => 0,
            Some(token) => parse_num(token)?,
        };
        let patch = match numbers.next() {
            None => 0,
            Some(token) => parse_num(token)?,
        };
        if numbers.next().is_some() {
            return None;
        }
        let pre = match pre_raw {
            Some(pre) if !pre.is_empty() => parse_identifiers(pre)?,
            _ => Vec::new(),
        };
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// Dot-separated identifiers, numeric where all digits; `None` for an
    /// empty identifier or a character outside `[0-9A-Za-z-]`.
    fn parse_identifiers(raw: &str) -> Option<Vec<PreIdent>> {
        raw.split('.')
            .map(|ident| {
                if ident.is_empty() {
                    None
                } else if let Ok(n) = ident.parse::<u64>() {
                    Some(PreIdent::Num(n))
                } else {
                    ident
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
                        .then(|| PreIdent::Alpha(ident.to_string()))
                }
            })
            .collect()
    }

    /// The build identifiers after `+`, empty when there are none. An empty
    /// or malformed build is refused.
    fn parse_build(raw: &str) -> Option<Vec<PreIdent>> {
        match raw.trim().split_once('+') {
            None => Some(Vec::new()),
            Some((_, build)) => parse_identifiers(build),
        }
    }

    /// Pub's `pub_semver` ordering: SemVer precedence, then build metadata as
    /// a final tie-break. Unlike SemVer 2.0 the build is significant — a
    /// version with one sorts after the same version without, and build
    /// identifiers compare like prerelease ones, so
    /// `1.0.0-pre < 1.0.0-pre+build < 1.0.0 < 1.0.0+build`. OSV's Pub
    /// ecosystem orders versions the same way.
    pub fn compare_pub(a: &str, b: &str) -> Option<Ordering> {
        let (version_a, build_a) = (parse(a)?, parse_build(a)?);
        let (version_b, build_b) = (parse(b)?, parse_build(b)?);
        Some(compare_parsed(&version_a, &version_b).then_with(|| {
            match (build_a.is_empty(), build_b.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => compare_pre(&build_a, &build_b),
            }
        }))
    }

    fn parse_num(raw: &str) -> Option<u64> {
        if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        raw.parse().ok()
    }

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let (a, b) = (parse(a)?, parse(b)?);
        Some(compare_parsed(&a, &b))
    }

    pub fn compare_parsed(a: &Version, b: &Version) -> Ordering {
        a.major
            .cmp(&b.major)
            .then(a.minor.cmp(&b.minor))
            .then(a.patch.cmp(&b.patch))
            .then_with(|| {
                match (a.pre.is_empty(), b.pre.is_empty()) {
                    (true, true) => Ordering::Equal,
                    // A release outranks any of its own prereleases.
                    (true, false) => Ordering::Greater,
                    (false, true) => Ordering::Less,
                    (false, false) => compare_pre(&a.pre, &b.pre),
                }
            })
    }

    fn compare_pre(a: &[PreIdent], b: &[PreIdent]) -> Ordering {
        for (x, y) in a.iter().zip(b.iter()) {
            let ord = match (x, y) {
                (PreIdent::Num(m), PreIdent::Num(n)) => m.cmp(n),
                (PreIdent::Alpha(x), PreIdent::Alpha(y)) => x.cmp(y),
                // Numeric identifiers always have lower precedence.
                (PreIdent::Num(_), PreIdent::Alpha(_)) => Ordering::Less,
                (PreIdent::Alpha(_), PreIdent::Num(_)) => Ordering::Greater,
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        a.len().cmp(&b.len())
    }
}

pub mod pep440 {
    //! PEP 440 ordering: epochs, release segments (trailing zeros
    //! insignificant), `dev < pre < release < post`, local versions.

    use std::cmp::Ordering;

    #[derive(Debug, PartialEq, Eq)]
    pub struct Version {
        pub epoch: u64,
        pub release: Vec<u64>,
        /// (phase, number): a < b < rc.
        pub pre: Option<(u8, u64)>,
        pub post: Option<u64>,
        pub dev: Option<u64>,
        pub local: Vec<(bool, u64, String)>,
    }

    /// Pre-release spellings PEP 440 normalizes onto the canonical phases,
    /// ordered longest-first so `rc` is never read as the post marker `r`.
    const MARKERS: [(&str, MarkerKind); 12] = [
        ("preview", MarkerKind::Pre(2)),
        ("alpha", MarkerKind::Pre(0)),
        ("beta", MarkerKind::Pre(1)),
        ("post", MarkerKind::Post),
        ("pre", MarkerKind::Pre(2)),
        ("rev", MarkerKind::Post),
        ("dev", MarkerKind::Dev),
        ("rc", MarkerKind::Pre(2)),
        ("a", MarkerKind::Pre(0)),
        ("b", MarkerKind::Pre(1)),
        ("c", MarkerKind::Pre(2)),
        ("r", MarkerKind::Post),
    ];
    const SEPARATORS: [char; 3] = ['.', '-', '_'];

    #[derive(Clone, Copy)]
    enum MarkerKind {
        Pre(u8),
        Post,
        Dev,
    }

    /// Try every marker at the head of `candidate`, longest first, and return
    /// its kind, the digits that follow it, and the remainder.
    fn strip_marker(candidate: &str) -> Option<(MarkerKind, &str, &str)> {
        for (marker, kind) in MARKERS {
            if let Some(after) = candidate.strip_prefix(marker) {
                let digits_end = after
                    .char_indices()
                    .find(|(_, c)| !c.is_ascii_digit())
                    .map_or(after.len(), |(index, _)| index);
                let (digits, next) = after.split_at(digits_end);
                return Some((kind, digits, next));
            }
        }
        None
    }

    pub fn parse(raw: &str) -> Option<Version> {
        let s = raw
            .trim()
            .trim_start_matches(['v', 'V'])
            .to_ascii_lowercase();
        let (s, local) = match s.split_once('+') {
            Some((s, local)) => (s, Some(local)),
            None => (s.as_str(), None),
        };

        let (epoch, rest) = match s.split_once('!') {
            Some((epoch, rest)) => (epoch.parse().ok()?, rest),
            None => (0, s),
        };

        // Release digits run until the first marker; one separator directly
        // before a marker belongs to the marker, never to the release.
        let release_end = rest
            .char_indices()
            .find(|(_, c)| !c.is_ascii_digit() && *c != '.')
            .map_or(rest.len(), |(index, _)| index);
        // The separator directly before the first marker belongs to the
        // marker, so strip one from the release part — or `1.0.dev1` would
        // try to parse an empty release segment.
        let mut release_part = &rest[..release_end];
        for separator in SEPARATORS {
            if let Some(stripped) = release_part.strip_suffix(separator) {
                release_part = stripped;
                break;
            }
        }
        let mut release = Vec::new();
        for segment in release_part.split('.') {
            if segment.is_empty() {
                return None;
            }
            release.push(segment.parse().ok()?);
        }
        if release.is_empty() {
            return None;
        }

        let mut pre = None;
        let mut post = None;
        let mut dev = None;
        let mut tail = &rest[release_end..];
        while !tail.is_empty() {
            // One optional separator may sit directly before a marker.
            let candidate = SEPARATORS
                .iter()
                .find_map(|separator| tail.strip_prefix(*separator))
                .unwrap_or(tail);

            if let Some((kind, digits, next)) = strip_marker(candidate) {
                let number = if digits.is_empty() {
                    0
                } else {
                    digits.parse().ok()?
                };
                let slot_free = match kind {
                    MarkerKind::Pre(pre_phase) if pre.is_none() => {
                        pre = Some((pre_phase, number));
                        true
                    }
                    MarkerKind::Post if post.is_none() => {
                        post = Some(number);
                        true
                    }
                    MarkerKind::Dev if dev.is_none() => {
                        dev = Some(number);
                        true
                    }
                    _ => false,
                };
                if !slot_free {
                    // A version carrying the same marker twice is not a
                    // spelling PEP 440 normalizes; refuse it.
                    return None;
                }
                tail = next;
            } else {
                return None;
            }
        }

        let local = match local {
            Some(local) if !local.is_empty() => local
                .split('.')
                .map(|segment| {
                    if let Ok(n) = segment.parse::<u64>() {
                        Some((true, n, String::new()))
                    } else if segment.chars().all(|c| c.is_ascii_alphanumeric()) {
                        Some((false, 0, segment.to_string()))
                    } else {
                        None
                    }
                })
                .collect::<Option<Vec<_>>>()?,
            _ => Vec::new(),
        };

        Some(Version {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let (a, b) = (parse(a)?, parse(b)?);
        Some(compare_parsed(&a, &b))
    }

    /// PEP 440: trailing zero release segments are insignificant.
    fn release_trimmed(v: &[u64]) -> &[u64] {
        let end = v
            .iter()
            .rposition(|segment| *segment != 0)
            .map_or(0, |index| index + 1);
        &v[..end]
    }

    pub fn compare_parsed(a: &Version, b: &Version) -> Ordering {
        let trim = release_trimmed;
        // Pre/post/dev jointly: a dev-only version (no pre, no post) sorts
        // before pre-releases; a bare release sorts after them; no post sorts
        // before any post; a dev release sorts below the same version
        // without one.
        let pre_key = |v: &Version| -> (i8, u8, u64) {
            match v.pre {
                Some((phase, n)) => (0, phase, n),
                None if v.post.is_none() && v.dev.is_some() => (-1, 0, 0),
                None => (1, 0, 0),
            }
        };
        let post_key = |v: &Version| -> (i8, u64) {
            match v.post {
                None => (-1, 0),
                Some(n) => (0, n),
            }
        };
        let dev_key = |v: &Version| -> (i8, u64) {
            match v.dev {
                None => (1, 0),
                Some(n) => (0, n),
            }
        };
        a.epoch
            .cmp(&b.epoch)
            .then_with(|| trim(&a.release).cmp(trim(&b.release)))
            .then_with(|| pre_key(a).cmp(&pre_key(b)))
            .then_with(|| post_key(a).cmp(&post_key(b)))
            .then_with(|| dev_key(a).cmp(&dev_key(b)))
            .then_with(|| match (a.local.is_empty(), b.local.is_empty()) {
                (true, true) => Ordering::Equal,
                // A local version sorts above the bare release.
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => compare_local(&a.local, &b.local),
            })
    }

    fn compare_local(a: &[(bool, u64, String)], b: &[(bool, u64, String)]) -> Ordering {
        for (x, y) in a.iter().zip(b.iter()) {
            let ord = match (x, y) {
                ((true, m, _), (true, n, _)) => m.cmp(n),
                ((false, _, x), (false, _, y)) => x.cmp(y),
                // Numeric local segments sort above alphanumeric ones.
                ((true, _, _), (false, _, _)) => Ordering::Greater,
                ((false, _, _), (true, _, _)) => Ordering::Less,
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        a.len().cmp(&b.len())
    }
}

pub mod debian {
    //! Debian policy §5.6.12: `[epoch:]upstream[-revision]` compared part by
    //! part, where digits compare numerically, `~` sorts before everything
    //! (including the end of the part), letters sort before non-letters, and
    //! everything else compares by ASCII offset past the letters.

    use std::cmp::Ordering;

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let (ea, ua, ra) = split_version(a);
        let (eb, ub, rb) = split_version(b);
        Some(
            ea.cmp(&eb)
                .then_with(|| compare_fragment(ua, ub))
                .then_with(|| compare_fragment(ra, rb)),
        )
    }

    /// `[epoch:]upstream[-revision]` with absent parts as zero/empty.
    fn split_version(v: &str) -> (u64, &str, &str) {
        let (epoch, rest) = match v.split_once(':') {
            Some((epoch, rest)) => (epoch.parse().unwrap_or(0), rest),
            None => (0, v),
        };
        match rest.rsplit_once('-') {
            Some((upstream, revision)) => (epoch, upstream, revision),
            None => (epoch, rest, ""),
        }
    }

    fn fragment_order(c: Option<char>) -> i32 {
        match c {
            None => 0,
            Some('~') => -1,
            Some(c) if c.is_ascii_alphabetic() => c as i32,
            Some(c) => c as i32 + 256,
        }
    }

    fn compare_fragment(mut a: &str, mut b: &str) -> Ordering {
        loop {
            if a.is_empty() && b.is_empty() {
                return Ordering::Equal;
            }
            if a.starts_with(|c: char| c.is_ascii_digit())
                || b.starts_with(|c: char| c.is_ascii_digit())
            {
                let (num_a, rest_a) = take_number(a);
                let (num_b, rest_b) = take_number(b);
                if num_a != num_b {
                    return num_a.cmp(&num_b);
                }
                a = rest_a;
                b = rest_b;
                continue;
            }
            let (head_a, head_b) = (a.chars().next(), b.chars().next());
            let (ord_a, ord_b) = (fragment_order(head_a), fragment_order(head_b));
            if ord_a != ord_b {
                return ord_a.cmp(&ord_b);
            }
            if let Some(c) = head_a {
                a = &a[c.len_utf8()..];
            }
            if let Some(c) = head_b {
                b = &b[c.len_utf8()..];
            }
        }
    }

    fn take_number(fragment: &str) -> (u64, &str) {
        let digits_end = fragment
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(fragment.len());
        let digits = &fragment[..digits_end];
        let value = digits.trim_start_matches('0');
        let number = if value.is_empty() {
            0
        } else {
            value.parse().unwrap_or(u64::MAX)
        };
        (number, &fragment[digits_end..])
    }
}

pub mod maven {
    //! Maven version order, as the POM reference specifies it
    //! (<https://maven.apache.org/pom.html#Version_Order_Specification>) and
    //! `ComparableVersion` implements it — the model OSV's Maven ecosystem
    //! uses too:
    //!
    //! - the version is lowercased and split into tokens at `.`, `-` and every
    //!   transition between digits and non-digits (a transition acts as `-`);
    //!   each token remembers its separator, and an empty token is `0`;
    //! - `a`/`b`/`m` directly followed by a digit mean alpha/beta/milestone,
    //!   `cr` means `rc`, and `ga`/`final`/`release` mean the release (`""`);
    //! - trailing null tokens (`0`, the release) are trimmed from the end, and
    //!   again before each remaining `-` group;
    //! - tokens compare pairwise, the shorter side padded with a null (zero
    //!   against a number, the release against a qualifier). With the same
    //!   separator numbers compare numerically, a qualifier sits below a
    //!   number, and qualifiers order
    //!   `alpha < beta < milestone < rc = cr < snapshot < "" = ga = final =
    //!   release < sp < unknown`, unknown qualifiers lexically among
    //!   themselves. With different separators,
    //!   `.qualifier < -qualifier < -number < .number`.
    //!
    //! Unknown qualifiers — Guava's `-jre`/`-android`, Jetty's `.v20210629` —
    //! therefore order the way Maven orders them instead of being refused.

    use std::cmp::Ordering;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Separator {
        Dot,
        Hyphen,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Value {
        /// Digits without leading zeroes (`"0"` for zero), so numbers wider
        /// than any integer type still order by (length, digits).
        Number(String),
        /// Lowercased, with aliases folded onto their canonical spelling.
        Qualifier(String),
    }

    #[derive(Debug)]
    struct Token {
        separator: Separator,
        value: Value,
    }

    impl Token {
        fn is_null(&self) -> bool {
            match &self.value {
                Value::Number(digits) => digits == "0",
                Value::Qualifier(qualifier) => qualifier.is_empty(),
            }
        }
    }

    /// Known qualifiers in order; `""` is the release. Anything else ranks
    /// after all of them.
    const KNOWN_QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

    fn qualifier_rank(qualifier: &str) -> usize {
        KNOWN_QUALIFIERS
            .iter()
            .position(|known| *known == qualifier)
            .unwrap_or(KNOWN_QUALIFIERS.len())
    }

    fn compare_qualifiers(a: &str, b: &str) -> Ordering {
        // Equal known ranks are equal strings (aliases are already folded),
        // so the lexical tie-break only ever orders unknown qualifiers.
        qualifier_rank(a)
            .cmp(&qualifier_rank(b))
            .then_with(|| a.cmp(b))
    }

    fn compare_numbers(a: &str, b: &str) -> Ordering {
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }

    /// Order across different separators:
    /// `.qualifier < -qualifier < -number < .number`.
    fn kind_rank(token: &Token) -> u8 {
        match (token.separator, &token.value) {
            (Separator::Dot, Value::Qualifier(_)) => 0,
            (Separator::Hyphen, Value::Qualifier(_)) => 1,
            (Separator::Hyphen, Value::Number(_)) => 2,
            (Separator::Dot, Value::Number(_)) => 3,
        }
    }

    fn compare_tokens(a: &Token, b: &Token) -> Ordering {
        if a.separator != b.separator {
            return kind_rank(a).cmp(&kind_rank(b));
        }
        match (&a.value, &b.value) {
            (Value::Number(x), Value::Number(y)) => compare_numbers(x, y),
            (Value::Qualifier(x), Value::Qualifier(y)) => compare_qualifiers(x, y),
            (Value::Number(_), Value::Qualifier(_)) => Ordering::Greater,
            (Value::Qualifier(_), Value::Number(_)) => Ordering::Less,
        }
    }

    /// `token` against the null the shorter version is padded with: zero
    /// against a number, the release against a qualifier — so `1 < 1.1`,
    /// `1-snapshot < 1 < 1-sp`, and `1 < 1-jre`.
    fn compare_to_padding(token: &Token) -> Ordering {
        match &token.value {
            Value::Number(digits) => compare_numbers(digits, "0"),
            Value::Qualifier(qualifier) => compare_qualifiers(qualifier, ""),
        }
    }

    fn canonical_qualifier(qualifier: &str, followed_by_digit: bool) -> &str {
        match qualifier {
            "a" if followed_by_digit => "alpha",
            "b" if followed_by_digit => "beta",
            "m" if followed_by_digit => "milestone",
            "cr" => "rc",
            "ga" | "final" | "release" => "",
            other => other,
        }
    }

    /// Split one `.`/`-`-delimited segment at its digit/non-digit
    /// transitions; every piece after the first is `-`-separated.
    fn push_segment(tokens: &mut Vec<Token>, mut separator: Separator, segment: &str) {
        if segment.is_empty() {
            tokens.push(Token {
                separator,
                value: Value::Number("0".to_string()),
            });
            return;
        }
        // The caller admits only ASCII, so byte offsets are char boundaries.
        let bytes = segment.as_bytes();
        let mut start = 0;
        while start < bytes.len() {
            let digit = bytes[start].is_ascii_digit();
            let end = bytes[start..]
                .iter()
                .position(|byte| byte.is_ascii_digit() != digit)
                .map_or(bytes.len(), |offset| start + offset);
            let piece = &segment[start..end];
            let value = if digit {
                let trimmed = piece.trim_start_matches('0');
                Value::Number(if trimmed.is_empty() { "0" } else { trimmed }.to_string())
            } else {
                // A non-digit run that stops before the segment ends stops
                // at a digit.
                Value::Qualifier(canonical_qualifier(piece, end < bytes.len()).to_string())
            };
            tokens.push(Token { separator, value });
            separator = Separator::Hyphen;
            start = end;
        }
    }

    /// Trim trailing nulls from the end, then again before each remaining
    /// `-` group, walking from the end to the start. The first token stays.
    fn trim_nulls(tokens: &mut Vec<Token>) {
        let mut trimming = true;
        let mut index = tokens.len();
        while index > 1 {
            index -= 1;
            let starts_group = tokens[index].separator == Separator::Hyphen;
            if trimming && tokens[index].is_null() {
                tokens.remove(index);
            } else {
                trimming = false;
            }
            if starts_group {
                trimming = true;
            }
        }
    }

    fn parse(raw: &str) -> Option<Vec<Token>> {
        let version = raw.trim().to_ascii_lowercase();
        if version.is_empty() || !version.chars().all(|c| c.is_ascii_graphic()) {
            return None;
        }
        let mut tokens = Vec::new();
        let mut separator = Separator::Dot;
        let mut rest = version.as_str();
        loop {
            let end = rest.find(['.', '-']).unwrap_or(rest.len());
            push_segment(&mut tokens, separator, &rest[..end]);
            if end == rest.len() {
                break;
            }
            separator = if rest.as_bytes()[end] == b'.' {
                Separator::Dot
            } else {
                Separator::Hyphen
            };
            rest = &rest[end + 1..];
        }
        trim_nulls(&mut tokens);
        Some(tokens)
    }

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let (a, b) = (parse(a)?, parse(b)?);
        for index in 0..a.len().max(b.len()) {
            let ord = match (a.get(index), b.get(index)) {
                (Some(x), Some(y)) => compare_tokens(x, y),
                (Some(x), None) => compare_to_padding(x),
                (None, Some(y)) => compare_to_padding(y).reverse(),
                (None, None) => break,
            };
            if ord != Ordering::Equal {
                return Some(ord);
            }
        }
        Some(Ordering::Equal)
    }
}

pub mod gem {
    //! RubyGems `Gem::Version` ordering: dotted segments, numeric segments
    //! compare numerically, alphanumeric prerelease segments lexically below
    //! any number at the same position, trailing zero segments are
    //! insignificant.

    use std::cmp::Ordering;

    #[derive(Debug, PartialEq, Eq)]
    enum Segment {
        Num(u64),
        Str(String),
    }

    fn parse(raw: &str) -> Option<Vec<Segment>> {
        let s = raw.trim().trim_start_matches(['v', 'V']);
        let mut segments = Vec::new();
        for segment in s.split('.') {
            if segment.is_empty() {
                return None;
            }
            if let Ok(n) = segment.parse::<u64>() {
                segments.push(Segment::Num(n));
            } else if segment.chars().all(|c| c.is_ascii_alphanumeric()) {
                segments.push(Segment::Str(segment.to_ascii_lowercase()));
            } else {
                return None;
            }
        }
        if segments.is_empty() {
            return None;
        }
        Some(segments)
    }

    fn trim_trailing_zeroes(mut segments: Vec<Segment>) -> Vec<Segment> {
        while matches!(segments.last(), Some(Segment::Num(0))) {
            segments.pop();
        }
        segments
    }

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let (a, b) = (
            trim_trailing_zeroes(parse(a)?),
            trim_trailing_zeroes(parse(b)?),
        );
        for (x, y) in a.iter().zip(b.iter()) {
            let ord = match (x, y) {
                (Segment::Num(m), Segment::Num(n)) => m.cmp(n),
                (Segment::Str(x), Segment::Str(y)) => x.cmp(y),
                // Prerelease strings sort below numbers at the same position.
                (Segment::Num(_), Segment::Str(_)) => Ordering::Greater,
                (Segment::Str(_), Segment::Num(_)) => Ordering::Less,
            };
            if ord != Ordering::Equal {
                return Some(ord);
            }
        }
        // One version is a prefix of the other after zero-trimming. The
        // longer side's remaining segments decide: a string segment makes it
        // a prerelease of the shorter release (less); a positive number makes
        // it greater; further zeros keep looking.
        let (longer, a_is_longer) = if a.len() > b.len() {
            (&a, true)
        } else {
            (&b, false)
        };
        for segment in &longer[a.len().min(b.len())..] {
            match segment {
                Segment::Str(_) => {
                    return Some(if a_is_longer {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    })
                }
                Segment::Num(0) => {}
                Segment::Num(_) => {
                    return Some(if a_is_longer {
                        Ordering::Greater
                    } else {
                        Ordering::Less
                    })
                }
            }
        }
        Some(Ordering::Equal)
    }
}

pub mod loose {
    //! Dotted numeric versions with up to four release segments and an
    //! optional prerelease suffix — the concrete shape NuGet and Composer
    //! lockfiles pin. Comparison: numeric segments left to right, a release
    //! above its prereleases (semver rules for the suffix), then the fourth
    //! segment numerically.

    use std::cmp::Ordering;

    /// Release segments (major, minor, patch, revision) and an optional
    /// prerelease suffix string.
    struct Parsed {
        release: (u64, u64, u64, i64),
        pre: Option<String>,
    }

    fn parse(raw: &str) -> Option<Parsed> {
        let s = raw.trim().trim_start_matches(['v', 'V']);
        let (core, pre) = match s.split_once(['-', '+']) {
            Some((core, pre)) if s.contains('-') => {
                let pre = pre.split_once('+').map_or(pre, |(pre, _)| pre);
                (core, Some(pre.to_string()))
            }
            _ => (s.split_once('+').map_or(s, |(core, _)| core), None),
        };
        let mut numbers = core.split('.');
        let mut parts = [0u64, 0, 0];
        let mut revision = -1i64;
        for (index, slot) in parts.iter_mut().enumerate() {
            let token = match numbers.next() {
                Some(token) => token,
                None => {
                    if index == 0 {
                        return None;
                    }
                    break;
                }
            };
            if token.is_empty() || !token.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            *slot = token.parse().ok()?;
        }
        if let Some(token) = numbers.next() {
            if token.is_empty() || !token.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            revision = token.parse::<i64>().ok()?;
        }
        if numbers.next().is_some() {
            return None;
        }
        Some(Parsed {
            release: (parts[0], parts[1], parts[2], revision),
            pre,
        })
    }

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let parsed_a = parse(a)?;
        let parsed_b = parse(b)?;
        let (pa, sa) = (parsed_a.release, parsed_a.pre);
        let (pb, sb) = (parsed_b.release, parsed_b.pre);
        let pre_key = |pre: &Option<String>| match pre {
            None => (1u8, String::new()),
            Some(p) => (0u8, p.clone()),
        };
        Some(
            pa.0.cmp(&pb.0)
                .then(pa.1.cmp(&pb.1))
                .then(pa.2.cmp(&pb.2))
                .then(pre_key(&sa).cmp(&pre_key(&sb)))
                .then(pa.3.cmp(&pb.3)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    fn table(family: VersionFamily, pairs: &[(&str, &str, Ordering)]) {
        for (a, b, expected) in pairs {
            let got = compare(family, a, b);
            assert_eq!(
                got,
                Some(*expected),
                "{family:?}: {a:?} vs {b:?} expected {expected:?}"
            );
            let mirror = compare(family, b, a);
            assert_eq!(mirror, Some(expected.reverse()));
        }
    }

    fn unparseable(family: VersionFamily, versions: &[&str]) {
        for v in versions {
            assert_eq!(compare(family, v, "1.0.0"), None, "{family:?}: {v:?}");
        }
    }

    #[test]
    fn semver_ordering_follows_the_specification() {
        table(
            VersionFamily::SemVer,
            &[
                ("1.0.0", "2.0.0", Less),
                ("2.1.0", "2.0.9", Greater),
                ("1.0.0-alpha", "1.0.0", Less),
                ("1.0.0-alpha", "1.0.0-alpha.1", Less),
                ("1.0.0-alpha.1", "1.0.0-alpha.beta", Less),
                ("1.0.0-alpha.beta", "1.0.0-beta", Less),
                ("1.0.0-beta", "1.0.0-beta.2", Less),
                ("1.0.0-beta.2", "1.0.0-beta.11", Less),
                ("1.0.0-beta.11", "1.0.0-rc.1", Less),
                ("1.0.0-rc.1", "1.0.0", Less),
                ("1.0.0", "1.0.1", Less),
                // numeric identifiers sort below alphanumeric
                ("1.0.0-1", "1.0.0-alpha", Less),
                // leniency: leading v, missing segments, build metadata
                ("v1.2.3", "1.2.3", Equal),
                ("1.2", "1.2.0", Equal),
                ("1.2.3+build.5", "1.2.3", Equal),
                ("v1.2.3+incompatible", "1.2.3", Equal),
                // Go pseudo-versions are prerelease-shaped and order by them
                (
                    "v0.0.0-20180518173023-abc",
                    "v0.0.0-20190101111111-abc",
                    Less,
                ),
                ("v0.0.0-20180518173023-abc", "v0.1.0", Less),
            ],
        );
        unparseable(VersionFamily::SemVer, &["", "x.y.z", "1.2.3.4", "1..3"]);
    }

    #[test]
    fn pep440_ordering_follows_the_specification() {
        table(
            VersionFamily::Pep440,
            &[
                ("1.0", "1.0.0", Equal),
                ("1.0.1", "1.0", Greater),
                ("1.9", "1.10", Less),
                // epoch dominates
                ("1!1.0", "2.0", Greater),
                // dev < pre < release < post
                ("1.0.dev1", "1.0a1", Less),
                ("1.0a1", "1.0a2", Less),
                ("1.0a2", "1.0b1", Less),
                ("1.0b1", "1.0rc1", Less),
                ("1.0rc1", "1.0", Less),
                ("1.0", "1.0.post1", Less),
                ("1.0.post1", "1.1.dev1", Less),
                // alternate spellings normalize
                ("1.0alpha1", "1.0a1", Equal),
                ("1.0-beta2", "1.0b2", Equal),
                ("1.0-preview3", "1.0rc3", Equal),
                ("1.0rev4", "1.0.post4", Equal),
                ("v1.2.3", "1.2.3", Equal),
                // local sorts above the bare release
                ("1.0", "1.0+local", Less),
                ("1.0+local.1", "1.0+local.2", Less),
            ],
        );
        unparseable(VersionFamily::Pep440, &["", "abc", "1.0.x", "1.0!bad"]);
    }

    #[test]
    fn debian_ordering_follows_policy_5_6_12() {
        table(
            VersionFamily::Debian,
            &[
                ("1.0", "1.0.0", Less),
                ("1.0", "1.0~rc1", Greater),
                ("1.0~rc1", "1.0~rc2", Less),
                ("1.0~", "1.0", Less),
                // revision compares after upstream
                ("1.0-2", "1.0-10", Less),
                ("1.0-2", "1.1-1", Less),
                // epoch dominates
                ("1:0.9", "2.0", Greater),
                // letters sort before non-letters, so a letter tail loses
                // to a non-letter tail at the same position
                ("1.0beta", "1.0+", Less),
                ("1.0beta1", "1.0beta", Greater),
                // leading zeroes are insignificant
                ("1.02", "1.2", Equal),
                // the shapes dpkg/rpm/adbus emit
                ("1.2.3-r0", "1.2.3-r1", Less),
                ("1.2.3~upstream4", "1.2.3", Less),
            ],
        );
    }

    #[test]
    fn maven_ordering_follows_comparable_version() {
        table(
            VersionFamily::Maven,
            &[
                ("1.0", "1.0.1", Less),
                ("1.0.1", "1.0.2", Less),
                ("1.0", "2.0", Less),
                // qualifiers
                ("1.0-alpha1", "1.0-beta1", Less),
                ("1.0-beta1", "1.0-milestone1", Less),
                ("1.0-milestone1", "1.0-rc1", Less),
                ("1.0-rc1", "1.0-SNAPSHOT", Less),
                ("1.0-SNAPSHOT", "1.0", Less),
                ("1.0", "1.0-sp1", Less),
                // padding: missing segment is zero, missing qualifier is release
                ("1.0", "1.0.0.1", Less),
                ("1.0.0-alpha", "1.0", Less),
                ("1.0.0.0", "1.0", Equal),
                // case-insensitive qualifiers and numeric suffixes
                ("1.0-Alpha-1", "1.0-alpha-1", Equal),
                ("1.0-alpha-2", "1.0-alpha-10", Less),
            ],
        );
        unparseable(VersionFamily::Maven, &["", "   ", "1.0 beta"]);
    }

    #[test]
    fn maven_unknown_qualifiers_sort_after_known_ones_lexically() {
        table(
            VersionFamily::Maven,
            &[
                // Guava ships each release in -jre and -android flavours.
                ("32.1.3-jre", "32.1.3-android", Greater),
                ("31.1-jre", "32.0.0-android", Less),
                ("32.0.0-jre", "32.0.0-android", Greater),
                ("32.0.1-jre", "32.0.0-android", Greater),
                ("32.0.0-android", "32.0.1-android", Less),
                ("32.1.3-jre", "33.0.0-jre", Less),
                ("32.1.3-jre", "32.1.3-JRE", Equal),
                // Unknown qualifiers sit after every known one, `sp` and the
                // release included, and before a following number.
                ("1.0-sp1", "1.0-jre", Less),
                ("1.0", "1.0-jre", Less),
                ("1.0-jre", "1.0.1", Less),
                ("1.0-jre", "1.0-1", Less),
                ("1.0-LATEST", "1.0-omega", Less),
                // Jetty's v-dated versions.
                ("9.4.43.v20210629", "9.4.44.v20210927", Less),
                ("9.4.43.v20210629", "9.4.43.v20210630", Less),
                ("9.4.43", "9.4.43.v20210629", Less),
                ("9.4.43.v20210629", "9.4.44", Less),
                ("9.4.43.v20210629", "10.0.0", Less),
                // Release aliases and their trimming.
                ("5.3.18.RELEASE", "5.3.18", Equal),
                ("5.6.15.Final", "5.6.15", Equal),
                ("1.0-cr1", "1.0-rc1", Equal),
                // Examples from the Maven version order specification.
                ("1", "1.1", Less),
                ("1-snapshot", "1", Less),
                ("1", "1-sp", Less),
                ("1-foo2", "1-foo10", Less),
                ("1-foo", "1-1", Less),
                ("1-1", "1.1", Less),
                ("1.ga", "1", Equal),
                ("1-ga", "1", Equal),
                ("1-0", "1", Equal),
                ("1.0", "1", Equal),
                ("1-sp", "1-ga", Greater),
                ("1-sp.1", "1-ga.1", Greater),
                ("1-sp-1", "1-ga-1", Less),
                ("1-ga-1", "1-1", Equal),
                ("1-a1", "1-alpha-1", Equal),
                // A letter/digit transition is a hyphen, so the glued and
                // separated spellings agree and order by the number.
                ("1.0-alpha1", "1.0-alpha-1", Equal),
                ("1.0-alpha1", "1.0-alpha-2", Less),
                // Numbers wider than u64 still compare numerically.
                (
                    "1.99999999999999999999999",
                    "1.100000000000000000000000",
                    Less,
                ),
            ],
        );
    }

    #[test]
    fn gem_ordering_follows_gem_version() {
        table(
            VersionFamily::Gem,
            &[
                ("1.0", "1.0.0", Equal),
                ("1.0.1", "1.0", Greater),
                ("1.9", "1.10", Less),
                // prerelease segments sort below numbers
                ("1.0.0.rc1", "1.0.0", Less),
                ("1.0.a", "1.0.0", Less),
                ("1.0.a", "1.0.1", Less),
                ("1.0.rc1", "1.0.rc2", Less),
                ("1.0.rc2", "1.0.pre", Greater),
                // deeper prerelease chains keep ordering after the prefix
                ("1.0.a", "1.0.a.1", Less),
                ("1.0.0.beta.1", "1.0.0.beta.2", Less),
                ("v2.1.0", "2.1.0", Equal),
            ],
        );
        unparseable(VersionFamily::Gem, &["", "1.0-beta.1", "dev-main"]);
    }

    #[test]
    fn loose_ordering_handles_nuget_and_composer_pins() {
        table(
            VersionFamily::Loose,
            &[
                ("1.0.0", "1.0.0.1", Less),
                ("1.0.0.1", "1.0.1", Less),
                ("1.0.0.1", "1.0.0.2", Less),
                ("1.0.0-beta.1", "1.0.0", Less),
                ("1.0.0-beta.1", "1.0.0-beta.2", Less),
                ("1.0.0-beta.2", "1.0.0-rc", Less),
                ("1.0", "1.0.0", Equal),
                ("v1.2.3", "1.2.3", Equal),
                ("1.2.3+build", "1.2.3", Equal),
            ],
        );
        unparseable(VersionFamily::Loose, &["", "dev-main", "1.0.x"]);
    }

    #[test]
    fn family_selection_covers_range_types_and_ecosystems() {
        assert_eq!(family_for("SEMVER", "npm"), Some(VersionFamily::SemVer));
        assert_eq!(family_for("ECOSYSTEM", "PyPI"), Some(VersionFamily::Pep440));
        assert_eq!(family_for("ECOSYSTEM", "Maven"), Some(VersionFamily::Maven));
        assert_eq!(
            family_for("ECOSYSTEM", "RubyGems"),
            Some(VersionFamily::Gem)
        );
        assert_eq!(
            family_for("ECOSYSTEM", "Debian:12"),
            Some(VersionFamily::Debian)
        );
        assert_eq!(
            family_for("ECOSYSTEM", "Alpine:v3.20"),
            Some(VersionFamily::Debian)
        );
        assert_eq!(family_for("ECOSYSTEM", "NuGet"), Some(VersionFamily::Loose));
        assert_eq!(
            family_for("ECOSYSTEM", "Packagist"),
            Some(VersionFamily::Loose)
        );
        assert_eq!(family_for("GIT", "npm"), None);
    }

    #[test]
    fn hex_and_pub_have_comparators() {
        // Elixir's Version is SemVer 2.0 with build metadata ignored.
        assert_eq!(family_for("ECOSYSTEM", "Hex"), Some(VersionFamily::SemVer));
        // pub_semver orders build metadata, so it gets its own family.
        assert_eq!(family_for("ECOSYSTEM", "Pub"), Some(VersionFamily::Pub));
    }

    #[test]
    fn distro_ecosystems_map_only_where_a_comparator_fits() {
        // apk-versioned distributions share the Alpine comparator choice.
        for ecosystem in ["Wolfi", "Chainguard", "Alpine", "Alpine:v3.20"] {
            assert_eq!(
                family_for("ECOSYSTEM", ecosystem),
                Some(VersionFamily::Debian),
                "{ecosystem}"
            );
        }
        // dpkg comparison does not depend on the release, so the bare names
        // ELF package notes produce get the same comparator.
        for ecosystem in ["Debian", "Ubuntu", "Ubuntu:22.04:LTS"] {
            assert_eq!(
                family_for("ECOSYSTEM", ecosystem),
                Some(VersionFamily::Debian),
                "{ecosystem}"
            );
        }
        // RPM ordering (rpmvercmp) is not implemented, so RPM distributions
        // stay undetermined rather than borrowing a near-miss comparator.
        for ecosystem in [
            "Rocky Linux",
            "Rocky Linux:9",
            "AlmaLinux",
            "AlmaLinux:9",
            "Red Hat",
            "openSUSE",
            "SUSE",
            "Mageia",
            "Photon OS",
            // A prefix that merely starts like a known name is not it.
            "Debianish",
            "Wolfi:1",
        ] {
            assert_eq!(family_for("ECOSYSTEM", ecosystem), None, "{ecosystem}");
        }
    }

    #[test]
    fn pub_ordering_follows_pub_semver() {
        table(
            VersionFamily::Pub,
            &[
                ("1.0.0", "2.0.0", Less),
                ("1.0.0-dev.1", "1.0.0", Less),
                ("2.0.0-nullsafety.0", "2.0.0-nullsafety.1", Less),
                ("1.0.0-beta.2", "1.0.0-beta.11", Less),
                // Unlike SemVer 2.0, build metadata orders:
                // 1.0.0-pre < 1.0.0-pre+build < 1.0.0 < 1.0.0+build
                ("1.0.0-pre", "1.0.0-pre+build", Less),
                ("1.0.0-pre+build", "1.0.0", Less),
                ("1.0.0", "1.0.0+build", Less),
                ("1.0.0+1", "1.0.0+2", Less),
                ("1.0.0+2", "1.0.0+10", Less),
                ("1.0.0+1", "1.0.0+build", Less),
                ("1.0.0+build.1", "1.0.0+build.1.1", Less),
                ("1.0.0+build", "1.0.1", Less),
                ("1.0.0+build", "1.0.0+build", Equal),
            ],
        );
        unparseable(
            VersionFamily::Pub,
            &["", "x.y.z", "1.0.0+", "1.0.0+a..b", "1.0.0+a_b"],
        );
    }

    #[test]
    fn package_names_normalize_per_ecosystem_rules() {
        assert_eq!(normalize_package("PyPI", "Django"), "django");
        assert_eq!(
            normalize_package("PyPI", "zope.interface"),
            "zope-interface"
        );
        assert_eq!(normalize_package("PyPI", "Flask_Login"), "flask-login");
        assert_eq!(normalize_package("npm", "Lodash"), "lodash");
        assert_eq!(
            normalize_package("Maven", "org.apache.Commons"),
            "org.apache.Commons"
        );
    }

    /// The vectors the frontend mirror (src/features/dependencies/decisions.ts)
    /// also runs, so the two implementations cannot drift apart.
    #[test]
    fn shared_vectors_hold_for_the_frontend_mirror() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/version-ordering-vectors.json"
        ))
        .expect("version-ordering-vectors.json is valid JSON");
        let family_named = |name: &str| match name {
            "semver" => VersionFamily::SemVer,
            "pep440" => VersionFamily::Pep440,
            "debian" => VersionFamily::Debian,
            "maven" => VersionFamily::Maven,
            "gem" => VersionFamily::Gem,
            "loose" => VersionFamily::Loose,
            "pub" => VersionFamily::Pub,
            other => panic!("unknown family {other:?} in the shared vectors"),
        };

        let families = fixture["families"].as_array().expect("families array");
        assert!(!families.is_empty());
        for case in families {
            let range_type = case["rangeType"].as_str().expect("rangeType");
            let ecosystem = case["ecosystem"].as_str().expect("ecosystem");
            let expected = case["family"].as_str().map(family_named);
            assert_eq!(
                family_for(range_type, ecosystem),
                expected,
                "family_for({range_type:?}, {ecosystem:?})"
            );
        }

        let comparisons = fixture["comparisons"]
            .as_array()
            .expect("comparisons array");
        assert!(!comparisons.is_empty());
        for case in comparisons {
            let family = match (case["family"].as_str(), case["ecosystem"].as_str()) {
                (Some(name), None) => family_named(name),
                (None, Some(ecosystem)) => family_for("ECOSYSTEM", ecosystem)
                    .unwrap_or_else(|| panic!("{ecosystem:?} has no family")),
                _ => panic!("a comparison names exactly one of family/ecosystem: {case}"),
            };
            let a = case["a"].as_str().expect("a");
            let b = case["b"].as_str().expect("b");
            let expected = match &case["expected"] {
                serde_json::Value::Null => None,
                value => Some(
                    value
                        .as_i64()
                        .expect("expected is -1, 0, 1 or null")
                        .cmp(&0),
                ),
            };
            assert_eq!(
                compare(family, a, b),
                expected,
                "{family:?}: {a:?} vs {b:?}"
            );
            assert_eq!(
                compare(family, b, a),
                expected.map(Ordering::reverse),
                "{family:?}: {b:?} vs {a:?} (mirrored)"
            );
        }
    }
}
