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
//! comparator here. Callers treat `None` as *undetermined*, which keeps the
//! advisory (never silently drops it) and says so.

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
    /// rpm's `[epoch:]version[-release]` ordering (`rpmverCmp` over
    /// `rpmvercmp`), for the RPM-based distributions.
    Rpm,
    /// apk-tools' `apk_version_compare`, for Alpine and the apk-based
    /// distributions.
    Apk,
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
            // Distribution ecosystems name the distribution, optionally
            // followed by `:release` (`Debian:12`, `Alpine:v3.20`,
            // `Rocky Linux:9`, `Red Hat:enterprise_linux:9::appstream`). The
            // release never changes the version scheme, so only the name
            // before the first `:` decides, and the bare names ELF package
            // notes carry (`Debian`, no release) share it.
            other => distribution_family(other.split_once(':').map_or(other, |(name, _)| name)),
        },
        _ => None,
    }
}

/// The comparator a distribution's packages use, by the distribution name
/// OSV gives it. The RPM and apk lists follow OSV's own ecosystem table
/// (`osv/ecosystems/_ecosystems.py`), plus Photon OS, which builds with rpm
/// but which OSV lists without a comparator.
fn distribution_family(name: &str) -> Option<VersionFamily> {
    match name {
        "Debian" | "Ubuntu" => Some(VersionFamily::Debian),
        "Alpine"
        | "Alpaquita"
        | "BellSoft Hardened Containers"
        | "Chainguard"
        | "CleanStart"
        | "MinimOS"
        | "Wolfi" => Some(VersionFamily::Apk),
        "AlmaLinux" | "Azure Linux" | "Mageia" | "openEuler" | "openSUSE" | "Photon OS"
        | "Red Hat" | "Rocky Linux" | "SUSE" => Some(VersionFamily::Rpm),
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
        VersionFamily::Rpm => rpm::compare(a, b),
        VersionFamily::Apk => apk::compare(a, b),
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

pub mod rpm {
    //! rpm's version order, ported from rpm's `rpmio/rpmvercmp.cc`
    //! (`rpmvercmp`) and `rpmio/rpmver.cc` (`parseEVR`, `rpmverCmp`).
    //!
    //! A version is `[epoch:]version[-release]`. The epoch is the leading
    //! digits before a `:` and defaults to `0`; the release follows the `-`.
    //! Epoch, version and release compare in turn with `rpmvercmp`; a missing
    //! release sorts below any release, as `rpmverCmp` orders it (OSV's RPM
    //! comparator agrees). `rpmvercmp` walks both strings segment by segment:
    //!
    //! - any run of characters other than ASCII letters, digits, `~` and `^`
    //!   is a separator, and separators only delimit segments;
    //! - `~` sorts before everything, the end of the string included, so
    //!   `1.0~rc1 < 1.0`;
    //! - `^` sorts after the end of the string but before anything else, so
    //!   `1.0 < 1.0^git1 < 1.0.1`;
    //! - a segment is a run of digits or a run of letters; digits compare
    //!   numerically with leading zeros ignored (at any width), letters
    //!   compare as bytes, and a numeric segment is newer than an alphabetic
    //!   one;
    //! - when every segment matched, the side with characters left is newer.
    //!
    //! RPM versions are ASCII without whitespace, and rpm rejects `:` inside a
    //! version and `-` inside a version or release when it builds a package;
    //! a string outside that shape is refused rather than split one of the
    //! ways rpm and OSV disagree on.

    use std::cmp::Ordering;

    struct Evr<'a> {
        epoch: &'a str,
        version: &'a str,
        release: Option<&'a str>,
    }

    fn parse(raw: &str) -> Option<Evr<'_>> {
        if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_graphic()) {
            return None;
        }
        let digits_end = raw
            .bytes()
            .position(|byte| !byte.is_ascii_digit())
            .unwrap_or(raw.len());
        let (epoch, rest) = if raw.as_bytes().get(digits_end) == Some(&b':') {
            let epoch = &raw[..digits_end];
            (
                if epoch.is_empty() { "0" } else { epoch },
                &raw[digits_end + 1..],
            )
        } else {
            ("0", raw)
        };
        if rest.contains(':') {
            return None;
        }
        let (version, release) = match rest.split_once('-') {
            None => (rest, None),
            Some((_, release)) if release.is_empty() || release.contains('-') => return None,
            Some((version, release)) => (version, Some(release)),
        };
        if version.is_empty() {
            return None;
        }
        Some(Evr {
            epoch,
            version,
            release,
        })
    }

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let (a, b) = (parse(a)?, parse(b)?);
        Some(
            rpmvercmp(a.epoch, b.epoch)
                .then_with(|| rpmvercmp(a.version, b.version))
                .then_with(|| match (a.release, b.release) {
                    (Some(x), Some(y)) => rpmvercmp(x, y),
                    (Some(_), None) => Ordering::Greater,
                    (None, Some(_)) => Ordering::Less,
                    (None, None) => Ordering::Equal,
                }),
        )
    }

    fn is_separator(byte: u8) -> bool {
        !byte.is_ascii_alphanumeric() && byte != b'~' && byte != b'^'
    }

    /// `rpmvercmp`, step for step.
    pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
        if a == b {
            return Ordering::Equal;
        }
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let (mut one, mut two) = (0, 0);
        while one < a.len() || two < b.len() {
            while one < a.len() && is_separator(a[one]) {
                one += 1;
            }
            while two < b.len() && is_separator(b[two]) {
                two += 1;
            }
            let (head_a, head_b) = (a.get(one).copied(), b.get(two).copied());

            // The tilde sorts before everything else.
            if head_a == Some(b'~') || head_b == Some(b'~') {
                if head_a != Some(b'~') {
                    return Ordering::Greater;
                }
                if head_b != Some(b'~') {
                    return Ordering::Less;
                }
                one += 1;
                two += 1;
                continue;
            }

            // The caret is like the tilde, except that the end of the other
            // string (the base version) sorts below it.
            if head_a == Some(b'^') || head_b == Some(b'^') {
                if head_a.is_none() {
                    return Ordering::Less;
                }
                if head_b.is_none() {
                    return Ordering::Greater;
                }
                if head_a != Some(b'^') {
                    return Ordering::Greater;
                }
                if head_b != Some(b'^') {
                    return Ordering::Less;
                }
                one += 1;
                two += 1;
                continue;
            }

            if head_a.is_none() || head_b.is_none() {
                break;
            }

            // A completely numeric or completely alphabetic segment.
            let numeric = a[one].is_ascii_digit();
            let in_segment = |byte: &&u8| {
                if numeric {
                    byte.is_ascii_digit()
                } else {
                    byte.is_ascii_alphabetic()
                }
            };
            let end_a = one + a[one..].iter().take_while(in_segment).count();
            let end_b = two + b[two..].iter().take_while(in_segment).count();

            // Different segment types: numeric is newer than alphabetic.
            if end_b == two {
                return if numeric {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }

            let (mut segment_a, mut segment_b) = (&a[one..end_a], &b[two..end_b]);
            if numeric {
                while let [b'0', rest @ ..] = segment_a {
                    segment_a = rest;
                }
                while let [b'0', rest @ ..] = segment_b {
                    segment_b = rest;
                }
                // Whichever number has more digits wins.
                match segment_a.len().cmp(&segment_b.len()) {
                    Ordering::Equal => {}
                    order => return order,
                }
            }
            match segment_a.cmp(segment_b) {
                Ordering::Equal => {}
                order => return order,
            }
            one = end_a;
            two = end_b;
        }

        // Every segment compared equal; whichever side has characters left
        // (only the separators differed otherwise) is newer.
        match (one >= a.len(), two >= b.len()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, _) => Ordering::Greater,
        }
    }
}

pub mod apk {
    //! apk-tools' version order, ported from its `src/version.c`
    //! (`apk_version_validate`, `apk_version_compare`). The grammar is
    //! `digit{.digit}...{letter}{_suffix{#}}...{~hash}{-r#}`:
    //!
    //! - the version is a token stream — the initial number, further
    //!   `.`-separated numbers, at most one lowercase letter, any number of
    //!   `_suffix` tokens each optionally followed by a number, an optional
    //!   `~` commit hash (lowercase hex), and an optional `-rN` revision —
    //!   and a token may only follow the kinds before it in that list;
    //! - tokens compare pairwise while both sides have the same kind:
    //!   numbers numerically, except that a `.` number with a leading zero on
    //!   either side compares as a string (`8.2.0 < 8.2.001`); letters by
    //!   character; suffixes by rank
    //!   `alpha < beta < pre < rc < (none) < cvs < svn < git < hg < p`; the
    //!   commit hash as a string;
    //! - when the kinds diverge, a pre-release suffix (`alpha`, `beta`, `pre`,
    //!   `rc`) makes its side older — `1.2.3_rc1 < 1.2.3 < 1.2.3_p1` — and
    //!   otherwise the side whose next token comes earlier in the grammar is
    //!   newer, the end of the version coming last (`1.2.3 < 1.2.3-r0`,
    //!   `1.2.3a < 1.2.3.1`).
    //!
    //! apk orders invalid versions too, by where they stop parsing; this port
    //! refuses them instead, as OSV's APK comparator does. Numbers compare at
    //! any width rather than wrapping at 64 bits as apk's parser does.

    use std::cmp::Ordering;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Kind {
        InitialDigit,
        Digit,
        Letter,
        Suffix,
        SuffixNumber,
        CommitHash,
        Revision,
        End,
    }

    /// Suffixes in order; `""` is no suffix. Everything before it is a
    /// pre-release of the version it suffixes.
    const SUFFIXES: [&str; 10] = [
        "alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg", "p",
    ];
    const NO_SUFFIX: usize = 4;

    struct Token<'a> {
        kind: Kind,
        value: &'a str,
        suffix: usize,
    }

    /// The end of the run starting at `start` whose bytes `accept` admits.
    fn span(raw: &str, start: usize, accept: impl Fn(u8) -> bool) -> usize {
        start
            + raw.as_bytes()[start..]
                .iter()
                .take_while(|byte| accept(**byte))
                .count()
    }

    /// The token stream, or `None` when apk would reject the version.
    fn tokenize(raw: &str) -> Option<Vec<Token<'_>>> {
        let bytes = raw.as_bytes();
        let end = span(raw, 0, |byte| byte.is_ascii_digit());
        if end == 0 {
            return None;
        }
        let mut tokens = vec![Token {
            kind: Kind::InitialDigit,
            value: &raw[..end],
            suffix: NO_SUFFIX,
        }];
        let mut position = end;
        while position < bytes.len() {
            let last = tokens[tokens.len() - 1].kind;
            let (kind, start, end, suffix) = match bytes[position] {
                b'a'..=b'z' => {
                    if last > Kind::Digit {
                        return None;
                    }
                    (Kind::Letter, position, position + 1, NO_SUFFIX)
                }
                b'.' | b'0'..=b'9' => {
                    let start = if bytes[position] == b'.' {
                        if last > Kind::Digit {
                            return None;
                        }
                        position + 1
                    } else {
                        position
                    };
                    let kind = match last {
                        Kind::InitialDigit | Kind::Digit => Kind::Digit,
                        Kind::Suffix => Kind::SuffixNumber,
                        _ => return None,
                    };
                    let end = span(raw, start, |byte| byte.is_ascii_digit());
                    (kind, start, end, NO_SUFFIX)
                }
                b'_' => {
                    if last > Kind::SuffixNumber {
                        return None;
                    }
                    let start = position + 1;
                    let end = span(raw, start, |byte| byte.is_ascii_lowercase());
                    let name = &raw[start..end];
                    let suffix = SUFFIXES
                        .iter()
                        .position(|known| !known.is_empty() && *known == name)?;
                    (Kind::Suffix, start, end, suffix)
                }
                b'~' => {
                    if last >= Kind::CommitHash {
                        return None;
                    }
                    let start = position + 1;
                    let end = span(raw, start, |byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
                    (Kind::CommitHash, start, end, NO_SUFFIX)
                }
                b'-' => {
                    if last >= Kind::Revision || bytes.get(position + 1) != Some(&b'r') {
                        return None;
                    }
                    let start = position + 2;
                    let end = span(raw, start, |byte| byte.is_ascii_digit());
                    (Kind::Revision, start, end, NO_SUFFIX)
                }
                _ => return None,
            };
            // Every token but a suffix name (checked above) needs content.
            if end == start {
                return None;
            }
            tokens.push(Token {
                kind,
                value: &raw[start..end],
                suffix,
            });
            position = end;
        }
        Some(tokens)
    }

    /// Digit strings by numeric value, at any width.
    fn compare_numbers(a: &str, b: &str) -> Ordering {
        let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }

    /// Two tokens of the same kind.
    fn compare_tokens(a: &Token, b: &Token) -> Ordering {
        match a.kind {
            // A leading zero on either side makes it a string comparison,
            // as in Gentoo's version specification.
            Kind::Digit if a.value.starts_with('0') || b.value.starts_with('0') => {
                a.value.cmp(b.value)
            }
            Kind::InitialDigit | Kind::Digit | Kind::SuffixNumber | Kind::Revision => {
                compare_numbers(a.value, b.value)
            }
            Kind::Suffix => a.suffix.cmp(&b.suffix),
            Kind::Letter | Kind::CommitHash | Kind::End => a.value.cmp(b.value),
        }
    }

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let (a, b) = (tokenize(a)?, tokenize(b)?);
        let end = Token {
            kind: Kind::End,
            value: "",
            suffix: NO_SUFFIX,
        };
        let mut index = 0;
        let (next_a, next_b) = loop {
            let (x, y) = (a.get(index).unwrap_or(&end), b.get(index).unwrap_or(&end));
            if x.kind != y.kind || x.kind == Kind::End {
                break (x, y);
            }
            match compare_tokens(x, y) {
                Ordering::Equal => index += 1,
                order => return Some(order),
            }
        };
        if next_a.kind == next_b.kind {
            return Some(Ordering::Equal);
        }
        // The leading tokens are equal. The side that goes on is newer,
        // unless what it goes on with is a pre-release suffix.
        if next_a.kind == Kind::Suffix && next_a.suffix < NO_SUFFIX {
            return Some(Ordering::Less);
        }
        if next_b.kind == Kind::Suffix && next_b.suffix < NO_SUFFIX {
            return Some(Ordering::Greater);
        }
        Some(next_b.kind.cmp(&next_a.kind))
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
            Some(VersionFamily::Apk)
        );
        assert_eq!(
            family_for("ECOSYSTEM", "Rocky Linux:9"),
            Some(VersionFamily::Rpm)
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
        // The comparator follows the distribution's package manager, bare or
        // release-qualified, in the spellings OSV uses.
        let cases: [(VersionFamily, &[&str]); 3] = [
            (
                VersionFamily::Debian,
                &["Debian", "Debian:12", "Ubuntu", "Ubuntu:22.04:LTS"],
            ),
            (
                VersionFamily::Apk,
                &[
                    "Alpine",
                    "Alpine:v3.20",
                    "Wolfi",
                    "Chainguard",
                    "MinimOS",
                    "CleanStart",
                    "Alpaquita:23",
                    "BellSoft Hardened Containers:23",
                ],
            ),
            (
                VersionFamily::Rpm,
                &[
                    "Rocky Linux",
                    "Rocky Linux:9",
                    "AlmaLinux",
                    "AlmaLinux:9",
                    "Red Hat",
                    "Red Hat:enterprise_linux:9::appstream",
                    "SUSE",
                    "SUSE:Linux Enterprise Server 15 SP5",
                    "openSUSE",
                    "openSUSE:Leap 15.5",
                    "Mageia:9",
                    "Photon OS",
                    "Photon OS:5.0",
                    "Azure Linux:3",
                    "openEuler:22.03-LTS-SP4",
                ],
            ),
        ];
        for (family, ecosystems) in cases {
            for ecosystem in ecosystems {
                assert_eq!(
                    family_for("ECOSYSTEM", ecosystem),
                    Some(family),
                    "{ecosystem}"
                );
            }
        }
        for ecosystem in [
            // A name that merely starts like a known one is not it.
            "Debianish",
            "Rocky Linuxish",
            "Rocky Linux 9",
            "rocky linux",
            "Alpine3",
            // Schema ecosystems without a comparator, and Echo's own scheme.
            "Linux",
            "Android",
            "Echo",
            ":9",
            "",
        ] {
            assert_eq!(family_for("ECOSYSTEM", ecosystem), None, "{ecosystem}");
        }
    }

    #[test]
    fn rpm_ordering_follows_rpmvercmp() {
        table(
            VersionFamily::Rpm,
            &[
                // rpm's own suite, tests/rpmvercmp.at.
                ("1.0", "1.0", Equal),
                ("1.0", "2.0", Less),
                ("2.0", "2.0.1", Less),
                ("2.0.1a", "2.0.1", Greater),
                ("5.5p1", "5.5p2", Less),
                ("5.5p1", "5.5p10", Less),
                ("10xyz", "10.1xyz", Less),
                ("xyz10", "xyz10.1", Less),
                ("xyz.4", "8", Less),
                ("xyz.4", "2", Less),
                ("5.5p2", "5.6p1", Less),
                ("6.0.rc1", "6.0", Greater),
                ("10b2", "10a1", Greater),
                ("1.0a", "1.0aa", Less),
                ("10.0001", "10.1", Equal),
                ("10.0001", "10.0039", Less),
                ("4.999.9", "5.0", Less),
                ("20101121", "20101122", Less),
                ("2.0", "2_0", Equal),
                ("a+", "a_", Equal),
                ("+", "_", Equal),
                ("1.0~rc1", "1.0", Less),
                ("1.0~rc1", "1.0~rc2", Less),
                ("1.0~rc1~git123", "1.0~rc1", Less),
                ("1.0^", "1.0", Greater),
                ("1.0^git1", "1.0", Greater),
                ("1.0^git1", "1.0^git2", Less),
                ("1.0^git1", "1.01", Less),
                ("1.0^20160101", "1.0.1", Less),
                ("1.0^20160102", "1.0^20160101^git1", Greater),
                ("1.0~rc1^git1", "1.0~rc1", Greater),
                ("1.0^git1~pre", "1.0^git1", Less),
                // Epoch, then version, then release.
                ("1:1.0-1", "2.0-1", Greater),
                ("0:4.15-11.el9_8", "4.15-11.el9_8", Equal),
                ("00:1.0-1", "0:1.0-1", Equal),
                ("1.0-2", "1.0-10", Less),
                ("1.0-10", "1.1-1", Less),
                // A missing release sorts below any release (rpmverCmp).
                ("1.0", "1.0-1", Less),
                // Shapes from real OSV records: Red Hat and AlmaLinux module
                // builds, SUSE, openSUSE, Mageia and openEuler releases.
                (
                    "0:0.2.6-20.module+el8.9.0+1420+91577025",
                    "0:0.0.99.4-5.module+el8.9.0+1445+07728297",
                    Greater,
                ),
                (
                    "3:2.1.10-1.module_el8.10.0+3858+6ad51f9f",
                    "3:2.1.10-1.module_el8.10.0+3845+87b84552",
                    Greater,
                ),
                (
                    "20230404-117.git2e92a49f.el8_8.alma.1",
                    "20240111-121.gitb3132c18.el8",
                    Less,
                ),
                ("2.0.8_k4.12.14_10.118-4.8.2", "2.0.8-4.8.2", Greater),
                ("6.2.8-bp156.2.3.1", "6.2.8-bp156", Greater),
                ("3.2.7-1.2.mga9", "3.2.7-1.mga9", Greater),
                ("1:1.8.11-1.mga9", "0:1.9.1-2.mga9", Greater),
                ("1.10.2-1.oe2203", "1.2.2-1.oe2203", Greater),
                ("2.38.5-150400.4.34.2", "2.37.5-150400.4.34.2", Greater),
                // Digit runs compare at any width.
                (
                    "1.99999999999999999999999",
                    "1.100000000000000000000000",
                    Less,
                ),
            ],
        );
        unparseable(
            VersionFamily::Rpm,
            &[
                "", "1.0-", "-1", "1.0-1-1", "a:1.0", "1:2:3", "1.0 beta", "1.\u{e9}",
            ],
        );
    }

    #[test]
    fn apk_ordering_follows_apk_tools() {
        table(
            VersionFamily::Apk,
            &[
                // apk-tools' own suite, test/unit/version.data.
                ("0.1.0_alpha", "0.1.3_alpha", Less),
                ("0.1.0_alpha2", "0.1.0_alpha", Greater),
                ("1.1", "1.1_alpha1", Greater),
                ("0.8_beta1", "0.8_beta2", Less),
                ("3.1_p16", "3.1_p17", Less),
                ("4.5_p1-r1", "4.5_p1", Greater),
                ("2.9.11_pre20051101-r3", "2.9.11_pre20051101", Greater),
                ("1.6.8_p12-r1", "1.6.8_p9-r2", Greater),
                ("0.1.0_alpha_pre2", "0.1.0_alpha", Less),
                (
                    "1.0.0_pre20191002222144-r0",
                    "1.0.0_pre20210530193627-r0",
                    Less,
                ),
                ("6.0_pre1", "6.0", Less),
                ("6.0_p1", "6.0", Greater),
                ("8.2.0", "8.2.001", Less),
                ("8.2.0015", "8.2.002", Less),
                ("1.0~1234", "1.0~2345", Less),
                ("1.0~1234-r1", "1.0~2345-r0", Less),
                ("1.0~1234-r1", "1.0~1234-r0", Greater),
                ("4.5_p1", "0.9.8c-r1", Greater),
                // Suffix ranks: pre-releases below the release, the rest
                // above it.
                ("1.2.3_alpha", "1.2.3_beta", Less),
                ("1.2.3_beta", "1.2.3_pre", Less),
                ("1.2.3_pre", "1.2.3_rc", Less),
                ("1.2.3_rc1", "1.2.3", Less),
                ("1.2.3", "1.2.3_cvs", Less),
                ("1.2.3_cvs", "1.2.3_svn", Less),
                ("1.2.3_svn", "1.2.3_git", Less),
                ("1.2.3_git", "1.2.3_hg", Less),
                ("1.2.3_hg", "1.2.3_p", Less),
                // Real-world apk versions.
                ("1.2.5-r0", "1.2.5-r1", Less),
                ("3.0.13-r0", "3.0.9-r5", Greater),
                ("1.36.1-r29", "1.36.1-r3", Greater),
                ("2.40.1_rc1-r0", "2.40.1-r0", Less),
                ("2.40.1_rc1-r0", "2.40.0-r9", Greater),
                ("1.2.3_p20230101-r1", "1.2.3-r5", Greater),
                ("1.2.3_p20230101-r1", "1.2.4-r0", Less),
                ("0.9.3_git20231101-r0", "0.9.3-r0", Greater),
                ("0.9.3_git20231101-r0", "0.9.3_git20231201-r0", Less),
                ("1.2.3", "1.2.3-r0", Less),
                ("1.2.3a", "1.2.3.1", Less),
                ("1.2.3a", "1.2.3", Greater),
                ("1.3-r4", "1.3.1-r0", Less),
                (
                    "1.99999999999999999999999",
                    "1.100000000000000000000000",
                    Less,
                ),
            ],
        );
        // Invalid in apk-tools' suite, plus shapes apk never produces.
        unparseable(
            VersionFamily::Apk,
            &[
                "",
                "0.1bc",
                "0.1a1",
                "0.1_pre2~",
                "0.1_foobar",
                "0.1-pre1.1",
                "0.1-r",
                "0.1-r2_pre1",
                "0.1-r2-r3",
                ".1",
                "a",
                "0.1_",
                "0.1__alpha",
                "1.9.5p2",
                "v1.2.3",
                "1.2.3-1",
                "1.2.3_RC1",
            ],
        );
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
            "rpm" => VersionFamily::Rpm,
            "apk" => VersionFamily::Apk,
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
