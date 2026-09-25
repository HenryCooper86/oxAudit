//! Local version comparison for advisory range evaluation.
//!
//! Online matching delegates to OSV's server, which owns ecosystem-correct
//! semantics. A local advisory database has no server, so this module carries
//! the comparison rules locally: one comparator per family, each derived from
//! the family's published specification, each lenient about the spellings real
//! lockfiles contain (leading `v`, missing patch segments, build metadata).
//!
//! A comparator returns `None` when it refuses to guess — an unparseable
//! version, or a construct the spec leaves to implementations (unknown Maven
//! qualifiers, `dev-` branch names). Callers treat `None` as *undetermined*,
//! which keeps the advisory (never silently drops it) and says so.

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
            "npm" | "crates.io" | "Go" => Some(VersionFamily::SemVer),
            "Packagist" | "NuGet" => Some(VersionFamily::Loose),
            other => {
                // Distro ecosystems (Debian:*, Ubuntu:*, Alpine:*) all use
                // epoch-based comparison over the same character rules.
                if other.starts_with("Debian:")
                    || other.starts_with("Ubuntu:")
                    || other.starts_with("Alpine:")
                {
                    Some(VersionFamily::Debian)
                } else {
                    None
                }
            }
        },
        _ => None,
    }
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
            Some(pre) if !pre.is_empty() => pre
                .split('.')
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
                .collect::<Option<Vec<_>>>()?,
            _ => Vec::new(),
        };
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
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
    //! Maven `ComparableVersion` ordering: tokens split on `.` and `-`, numeric
    //! tokens compared numerically, qualifiers by their documented ranks
    //! (alpha < beta < milestone < rc < snapshot < release < sp). Unknown
    //! qualifiers are refused rather than guessed.

    use std::cmp::Ordering;

    #[derive(Debug, PartialEq, Eq)]
    enum Item {
        Integer(u64),
        /// A qualifier and the number glued to it (`alpha1`, `RC4`).
        Qualifier(u8, u64),
    }

    /// Rank 0 pads a version that ends before the other side's qualifier —
    /// `1.0` still outranks `1.0-alpha`.
    const RELEASE_RANK: u8 = 6;

    /// Known qualifiers longest-first, so `alpha` is never read as `a`.
    const QUALIFIERS: [(&str, u8); 13] = [
        ("milestone", 3),
        ("snapshot", 5),
        ("release", RELEASE_RANK),
        ("alpha", 1),
        ("final", RELEASE_RANK),
        ("beta", 2),
        ("cr", 4),
        ("ga", RELEASE_RANK),
        ("sp", 7),
        ("rc", 4),
        ("a", 1),
        ("b", 2),
        ("m", 3),
    ];

    fn qualifier_rank(token: &str) -> Option<(u8, u64)> {
        let token = token.to_ascii_lowercase();
        for (qualifier, rank) in QUALIFIERS {
            if let Some(rest) = token.strip_prefix(qualifier) {
                let number = if rest.is_empty() {
                    0
                } else if rest.chars().all(|c| c.is_ascii_digit()) {
                    rest.parse().ok()?
                } else {
                    return None;
                };
                return Some((rank, number));
            }
        }
        None
    }

    fn tokenize(version: &str) -> Option<Vec<Item>> {
        let mut items = Vec::new();
        for token in version.split(['.', '-']) {
            if token.is_empty() {
                continue;
            }
            if let Ok(n) = token.parse::<u64>() {
                items.push(Item::Integer(n));
            } else {
                let (rank, number) = qualifier_rank(token)?;
                items.push(Item::Qualifier(rank, number));
            }
        }
        Some(items)
    }

    pub fn compare(a: &str, b: &str) -> Option<Ordering> {
        let (a, b) = (tokenize(a)?, tokenize(b)?);
        let mut ord = Ordering::Equal;
        for index in 0..a.len().max(b.len()) {
            ord = match (a.get(index), b.get(index)) {
                (Some(Item::Integer(x)), Some(Item::Integer(y))) => x.cmp(y),
                (Some(Item::Qualifier(x, xn)), Some(Item::Qualifier(y, yn))) => {
                    x.cmp(y).then(xn.cmp(yn))
                }
                (Some(Item::Integer(_)), Some(Item::Qualifier(_, _))) => {
                    // Maven compares an integer token above every qualifier
                    // token at the same position ("1.0.1" > "1.0-rc1").
                    Ordering::Greater
                }
                (Some(Item::Qualifier(_, _)), Some(Item::Integer(_))) => Ordering::Less,
                // A version that ran out of items is padded: with 0 when the
                // other side has an integer, with the release rank when it has
                // a qualifier.
                (None, Some(Item::Integer(y))) => 0u64.cmp(y),
                (None, Some(Item::Qualifier(y, yn))) => (RELEASE_RANK, 0u64).cmp(&(*y, *yn)),
                (Some(Item::Integer(x)), None) => x.cmp(&0),
                (Some(Item::Qualifier(x, xn)), None) => (*x, *xn).cmp(&(RELEASE_RANK, 0)),
                (None, None) => break,
            };
            if ord != Ordering::Equal {
                return Some(ord);
            }
        }
        Some(ord)
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
        // Unknown qualifiers are refused rather than guessed.
        unparseable(VersionFamily::Maven, &["1.0-omega", "1.0-LATEST"]);
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
        assert_eq!(family_for("ECOSYSTEM", "Wolfi"), None);
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
}
