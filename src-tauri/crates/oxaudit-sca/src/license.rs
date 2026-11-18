//! Declared-license parsing and risk classification.
//!
//! A registry or lockfile states a license as an SPDX expression
//! (`MIT OR Apache-2.0`), a deprecated SPDX id (`GPL-2.0+`), or free text
//! (`Apache License, Version 2.0`). This module resolves what it can to SPDX
//! ids, keeps what it cannot as unknown, and sorts every license into a risk
//! category a policy can act on.
//!
//! Three rules hold throughout:
//!
//! - Nothing is guessed. Text that names a license family without a version
//!   (`BSD`, `GPL`) gets the family's category and no SPDX id. Text that
//!   matches nothing is unknown, never permissive.
//! - `A OR B` lets the licensee choose, so the least restrictive known
//!   operand is the effective category. `A AND B` binds to both, so the most
//!   restrictive one is.
//! - A category is a triage aid for engineers. It is not a legal opinion.

use serde::{Deserialize, Serialize};

/// Risk category of a license, ordered from least to most restrictive for
/// redistribution. `Unknown` sorts last: nothing is known about it.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum LicenseCategory {
    /// Public-domain dedications: no conditions.
    PublicDomain,
    /// Attribution-style licenses (MIT, BSD, Apache-2.0).
    Permissive,
    /// Copyleft limited to the licensed files or library (LGPL, MPL, EPL).
    WeakCopyleft,
    /// Copyleft that reaches the combined work when distributed (GPL).
    StrongCopyleft,
    /// Copyleft triggered by network use as well as distribution (AGPL).
    NetworkCopyleft,
    /// Source is published but use is restricted (SSPL, BUSL, Elastic).
    SourceAvailable,
    /// Commercial use is not granted (CC BY-NC, PolyForm Noncommercial).
    NonCommercial,
    /// Declared as proprietary, commercial or unlicensed.
    Proprietary,
    /// Undeclared, or declared in a form that could not be resolved.
    Unknown,
}

impl LicenseCategory {
    pub const ALL: [LicenseCategory; 9] = [
        Self::PublicDomain,
        Self::Permissive,
        Self::WeakCopyleft,
        Self::StrongCopyleft,
        Self::NetworkCopyleft,
        Self::SourceAvailable,
        Self::NonCommercial,
        Self::Proprietary,
        Self::Unknown,
    ];

    /// The name used in policy files (`category:strong-copyleft`) and JSON.
    pub fn slug(self) -> &'static str {
        match self {
            Self::PublicDomain => "public-domain",
            Self::Permissive => "permissive",
            Self::WeakCopyleft => "weak-copyleft",
            Self::StrongCopyleft => "strong-copyleft",
            Self::NetworkCopyleft => "network-copyleft",
            Self::SourceAvailable => "source-available",
            Self::NonCommercial => "non-commercial",
            Self::Proprietary => "proprietary",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.slug() == slug)
    }
}

use LicenseCategory::{
    NetworkCopyleft as Net, NonCommercial as Nc, Permissive as Perm, PublicDomain as Pd,
    SourceAvailable as Src, StrongCopyleft as Strong, WeakCopyleft as Weak,
};

/// SPDX license ids this build classifies. An id outside the table is
/// reported as unknown rather than assumed harmless.
const CATALOG: &[(&str, LicenseCategory)] = &[
    ("0BSD", Perm),
    ("AFL-2.1", Perm),
    ("AFL-3.0", Perm),
    ("AGPL-1.0-only", Net),
    ("AGPL-1.0-or-later", Net),
    ("AGPL-3.0-only", Net),
    ("AGPL-3.0-or-later", Net),
    ("APSL-2.0", Weak),
    ("Apache-1.1", Perm),
    ("Apache-2.0", Perm),
    ("Artistic-1.0", Perm),
    ("Artistic-1.0-Perl", Perm),
    ("Artistic-2.0", Perm),
    ("BSD-1-Clause", Perm),
    ("BSD-2-Clause", Perm),
    ("BSD-2-Clause-Patent", Perm),
    ("BSD-3-Clause", Perm),
    ("BSD-3-Clause-Clear", Perm),
    ("BSD-4-Clause", Perm),
    ("BSL-1.0", Perm),
    ("BUSL-1.1", Src),
    ("Beerware", Perm),
    ("BlueOak-1.0.0", Perm),
    ("CC-BY-3.0", Perm),
    ("CC-BY-4.0", Perm),
    ("CC-BY-NC-3.0", Nc),
    ("CC-BY-NC-4.0", Nc),
    ("CC-BY-NC-ND-3.0", Nc),
    ("CC-BY-NC-ND-4.0", Nc),
    ("CC-BY-NC-SA-3.0", Nc),
    ("CC-BY-NC-SA-4.0", Nc),
    ("CC-BY-ND-3.0", Src),
    ("CC-BY-ND-4.0", Src),
    ("CC-BY-SA-3.0", Strong),
    ("CC-BY-SA-4.0", Strong),
    ("CC-PDDC", Pd),
    ("CC0-1.0", Pd),
    ("CDDL-1.0", Weak),
    ("CDDL-1.1", Weak),
    ("CECILL-2.0", Strong),
    ("CECILL-2.1", Strong),
    ("CECILL-B", Perm),
    ("CECILL-C", Weak),
    ("CNRI-Python", Perm),
    ("CPAL-1.0", Net),
    ("CPL-1.0", Weak),
    ("ECL-2.0", Perm),
    ("EFL-2.0", Perm),
    ("EPL-1.0", Weak),
    ("EPL-2.0", Weak),
    ("EUPL-1.1", Strong),
    ("EUPL-1.2", Strong),
    ("Elastic-2.0", Src),
    ("FTL", Perm),
    ("GFDL-1.3-only", Strong),
    ("GFDL-1.3-or-later", Strong),
    ("GPL-1.0-only", Strong),
    ("GPL-1.0-or-later", Strong),
    ("GPL-2.0-only", Strong),
    ("GPL-2.0-or-later", Strong),
    ("GPL-3.0-only", Strong),
    ("GPL-3.0-or-later", Strong),
    ("HPND", Perm),
    ("ICU", Perm),
    ("IJG", Perm),
    ("IPL-1.0", Weak),
    ("ISC", Perm),
    ("JSON", Perm),
    ("LGPL-2.0-only", Weak),
    ("LGPL-2.0-or-later", Weak),
    ("LGPL-2.1-only", Weak),
    ("LGPL-2.1-or-later", Weak),
    ("LGPL-3.0-only", Weak),
    ("LGPL-3.0-or-later", Weak),
    ("MIT", Perm),
    ("MIT-0", Perm),
    ("MIT-CMU", Perm),
    ("MPL-1.0", Weak),
    ("MPL-1.1", Weak),
    ("MPL-2.0", Weak),
    ("MPL-2.0-no-copyleft-exception", Weak),
    ("MS-PL", Perm),
    ("MS-RL", Weak),
    ("MirOS", Perm),
    ("MulanPSL-2.0", Perm),
    ("NCSA", Perm),
    ("NTP", Perm),
    ("ODbL-1.0", Weak),
    ("OFL-1.1", Perm),
    ("OLDAP-2.8", Perm),
    ("OSL-3.0", Net),
    ("OpenSSL", Perm),
    ("PHP-3.0", Perm),
    ("PHP-3.01", Perm),
    ("PSF-2.0", Perm),
    ("PolyForm-Noncommercial-1.0.0", Nc),
    ("PolyForm-Small-Business-1.0.0", Src),
    ("PostgreSQL", Perm),
    ("Python-2.0", Perm),
    ("Python-2.0.1", Perm),
    ("QPL-1.0", Strong),
    ("RPL-1.5", Net),
    ("Ruby", Perm),
    ("SSPL-1.0", Src),
    ("Sleepycat", Strong),
    ("TCL", Perm),
    ("UPL-1.0", Perm),
    ("Unicode-3.0", Perm),
    ("Unicode-DFS-2015", Perm),
    ("Unicode-DFS-2016", Perm),
    ("Unlicense", Pd),
    ("Vim", Perm),
    ("W3C", Perm),
    ("W3C-20150513", Perm),
    ("WTFPL", Perm),
    ("X11", Perm),
    ("ZPL-2.1", Perm),
    ("Zend-2.0", Perm),
    ("Zlib", Perm),
    ("blessing", Pd),
    ("bzip2-1.0.6", Perm),
    ("curl", Perm),
    ("libpng", Perm),
    ("libpng-2.0", Perm),
    ("libtiff", Perm),
    ("zlib-acknowledgement", Perm),
];

/// Deprecated SPDX ids and the ids that replaced them.
const DEPRECATED: &[(&str, &str)] = &[
    ("AGPL-1.0", "AGPL-1.0-only"),
    ("AGPL-3.0", "AGPL-3.0-only"),
    ("GFDL-1.3", "GFDL-1.3-only"),
    ("GPL-1.0", "GPL-1.0-only"),
    ("GPL-2.0", "GPL-2.0-only"),
    ("GPL-3.0", "GPL-3.0-only"),
    ("LGPL-2.0", "LGPL-2.0-only"),
    ("LGPL-2.1", "LGPL-2.1-only"),
    ("LGPL-3.0", "LGPL-3.0-only"),
    ("BSD-2-Clause-FreeBSD", "BSD-2-Clause"),
    ("BSD-2-Clause-NetBSD", "BSD-2-Clause"),
];

/// SPDX exceptions that permit linking or combining without the copyleft
/// reaching the combined work. With one of these, a strong-copyleft license
/// is treated as weak copyleft.
const LINKING_EXCEPTIONS: &[&str] = &[
    "Autoconf-exception-2.0",
    "Autoconf-exception-3.0",
    "Bison-exception-2.2",
    "Classpath-exception-2.0",
    "Font-exception-2.0",
    "GCC-exception-2.0",
    "GCC-exception-3.1",
    "GPL-3.0-linking-exception",
    "LGPL-3.0-linking-exception",
    "LLVM-exception",
    "Libtool-exception",
    "Linux-syscall-note",
    "OCaml-LGPL-linking-exception",
    "Qt-LGPL-exception-1.1",
    "Universal-FOSS-exception-1.0",
    "WxWindows-exception-3.1",
    "u-boot-exception-2.0",
];

/// What a free-text license name resolves to.
#[derive(Clone, Copy)]
enum Alias {
    /// Exactly this SPDX id.
    Id(&'static str),
    /// A license family with no version stated: a category, no id.
    Family(LicenseCategory),
    /// A statement that no open license applies.
    Proprietary,
}

/// Free-text names seen in registry metadata, already normalized by
/// [`normalize_text`]: lower case, punctuation folded to spaces.
const ALIASES: &[(&str, Alias)] = &[
    ("mit", Alias::Id("MIT")),
    ("mit mit", Alias::Id("MIT")),
    ("expat", Alias::Id("MIT")),
    ("mit x11", Alias::Id("MIT")),
    ("apache", Alias::Family(Perm)),
    ("apache software", Alias::Family(Perm)),
    ("apache 2", Alias::Id("Apache-2.0")),
    ("apache 2.0", Alias::Id("Apache-2.0")),
    ("apache2", Alias::Id("Apache-2.0")),
    ("apache v2", Alias::Id("Apache-2.0")),
    ("apache v2.0", Alias::Id("Apache-2.0")),
    ("apache version 2.0", Alias::Id("Apache-2.0")),
    ("apache software version 2.0", Alias::Id("Apache-2.0")),
    ("apache software 2.0", Alias::Id("Apache-2.0")),
    ("asl 2.0", Alias::Id("Apache-2.0")),
    ("al 2.0", Alias::Id("Apache-2.0")),
    ("bsd", Alias::Family(Perm)),
    ("bsd 3", Alias::Id("BSD-3-Clause")),
    ("bsd 3 clause", Alias::Id("BSD-3-Clause")),
    ("3 clause bsd", Alias::Id("BSD-3-Clause")),
    ("new bsd", Alias::Id("BSD-3-Clause")),
    ("modified bsd", Alias::Id("BSD-3-Clause")),
    ("revised bsd", Alias::Id("BSD-3-Clause")),
    ("eclipse distribution v 1.0", Alias::Id("BSD-3-Clause")),
    ("edl 1.0", Alias::Id("BSD-3-Clause")),
    ("bsd 2", Alias::Id("BSD-2-Clause")),
    ("bsd 2 clause", Alias::Id("BSD-2-Clause")),
    ("2 clause bsd", Alias::Id("BSD-2-Clause")),
    ("simplified bsd", Alias::Id("BSD-2-Clause")),
    ("freebsd", Alias::Id("BSD-2-Clause")),
    ("isc iscl", Alias::Id("ISC")),
    ("gpl", Alias::Family(Strong)),
    ("gnu gpl", Alias::Family(Strong)),
    ("gnu general public", Alias::Family(Strong)),
    ("gnu general public gpl", Alias::Family(Strong)),
    ("gplv2", Alias::Id("GPL-2.0-only")),
    ("gpl v2", Alias::Id("GPL-2.0-only")),
    ("gpl 2", Alias::Id("GPL-2.0-only")),
    ("gnu gpl v2", Alias::Id("GPL-2.0-only")),
    ("gnu general public v2 gplv2", Alias::Id("GPL-2.0-only")),
    ("gplv2+", Alias::Id("GPL-2.0-or-later")),
    (
        "gnu general public v2 or later gplv2+",
        Alias::Id("GPL-2.0-or-later"),
    ),
    ("gplv3", Alias::Id("GPL-3.0-only")),
    ("gpl v3", Alias::Id("GPL-3.0-only")),
    ("gpl 3", Alias::Id("GPL-3.0-only")),
    ("gnu gpl v3", Alias::Id("GPL-3.0-only")),
    ("gnu general public v3", Alias::Id("GPL-3.0-only")),
    ("gnu general public v3.0", Alias::Id("GPL-3.0-only")),
    ("gnu general public v3 gplv3", Alias::Id("GPL-3.0-only")),
    ("gplv3+", Alias::Id("GPL-3.0-or-later")),
    (
        "gnu general public v3 or later gplv3+",
        Alias::Id("GPL-3.0-or-later"),
    ),
    ("lgpl", Alias::Family(Weak)),
    ("gnu lgpl", Alias::Family(Weak)),
    ("gnu lesser general public", Alias::Family(Weak)),
    (
        "gnu library or lesser general public lgpl",
        Alias::Family(Weak),
    ),
    ("lgplv2.1", Alias::Id("LGPL-2.1-only")),
    ("lgpl v2.1", Alias::Id("LGPL-2.1-only")),
    ("lgpl 2.1", Alias::Id("LGPL-2.1-only")),
    ("gnu lesser general public v2.1", Alias::Id("LGPL-2.1-only")),
    (
        "gnu lesser general public v2 or later lgplv2+",
        Alias::Id("LGPL-2.0-or-later"),
    ),
    ("lgplv3", Alias::Id("LGPL-3.0-only")),
    ("lgpl v3", Alias::Id("LGPL-3.0-only")),
    ("lgpl 3", Alias::Id("LGPL-3.0-only")),
    (
        "gnu lesser general public v3 lgplv3",
        Alias::Id("LGPL-3.0-only"),
    ),
    (
        "gnu lesser general public v3 or later lgplv3+",
        Alias::Id("LGPL-3.0-or-later"),
    ),
    ("agpl", Alias::Family(Net)),
    ("gnu affero general public", Alias::Family(Net)),
    ("agplv3", Alias::Id("AGPL-3.0-only")),
    ("agpl v3", Alias::Id("AGPL-3.0-only")),
    ("agpl 3", Alias::Id("AGPL-3.0-only")),
    ("gnu affero general public v3", Alias::Id("AGPL-3.0-only")),
    (
        "gnu affero general public v3 or later agplv3+",
        Alias::Id("AGPL-3.0-or-later"),
    ),
    ("mpl", Alias::Family(Weak)),
    ("mpl 2", Alias::Id("MPL-2.0")),
    ("mpl 2.0", Alias::Id("MPL-2.0")),
    ("mpl2", Alias::Id("MPL-2.0")),
    ("mozilla public 2.0", Alias::Id("MPL-2.0")),
    ("mozilla public version 2.0", Alias::Id("MPL-2.0")),
    ("mozilla public 2.0 mpl 2.0", Alias::Id("MPL-2.0")),
    ("mozilla public 1.1 mpl 1.1", Alias::Id("MPL-1.1")),
    ("epl", Alias::Family(Weak)),
    ("epl 1.0", Alias::Id("EPL-1.0")),
    ("eclipse public 1.0", Alias::Id("EPL-1.0")),
    ("eclipse public v 1.0", Alias::Id("EPL-1.0")),
    ("eclipse public v1.0", Alias::Id("EPL-1.0")),
    ("epl 2.0", Alias::Id("EPL-2.0")),
    ("eclipse public 2.0", Alias::Id("EPL-2.0")),
    ("eclipse public v 2.0", Alias::Id("EPL-2.0")),
    ("eclipse public v2.0", Alias::Id("EPL-2.0")),
    ("eclipse public 2.0 epl 2.0", Alias::Id("EPL-2.0")),
    ("cddl", Alias::Family(Weak)),
    ("cddl 1.0", Alias::Id("CDDL-1.0")),
    (
        "common development and distribution 1.0",
        Alias::Id("CDDL-1.0"),
    ),
    ("cddl 1.1", Alias::Id("CDDL-1.1")),
    ("public domain", Alias::Family(Pd)),
    ("unlicense unlicense", Alias::Id("Unlicense")),
    ("cc0", Alias::Id("CC0-1.0")),
    ("cc0 1.0 universal", Alias::Id("CC0-1.0")),
    (
        "cc0 1.0 universal cc0 1.0 public domain dedication",
        Alias::Id("CC0-1.0"),
    ),
    ("psf", Alias::Id("PSF-2.0")),
    ("psfl", Alias::Id("PSF-2.0")),
    ("python software foundation", Alias::Id("PSF-2.0")),
    ("zlib libpng", Alias::Id("Zlib")),
    ("boost", Alias::Id("BSL-1.0")),
    ("boost software 1.0", Alias::Id("BSL-1.0")),
    ("boost software 1.0 bsl 1.0", Alias::Id("BSL-1.0")),
    ("do what f*ck you want to public wtfpl", Alias::Id("WTFPL")),
    ("artistic", Alias::Family(Perm)),
    ("artistic 2.0", Alias::Id("Artistic-2.0")),
    (
        "historical permission notice and disclaimer hpnd",
        Alias::Id("HPND"),
    ),
    ("zope public", Alias::Id("ZPL-2.1")),
    ("university of illinois ncsa open source", Alias::Id("NCSA")),
    ("eupl 1.2", Alias::Id("EUPL-1.2")),
    ("european union public 1.2 eupl 1.2", Alias::Id("EUPL-1.2")),
    ("sil open font 1.1 ofl 1.1", Alias::Id("OFL-1.1")),
    ("unlicensed", Alias::Proprietary),
    ("proprietary", Alias::Proprietary),
    ("commercial", Alias::Proprietary),
    ("other proprietary", Alias::Proprietary),
    ("all rights reserved", Alias::Proprietary),
];

/// The longest declared license kept verbatim. Some registries put a whole
/// license text in the field; a report keeps the start of it.
pub const MAX_DECLARED_CHARS: usize = 160;
/// Operand cap for one expression, so a hostile field cannot build a deep tree.
const MAX_OPERANDS: usize = 64;

/// One license named by a declaration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LicenseTerm {
    /// The SPDX id, when the text resolved to exactly one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The text as declared, for terms that have no id.
    pub text: String,
    pub category: LicenseCategory,
    /// The SPDX exception joined with `WITH`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception: Option<String>,
}

impl LicenseTerm {
    /// How the term is written in a normalized expression.
    pub fn label(&self) -> String {
        let base = self.id.as_deref().unwrap_or(&self.text);
        match &self.exception {
            Some(exception) => format!("{base} WITH {exception}"),
            None => base.to_string(),
        }
    }
}

/// A parsed license declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expression {
    Term(LicenseTerm),
    And(Vec<Expression>),
    Or(Vec<Expression>),
}

impl Expression {
    /// Every term, left to right.
    pub fn terms(&self) -> Vec<&LicenseTerm> {
        match self {
            Self::Term(term) => vec![term],
            Self::And(parts) | Self::Or(parts) => parts.iter().flat_map(Self::terms).collect(),
        }
    }

    /// Fold the tree: `leaf` scores a term, `and`/`or` combine operand scores.
    pub fn fold<T>(
        &self,
        leaf: &impl Fn(&LicenseTerm) -> T,
        and: &impl Fn(Vec<T>) -> T,
        or: &impl Fn(Vec<T>) -> T,
    ) -> T {
        match self {
            Self::Term(term) => leaf(term),
            Self::And(parts) => and(parts.iter().map(|part| part.fold(leaf, and, or)).collect()),
            Self::Or(parts) => or(parts.iter().map(|part| part.fold(leaf, and, or)).collect()),
        }
    }

    fn render(&self, nested: bool) -> String {
        let join = |parts: &[Expression], operator: &str| {
            let text = parts
                .iter()
                .map(|part| part.render(true))
                .collect::<Vec<_>>()
                .join(operator);
            if nested {
                format!("({text})")
            } else {
                text
            }
        };
        match self {
            Self::Term(term) => term.label(),
            Self::And(parts) => join(parts, " AND "),
            Self::Or(parts) => join(parts, " OR "),
        }
    }
}

/// The classification of one component's declared license.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LicenseAssessment {
    /// The declaration as found, truncated to [`MAX_DECLARED_CHARS`].
    /// Absent when the component declared nothing or nothing was fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<String>,
    /// The declaration rewritten with resolved SPDX ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    /// The effective category after applying `OR` (licensee's choice) and
    /// `AND` (all apply).
    pub category: LicenseCategory,
    /// True when part of the declaration could not be resolved, so the
    /// category rests on the resolved part only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub incomplete: bool,
    pub terms: Vec<LicenseTerm>,
}

impl LicenseAssessment {
    /// The assessment of a component with no declared license.
    pub fn undeclared() -> Self {
        Self {
            declared: None,
            expression: None,
            category: LicenseCategory::Unknown,
            incomplete: false,
            terms: Vec::new(),
        }
    }
}

/// Classify a declared license. `None` or blank text is undeclared.
pub fn assess(declared: Option<&str>) -> LicenseAssessment {
    let Some(declared) = declared.map(str::trim).filter(|text| !text.is_empty()) else {
        return LicenseAssessment::undeclared();
    };
    let expression = parse(declared);
    let terms: Vec<LicenseTerm> = expression.terms().into_iter().cloned().collect();
    let incomplete = terms
        .iter()
        .any(|term| term.category == LicenseCategory::Unknown);
    LicenseAssessment {
        declared: Some(truncate(declared)),
        expression: Some(expression.render(false)),
        category: effective_category(&expression),
        incomplete,
        terms,
    }
}

/// The effective category: `OR` takes the least restrictive known operand,
/// `AND` the most restrictive known one. Unknown operands are skipped unless
/// every operand is unknown.
pub fn effective_category(expression: &Expression) -> LicenseCategory {
    let known = |scores: Vec<LicenseCategory>, pick_max: bool| {
        let known = scores
            .into_iter()
            .filter(|category| *category != LicenseCategory::Unknown);
        let picked = if pick_max { known.max() } else { known.min() };
        picked.unwrap_or(LicenseCategory::Unknown)
    };
    expression.fold(
        &|term| term.category,
        &|scores| known(scores, true),
        &|scores| known(scores, false),
    )
}

fn truncate(text: &str) -> String {
    if text.chars().count() <= MAX_DECLARED_CHARS {
        return text.to_string();
    }
    let mut kept: String = text.chars().take(MAX_DECLARED_CHARS).collect();
    kept.push('…');
    kept
}

/// Parse a declaration into an expression. Never fails: text that resolves
/// to nothing becomes a single unknown term.
pub fn parse(declared: &str) -> Expression {
    let declared = declared.trim();
    if let Some(term) = resolve_text(declared) {
        return Expression::Term(term);
    }
    if let Some(expression) = parse_spdx(declared) {
        return expression;
    }
    // Cargo's pre-SPDX form: `MIT/Apache-2.0` means either.
    if declared.contains('/') {
        let parts: Vec<&str> = declared.split('/').map(str::trim).collect();
        if parts.len() <= MAX_OPERANDS && parts.iter().all(|part| resolve_text(part).is_some()) {
            return Expression::Or(
                parts
                    .into_iter()
                    .filter_map(resolve_text)
                    .map(Expression::Term)
                    .collect(),
            );
        }
    }
    Expression::Term(unknown_term(declared))
}

fn unknown_term(text: &str) -> LicenseTerm {
    LicenseTerm {
        id: None,
        text: truncate(text),
        category: LicenseCategory::Unknown,
        exception: None,
    }
}

/// The canonical SPDX id for `token`, case-insensitively, mapping deprecated
/// ids and the `+` suffix to their current form.
pub fn canonical_id(token: &str) -> Option<&'static str> {
    let token = token.trim();
    let catalog = |wanted: &str| {
        CATALOG
            .iter()
            .map(|(id, _)| *id)
            .find(|id| id.eq_ignore_ascii_case(wanted))
    };
    let deprecated = |wanted: &str| {
        DEPRECATED
            .iter()
            .find(|(old, _)| old.eq_ignore_ascii_case(wanted))
            .map(|(_, current)| *current)
    };
    if let Some(base) = token.strip_suffix('+') {
        // `GPL-2.0+` is "or later"; for licenses without that form the plus
        // adds nothing a category depends on.
        let current = deprecated(base).or_else(|| catalog(base))?;
        return match current.strip_suffix("-only") {
            Some(stem) => catalog(&format!("{stem}-or-later")),
            None => Some(current),
        };
    }
    deprecated(token).or_else(|| catalog(token))
}

/// The category of a canonical SPDX id.
pub fn category_of(id: &str) -> Option<LicenseCategory> {
    CATALOG
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, category)| *category)
}

/// Whether `id` is an SPDX exception this build knows relaxes copyleft.
fn linking_exception(id: &str) -> Option<&'static str> {
    LINKING_EXCEPTIONS
        .iter()
        .copied()
        .find(|known| known.eq_ignore_ascii_case(id))
}

fn term_for_id(id: &'static str) -> LicenseTerm {
    LicenseTerm {
        id: Some(id.to_string()),
        text: id.to_string(),
        category: category_of(id).expect("canonical ids are in the catalog"),
        exception: None,
    }
}

/// Lower case, with punctuation and the words `the`/`license`/`licence`
/// folded away, so `The Apache Software License, Version 2.0` and
/// `Apache Software License 2.0` compare equal.
fn normalize_text(text: &str) -> String {
    let lowered = text.to_lowercase();
    let folded: String = lowered
        .chars()
        .map(|character| match character {
            ',' | '(' | ')' | '-' | '_' | '/' | ':' | ';' | '"' | '\'' => ' ',
            other => other,
        })
        .collect();
    folded
        .split_whitespace()
        .filter(|word| !matches!(*word, "the" | "license" | "licence" | "licenses"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Resolve a whole string as one license: an SPDX id, or a known free-text
/// name. `None` when it is neither.
fn resolve_text(text: &str) -> Option<LicenseTerm> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(id) = canonical_id(text) {
        return Some(term_for_id(id));
    }
    let normalized = normalize_text(text);
    let alias = ALIASES
        .iter()
        .find(|(name, _)| *name == normalized)
        .map(|(_, alias)| *alias)?;
    Some(match alias {
        Alias::Id(id) => term_for_id(id),
        Alias::Family(category) => LicenseTerm {
            id: None,
            text: truncate(text),
            category,
            exception: None,
        },
        Alias::Proprietary => LicenseTerm {
            id: None,
            text: truncate(text),
            category: LicenseCategory::Proprietary,
            exception: None,
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    And,
    Or,
    With,
    Word(String),
}

fn tokenize(text: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if word.is_empty() {
            return;
        }
        let token = match word.to_ascii_uppercase().as_str() {
            "AND" => Token::And,
            "OR" => Token::Or,
            "WITH" => Token::With,
            _ => Token::Word(std::mem::take(word)),
        };
        word.clear();
        tokens.push(token);
    };
    for character in text.chars() {
        match character {
            '(' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Open);
            }
            ')' => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Close);
            }
            character if character.is_whitespace() => flush(&mut word, &mut tokens),
            character => word.push(character),
        }
    }
    flush(&mut word, &mut tokens);
    tokens
}

/// Parse an SPDX expression. `None` when the text is not one: two words with
/// no operator between them, unbalanced parentheses, or too many operands.
/// A well-formed expression whose id is not in the catalog still parses; that
/// operand is an unknown term.
fn parse_spdx(text: &str) -> Option<Expression> {
    let tokens = tokenize(text);
    let words = tokens
        .iter()
        .filter(|token| matches!(token, Token::Word(_)))
        .count();
    if words == 0 || words > MAX_OPERANDS {
        return None;
    }
    // A single bare word that is not a known id is free text, not SPDX.
    if tokens.len() == 1 {
        return None;
    }
    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
    };
    let expression = parser.or()?;
    (parser.position == tokens.len()).then_some(expression)
}

struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn or(&mut self) -> Option<Expression> {
        let mut parts = vec![self.and()?];
        while self.peek() == Some(&Token::Or) {
            self.position += 1;
            parts.push(self.and()?);
        }
        Some(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Expression::Or(parts)
        })
    }

    fn and(&mut self) -> Option<Expression> {
        let mut parts = vec![self.atom()?];
        while self.peek() == Some(&Token::And) {
            self.position += 1;
            parts.push(self.atom()?);
        }
        Some(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Expression::And(parts)
        })
    }

    fn atom(&mut self) -> Option<Expression> {
        match self.peek()?.clone() {
            Token::Open => {
                self.position += 1;
                let inner = self.or()?;
                (self.peek() == Some(&Token::Close)).then(|| {
                    self.position += 1;
                    inner
                })
            }
            Token::Word(word) => {
                self.position += 1;
                let mut term = resolve_text(&word).unwrap_or_else(|| unknown_term(&word));
                if self.peek() == Some(&Token::With) {
                    self.position += 1;
                    let Some(Token::Word(exception)) = self.peek().cloned() else {
                        return None;
                    };
                    self.position += 1;
                    match linking_exception(&exception) {
                        Some(known) => {
                            if term.category == LicenseCategory::StrongCopyleft {
                                term.category = LicenseCategory::WeakCopyleft;
                            }
                            term.exception = Some(known.to_string());
                        }
                        // An exception this build does not know changes
                        // nothing: the base license's category stands.
                        None => term.exception = Some(exception),
                    }
                }
                Some(Expression::Term(term))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn category(declared: &str) -> LicenseCategory {
        assess(Some(declared)).category
    }

    #[test]
    fn the_catalog_has_no_duplicates_and_every_alias_target_exists() {
        let mut seen = std::collections::BTreeSet::new();
        for (id, _) in CATALOG {
            assert!(seen.insert(id.to_ascii_lowercase()), "duplicate id {id}");
        }
        for (old, current) in DEPRECATED {
            assert!(category_of(current).is_some(), "{old} -> {current}");
            assert!(category_of(old).is_none(), "{old} is listed as current");
        }
        let mut names = std::collections::BTreeSet::new();
        for (name, alias) in ALIASES {
            assert!(names.insert(*name), "duplicate alias {name}");
            assert_eq!(
                *name,
                normalize_text(name),
                "alias {name} is not normalized"
            );
            if let Alias::Id(id) = alias {
                assert!(category_of(id).is_some(), "alias {name} -> {id}");
            }
        }
    }

    #[test]
    fn spdx_ids_resolve_case_insensitively_and_deprecated_forms_map_forward() {
        assert_eq!(canonical_id("mit"), Some("MIT"));
        assert_eq!(canonical_id("GPL-2.0"), Some("GPL-2.0-only"));
        assert_eq!(canonical_id("GPL-2.0+"), Some("GPL-2.0-or-later"));
        assert_eq!(canonical_id("lgpl-2.1+"), Some("LGPL-2.1-or-later"));
        assert_eq!(canonical_id("Apache-2.0+"), Some("Apache-2.0"));
        assert_eq!(canonical_id("NotALicense"), None);
    }

    #[test]
    fn free_text_names_resolve_to_ids() {
        for (text, id) in [
            ("MIT License", "MIT"),
            ("The MIT License (MIT)", "MIT"),
            ("Apache License, Version 2.0", "Apache-2.0"),
            ("The Apache Software License, Version 2.0", "Apache-2.0"),
            ("Apache 2.0", "Apache-2.0"),
            ("BSD 3-Clause License", "BSD-3-Clause"),
            ("New BSD License", "BSD-3-Clause"),
            ("ISC License (ISCL)", "ISC"),
            ("Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0"),
            ("GNU General Public License v3 (GPLv3)", "GPL-3.0-only"),
            ("Eclipse Public License - v 2.0", "EPL-2.0"),
        ] {
            let assessment = assess(Some(text));
            assert_eq!(assessment.terms[0].id.as_deref(), Some(id), "{text}");
            assert!(!assessment.incomplete, "{text}");
        }
    }

    #[test]
    fn a_family_without_a_version_gets_a_category_and_no_id() {
        let assessment = assess(Some("BSD"));
        assert_eq!(assessment.category, LicenseCategory::Permissive);
        assert_eq!(assessment.terms[0].id, None);
        assert_eq!(category("GPL"), LicenseCategory::StrongCopyleft);
        assert_eq!(category("LGPL"), LicenseCategory::WeakCopyleft);
        assert_eq!(
            category("Apache Software License"),
            LicenseCategory::Permissive
        );
    }

    #[test]
    fn or_takes_the_least_restrictive_choice_and_and_the_most() {
        assert_eq!(category("MIT OR GPL-3.0-only"), LicenseCategory::Permissive);
        assert_eq!(
            category("MIT AND GPL-3.0-only"),
            LicenseCategory::StrongCopyleft
        );
        assert_eq!(
            category("(MIT OR Apache-2.0) AND AGPL-3.0-only"),
            LicenseCategory::NetworkCopyleft
        );
        assert_eq!(
            category("GPL-2.0-only OR (MIT AND LGPL-2.1-only)"),
            LicenseCategory::WeakCopyleft
        );
        assert_eq!(category("MIT/Apache-2.0"), LicenseCategory::Permissive);
        assert_eq!(
            assess(Some("mit or apache-2.0")).expression.as_deref(),
            Some("MIT OR Apache-2.0")
        );
    }

    #[test]
    fn a_linking_exception_relaxes_strong_copyleft_and_nothing_else() {
        let assessment = assess(Some("GPL-2.0-only WITH Classpath-exception-2.0"));
        assert_eq!(assessment.category, LicenseCategory::WeakCopyleft);
        assert_eq!(
            assessment.expression.as_deref(),
            Some("GPL-2.0-only WITH Classpath-exception-2.0")
        );
        assert_eq!(
            category("Apache-2.0 WITH LLVM-exception"),
            LicenseCategory::Permissive
        );
        assert_eq!(
            category("AGPL-3.0-only WITH Classpath-exception-2.0"),
            LicenseCategory::NetworkCopyleft
        );
        // An exception nobody recognises changes nothing.
        assert_eq!(
            category("GPL-3.0-only WITH Made-Up-exception"),
            LicenseCategory::StrongCopyleft
        );
    }

    #[test]
    fn unresolved_text_is_unknown_never_permissive() {
        assert_eq!(
            category("SEE LICENSE IN LICENSE.txt"),
            LicenseCategory::Unknown
        );
        assert_eq!(category("Custom"), LicenseCategory::Unknown);
        assert_eq!(assess(None).category, LicenseCategory::Unknown);
        assert_eq!(assess(Some("   ")).declared, None);
        assert_eq!(category("UNLICENSED"), LicenseCategory::Proprietary);
        assert_eq!(category("Proprietary"), LicenseCategory::Proprietary);
    }

    #[test]
    fn an_unknown_operand_marks_the_assessment_incomplete() {
        let either = assess(Some("MIT OR Weird-1.0"));
        assert_eq!(either.category, LicenseCategory::Permissive);
        assert!(either.incomplete);
        let both = assess(Some("MIT AND Weird-1.0"));
        assert_eq!(both.category, LicenseCategory::Permissive);
        assert!(both.incomplete);
        let neither = assess(Some("Weird-1.0 OR Odd-2.0"));
        assert_eq!(neither.category, LicenseCategory::Unknown);
    }

    #[test]
    fn malformed_expressions_and_long_texts_stay_bounded_and_unknown() {
        assert_eq!(category("MIT OR"), LicenseCategory::Unknown);
        assert_eq!(category("(MIT OR ISC"), LicenseCategory::Unknown);
        assert_eq!(category("MIT WITH"), LicenseCategory::Unknown);
        let text = "Permission is hereby granted ".repeat(40);
        let assessment = assess(Some(&text));
        assert_eq!(assessment.category, LicenseCategory::Unknown);
        assert!(assessment.declared.unwrap().chars().count() <= MAX_DECLARED_CHARS + 1);
        let many = vec!["MIT"; MAX_OPERANDS + 1].join(" OR ");
        assert_eq!(category(&many), LicenseCategory::Unknown);
    }

    #[test]
    fn category_slugs_round_trip() {
        for category in LicenseCategory::ALL {
            assert_eq!(LicenseCategory::from_slug(category.slug()), Some(category));
            assert_eq!(
                serde_json::to_value(category).unwrap(),
                serde_json::json!(category.slug())
            );
        }
    }
}
