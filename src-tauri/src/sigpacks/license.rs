//! Recognise a licence from the text of a `LICENSE`/`COPYING` file.
//!
//! This is a convenience that prefills the licence field at import, never a
//! legal determination: the user confirms or overrides the value. Detection
//! looks for characteristic phrases and returns `None` when nothing matches
//! rather than guessing.

/// File names (case-insensitive, with an optional text extension) that carry
/// a pack's licence.
pub(crate) fn is_license_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem = lower
        .strip_suffix(".md")
        .or_else(|| lower.strip_suffix(".txt"))
        .or_else(|| lower.strip_suffix(".rst"))
        .unwrap_or(&lower);
    matches!(stem, "license" | "licence" | "copying" | "unlicense")
}

fn normalize(text: &str) -> String {
    text.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The SPDX-style identifier of the recognised licence, or `None`.
pub fn detect_license(text: &str) -> Option<String> {
    let t = normalize(text);
    let has = |phrase: &str| t.contains(phrase);
    let id = if has("gnu affero general public license") {
        "AGPL-3.0"
    } else if has("gnu lesser general public license") {
        if has("version 2.1") {
            "LGPL-2.1"
        } else if has("version 3") {
            "LGPL-3.0"
        } else {
            "LGPL"
        }
    } else if has("gnu library general public license") {
        "LGPL-2.0"
    } else if has("gnu general public license") {
        if has("version 3") {
            "GPL-3.0"
        } else if has("version 2") {
            "GPL-2.0"
        } else {
            return None;
        }
    } else if has("mozilla public license") && has("version 2.0") {
        "MPL-2.0"
    } else if has("apache license") && has("version 2.0") {
        "Apache-2.0"
    } else if has("cc0 1.0 universal") {
        "CC0-1.0"
    } else if has("this is free and unencumbered software released into the public domain") {
        "Unlicense"
    } else if has("redistribution and use in source and binary forms") {
        if has("neither the name") {
            "BSD-3-Clause"
        } else if has("redistributions in binary form") {
            "BSD-2-Clause"
        } else {
            return None;
        }
    } else if has("permission is hereby granted, free of charge, to any person obtaining a copy") {
        "MIT"
    } else {
        return None;
    };
    Some(id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_each_family_by_characteristic_phrases() {
        let table: &[(&str, Option<&str>)] = &[
            (
                "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software",
                Some("MIT"),
            ),
            (
                "Apache License\n   Version 2.0, January 2004\n http://www.apache.org/licenses/",
                Some("Apache-2.0"),
            ),
            (
                "Redistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are met:\n1. Redistributions of source code\n2. Redistributions in binary form must reproduce",
                Some("BSD-2-Clause"),
            ),
            (
                "Redistribution and use in source and binary forms, with or without modification, are permitted\nRedistributions in binary form\nNeither the name of the copyright holder nor",
                Some("BSD-3-Clause"),
            ),
            (
                "GNU GENERAL PUBLIC LICENSE\n Version 2, June 1991",
                Some("GPL-2.0"),
            ),
            (
                "GNU GENERAL PUBLIC LICENSE\n Version 3, 29 June 2007",
                Some("GPL-3.0"),
            ),
            (
                "GNU AFFERO GENERAL PUBLIC LICENSE\n Version 3, 19 November 2007\n(GNU General Public License)",
                Some("AGPL-3.0"),
            ),
            (
                "GNU LESSER GENERAL PUBLIC LICENSE\n Version 3, 29 June 2007\nthe GNU General Public License",
                Some("LGPL-3.0"),
            ),
            (
                "GNU LESSER GENERAL PUBLIC LICENSE\n Version 2.1, February 1999",
                Some("LGPL-2.1"),
            ),
            (
                "Mozilla Public License Version 2.0\n==================================",
                Some("MPL-2.0"),
            ),
            ("CC0 1.0 Universal\n\nStatement of Purpose", Some("CC0-1.0")),
            (
                "This is free and unencumbered software released into the public domain.",
                Some("Unlicense"),
            ),
            ("Our own terms: do what you like but tell us.", None),
            ("", None),
        ];
        for (text, expected) in table {
            assert_eq!(
                detect_license(text).as_deref(),
                *expected,
                "text: {text:.50}"
            );
        }
    }

    #[test]
    fn licence_file_names() {
        for name in [
            "LICENSE",
            "License.md",
            "LICENCE.txt",
            "COPYING",
            "copying.txt",
        ] {
            assert!(is_license_file_name(name), "{name}");
        }
        for name in ["rules.yar", "license-notes.yar", "LICENSES"] {
            assert!(!is_license_file_name(name), "{name}");
        }
    }
}
