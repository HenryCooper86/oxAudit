//! Values a scan target defines about itself.
//!
//! Some defects are only visible once configuration is read. A Java
//! application that writes
//!
//! ```java
//! String algorithm = props.getProperty("hashAlg", "SHA-512");
//! MessageDigest.getInstance(algorithm);
//! ```
//!
//! is using whatever `hashAlg` says, and the literal in the source is the
//! value that applies only when the key is *absent*. Reading the source alone
//! gets this exactly backwards whenever the configured value is the weak one —
//! which is how 40 of the OWASP Benchmark's hash cases are built, and how a
//! real application ends up shipping MD5 with SHA-512 written in the code.
//!
//! Only `.properties` files are read. They are the format whose semantics are
//! unambiguous — one flat key to one flat value — and the format Java
//! applications put algorithm names in. YAML and TOML nest, and deciding what
//! `getProperty("a.b")` means against a nested document is guesswork this does
//! not need to make.

use std::collections::BTreeMap;
use std::path::Path;

/// A key defined once has a value; a key two files disagree about has none.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Resolution {
    Single(String),
    /// `application-dev.properties` and `application-prod.properties` both
    /// define it and differ. Which one runs is a deployment decision, so the
    /// honest answer is that the value is not known.
    Conflicting,
}

/// Configuration keys the scan target defines, indexed across its own files.
#[derive(Debug, Default, Clone)]
pub struct ProjectConfig {
    properties: BTreeMap<String, Resolution>,
}

/// Past this a file is a data dump rather than configuration.
const MAX_PROPERTIES_BYTES: u64 = 512 * 1024;

/// Past this the index is being used as a database.
const MAX_KEYS: usize = 20_000;

impl ProjectConfig {
    /// Index every `.properties` file among the paths the scan already
    /// collected.
    ///
    /// Fed from the file list rather than a fresh directory walk, so the
    /// index sees exactly the files the scan sees and inherits its exclusions.
    pub fn from_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Self {
        let mut config = Self::default();
        for path in paths {
            if path
                .extension()
                .map(|ext| ext != "properties")
                .unwrap_or(true)
            {
                continue;
            }
            if std::fs::metadata(path).is_ok_and(|meta| meta.len() > MAX_PROPERTIES_BYTES) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            config.absorb(&text);
        }
        config
    }

    /// The value of `key`, when the target defines it exactly once.
    pub fn get(&self, key: &str) -> Option<&str> {
        match self.properties.get(key) {
            Some(Resolution::Single(value)) => Some(value),
            _ => None,
        }
    }

    /// Is anything indexed at all?
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }

    fn absorb(&mut self, text: &str) {
        for (key, value) in parse_properties(text) {
            if self.properties.len() >= MAX_KEYS && !self.properties.contains_key(&key) {
                return;
            }
            match self.properties.get(&key) {
                // The same value written twice is not a disagreement.
                Some(Resolution::Single(existing)) if *existing != value => {
                    self.properties.insert(key, Resolution::Conflicting);
                }
                Some(_) => {}
                None => {
                    self.properties.insert(key, Resolution::Single(value));
                }
            }
        }
    }
}

/// Split a `.properties` document into its key/value pairs.
///
/// `#` and `!` open a comment, `=` and `:` both separate, and a trailing
/// backslash continues onto the next line. Escapes inside the value are left
/// as written: an algorithm name has none, and unescaping would be inventing
/// a value the file did not contain.
fn parse_properties(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut continued = String::new();
    for raw in text.lines() {
        let line = if continued.is_empty() {
            let trimmed = raw.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
                continue;
            }
            trimmed
        } else {
            raw.trim_start()
        };
        // An odd number of trailing backslashes escapes the newline.
        let backslashes = line.chars().rev().take_while(|c| *c == '\\').count();
        if backslashes % 2 == 1 {
            continued.push_str(&line[..line.len() - 1]);
            continue;
        }
        let joined = if continued.is_empty() {
            line.to_string()
        } else {
            let mut whole = std::mem::take(&mut continued);
            whole.push_str(line);
            whole
        };
        let Some(split) = joined.find(['=', ':']) else {
            continue;
        };
        let key = joined[..split].trim();
        if key.is_empty() {
            continue;
        }
        pairs.push((key.to_string(), joined[split + 1..].trim().to_string()));
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indexed(text: &str) -> ProjectConfig {
        let mut config = ProjectConfig::default();
        config.absorb(text);
        config
    }

    #[test]
    fn a_key_defined_once_resolves() {
        let config = indexed("# a comment\nhashAlg1=MD5\nhashAlg2 : SHA-256\n");
        assert_eq!(config.get("hashAlg1"), Some("MD5"));
        assert_eq!(config.get("hashAlg2"), Some("SHA-256"));
        assert_eq!(config.get("absent"), None);
    }

    #[test]
    fn comments_and_blank_lines_define_nothing() {
        let config = indexed("\n# hashAlg1=MD5\n! hashAlg2=MD5\n\n");
        assert!(config.is_empty());
    }

    #[test]
    fn two_files_that_disagree_resolve_to_nothing() {
        let mut config = ProjectConfig::default();
        config.absorb("cipher=AES\n");
        config.absorb("cipher=DES\n");
        assert_eq!(
            config.get("cipher"),
            None,
            "which one runs is a deployment decision"
        );
    }

    #[test]
    fn the_same_value_written_twice_is_not_a_disagreement() {
        let mut config = ProjectConfig::default();
        config.absorb("cipher=AES\n");
        config.absorb("cipher=AES\n");
        assert_eq!(config.get("cipher"), Some("AES"));
    }

    #[test]
    fn a_continued_line_is_one_value() {
        let config = indexed("path=/very/long/\\\n  tail\n");
        assert_eq!(config.get("path"), Some("/very/long/tail"));
    }

    #[test]
    fn an_even_number_of_trailing_backslashes_does_not_continue() {
        let config = indexed("windows=C:\\\\\nnext=2\n");
        assert_eq!(config.get("windows"), Some(r"C:\\"));
        assert_eq!(config.get("next"), Some("2"));
    }

    #[test]
    fn a_line_with_no_separator_defines_nothing() {
        let config = indexed("justakey\n");
        assert!(config.is_empty());
    }
}
