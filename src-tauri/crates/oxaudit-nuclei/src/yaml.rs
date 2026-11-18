//! A small ordered YAML value, deserialised by `serde-saphyr` under strict
//! resource budgets, plus lookup helpers used by the loader.

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Yaml {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl<'de> Deserialize<'de> for Yaml {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Yaml;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any YAML value")
            }
            fn visit_unit<E>(self) -> Result<Yaml, E> {
                Ok(Yaml::Null)
            }
            fn visit_none<E>(self) -> Result<Yaml, E> {
                Ok(Yaml::Null)
            }
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Yaml, D2::Error> {
                Yaml::deserialize(d)
            }
            fn visit_bool<E>(self, v: bool) -> Result<Yaml, E> {
                Ok(Yaml::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Yaml, E> {
                Ok(Yaml::Int(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Yaml, E> {
                Ok(match i64::try_from(v) {
                    Ok(n) => Yaml::Int(n),
                    Err(_) => Yaml::Float(v as f64),
                })
            }
            fn visit_f64<E>(self, v: f64) -> Result<Yaml, E> {
                Ok(Yaml::Float(v))
            }
            fn visit_str<E>(self, v: &str) -> Result<Yaml, E> {
                Ok(Yaml::Str(v.to_string()))
            }
            fn visit_string<E>(self, v: String) -> Result<Yaml, E> {
                Ok(Yaml::Str(v))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Yaml, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<Yaml>()? {
                    items.push(item);
                }
                Ok(Yaml::Seq(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Yaml, A::Error> {
                let mut entries = Vec::new();
                while let Some((k, v)) = map.next_entry::<Yaml, Yaml>()? {
                    let key = k.scalar_text().unwrap_or_default();
                    entries.push((key, v));
                }
                Ok(Yaml::Map(entries))
            }
        }
        d.deserialize_any(V)
    }
}

/// Parses one YAML document under the loader's resource budgets.
pub(crate) fn parse_document(src: &str) -> Result<Yaml, String> {
    let options = serde_saphyr::options! {
        strict_booleans: true,
        ignore_binary_tag_for_string: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
        with_snippet: false,
        budget: serde_saphyr::budget! {
            max_depth: 48,
            max_documents: 1,
            max_nodes: 100_000,
            max_events: 400_000,
            max_anchors: 256,
            max_aliases: 256,
            max_recorded_anchor_events: 50_000,
            max_recorded_anchor_bytes: 1024 * 1024,
            max_total_scalar_bytes: 2 * 1024 * 1024,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: 50_000,
            max_replay_stack_depth: 16,
            max_alias_expansions_per_anchor: 64,
        },
    };
    serde_saphyr::from_str_with_options::<Yaml>(src, options).map_err(|e| e.to_string())
}

/// Hyphens and underscores are interchangeable in Nuclei field names
/// (`max-redirects`, `race_count`).
fn norm(key: &str) -> String {
    key.replace('_', "-").to_ascii_lowercase()
}

impl Yaml {
    pub fn scalar_text(&self) -> Option<String> {
        match self {
            Yaml::Str(s) => Some(s.clone()),
            Yaml::Int(n) => Some(n.to_string()),
            Yaml::Float(f) => Some(crate::dsl::format_float(*f)),
            Yaml::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(String, Yaml)]> {
        match self {
            Yaml::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Field lookup with hyphen/underscore tolerance. The first match wins.
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        let want = norm(key);
        self.as_map()?
            .iter()
            .find(|(k, _)| norm(k) == want)
            .map(|(_, v)| v)
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some_and(|v| !matches!(v, Yaml::Null))
    }

    pub fn string(&self, key: &str) -> Option<String> {
        self.get(key)?.scalar_text()
    }

    pub fn boolean(&self, key: &str) -> bool {
        match self.get(key) {
            Some(Yaml::Bool(b)) => *b,
            Some(Yaml::Str(s)) => s.eq_ignore_ascii_case("true"),
            _ => false,
        }
    }

    pub fn int(&self, key: &str) -> Option<i64> {
        match self.get(key)? {
            Yaml::Int(n) => Some(*n),
            Yaml::Float(f) if *f == f.trunc() => Some(*f as i64),
            Yaml::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn float(&self, key: &str) -> Option<f64> {
        match self.get(key)? {
            Yaml::Int(n) => Some(*n as f64),
            Yaml::Float(f) => Some(*f),
            Yaml::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    /// A string or list of strings, with comma-separated strings split.
    pub fn string_list(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Yaml::Seq(items)) => items
                .iter()
                .filter_map(Yaml::scalar_text)
                .flat_map(|s| split_commas(&s))
                .collect(),
            Some(other) => other
                .scalar_text()
                .map(|s| split_commas(&s))
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// A list of scalars exactly as written (no comma splitting). A single
    /// scalar is a one-element list.
    pub fn raw_list(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Yaml::Seq(items)) => items.iter().filter_map(Yaml::scalar_text).collect(),
            Some(other) => other.scalar_text().into_iter().collect(),
            None => Vec::new(),
        }
    }

    /// The elements of a field that should be a sequence of mappings.
    pub fn maps(&self, key: &str) -> Vec<&Yaml> {
        match self.get(key) {
            Some(Yaml::Seq(items)) => items.iter().filter(|i| i.as_map().is_some()).collect(),
            Some(m @ Yaml::Map(_)) => vec![m],
            _ => Vec::new(),
        }
    }
}

fn split_commas(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}
