//! Key-sorted JSON for hashing, independent of how `serde_json` is built.
//!
//! These helpers hash a `Value`, where sorting every object is exactly right.
//! For output that must match what releases produced, use [`crate::stable_json`],
//! which keeps struct field order.
//!
//! `serde_json::Map` is a sorted `BTreeMap` unless any crate in the build
//! enables the `preserve_order` feature (the `yara-x` dependency does, for the
//! whole workspace). Feature unification therefore decides whether a `Value`
//! iterates and serializes in key order or in insertion order. Anything that
//! hashes, signs, caches or byte-compares a serialized `Value` must go through
//! these helpers so the bytes are the same in every build and equal to what
//! releases built without `preserve_order` produced.

use serde_json::Value;
use std::collections::BTreeMap;

/// Rebuild `value` with every object, at any depth, in key order.
#[must_use]
pub fn sort_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> =
                map.into_iter().map(|(k, v)| (k, sort_keys(v))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

/// Compact serialization of `value` with every object in key order.
///
/// # Errors
/// Returns the serializer's message when `value` cannot be represented.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&sort_keys(value.clone())).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_serialize_in_key_order_at_every_depth() {
        let value: Value =
            serde_json::from_str(r#"{"z":1,"a":{"y":[{"d":1,"c":2}],"b":3}}"#).unwrap();
        assert_eq!(
            String::from_utf8(canonical_bytes(&value).unwrap()).unwrap(),
            r#"{"a":{"b":3,"y":[{"c":2,"d":1}]},"z":1}"#
        );
    }
}
