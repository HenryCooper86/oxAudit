//! JSON output that is byte-identical to `serde_json` in a build WITHOUT the
//! `preserve_order` feature, whichever way the build was configured.
//!
//! `serde_json::Map` is a sorted `BTreeMap` unless some crate in the build
//! enables `preserve_order` (the `yara-x` dependency does, for the whole
//! workspace, through Cargo feature unification). Releases up to 0.3.3 were
//! built without it, so their output has these properties:
//!
//! * plain structs serialize their fields in declaration order;
//! * `serde_json::Map` / `Value::Object` (including every `json!` literal and
//!   every struct that was converted to a `Value`) serialize in key order;
//! * `BTreeMap` serializes in key order, `HashMap` in arbitrary order.
//!
//! [`to_vec`] and friends reproduce exactly that. Values are first serialized
//! into a small owned tree (structs keep field order, maps are key-sorted),
//! which `serde_json` then writes, so number, float and string formatting is
//! `serde_json`'s own, for compact and pretty output alike.
//!
//! Only maps whose keys are all strings are sorted (an integer-keyed
//! `BTreeMap` iterates numerically and keeps that order). A map is recognised by `serialize_map(Some(len))`. serde's `#[serde(flatten)]`
//! structs call `serialize_map(None)` and keep their field order, exactly as in
//! a build without `preserve_order`. Types that serialize their fields through
//! `serialize_map(Some(_))` with a meaningful non-sorted order (an `IndexMap`)
//! would be sorted; the workspace has none that reach an output.
//!
//! Internally tagged enums (`#[serde(tag = "...")]`, no `content`): serde
//! serializes a newtype variant through its private `TaggedSerializer`
//! (`serde::__private::ser::serialize_tagged_newtype`), which wraps the
//! serializer it is given and
//!
//! * for an inner **struct** calls `serialize_struct(name, len + 1)` and
//!   writes the tag as the first field, so the output is
//!   `{"tag":"Variant", <fields in declaration order>}`. This module produces
//!   exactly that.
//! * for an inner **map** (`BTreeMap`, `HashMap`, `serde_json::Map`,
//!   `Value::Object`) calls `serialize_map(len.map(|len| len + 1))` and writes
//!   the tag with `serialize_entry` as the first entry, then the map's own
//!   entries in its iteration order. `serde_json` without `preserve_order`
//!   writes `{"tag":"Variant", <entries in key order>}`: the tag stays first
//!   and is not sorted with the keys. At the `Serializer` interface that tag
//!   entry is indistinguishable from an ordinary first map entry (same calls,
//!   same `'static` key and value types, no newtype-variant hint), so this
//!   module cannot emulate it: it sorts the tag together with the map's keys
//!   and writes, for example, `{"a":1,"kind":"V","z":2}` where serde_json
//!   writes `{"kind":"V","a":1,"z":2}`. The output is still deterministic,
//!   but not byte-identical. No type in this workspace that reaches a
//!   `stable_json` output has such a variant (internally tagged enums here
//!   have unit and struct variants only, and every other tagged enum is
//!   adjacently tagged); give a new one a struct payload or adjacent tagging.
//!   The tests `internally_tagged_newtype_*` pin both cases.
//!
//! Known non-goals: `serde_json::value::RawValue` and the
//! `arbitrary_precision` number wrapper are not supported.

use serde::ser::{self, Impossible, Serialize};
use std::fmt;

/// Error raised while building the intermediate tree.
#[derive(Debug)]
struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self(message.to_string())
    }
}

fn key_must_be_a_string() -> Error {
    Error("key must be a string".to_owned())
}

/// Owned JSON tree that keeps struct field order.
enum Node {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    I128(i128),
    U128(u128),
    F32(f32),
    F64(f64),
    Str(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

impl Serialize for Node {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use ser::{SerializeMap, SerializeSeq};
        match self {
            Node::Null => serializer.serialize_unit(),
            Node::Bool(v) => serializer.serialize_bool(*v),
            Node::I64(v) => serializer.serialize_i64(*v),
            Node::U64(v) => serializer.serialize_u64(*v),
            Node::I128(v) => serializer.serialize_i128(*v),
            Node::U128(v) => serializer.serialize_u128(*v),
            Node::F32(v) => serializer.serialize_f32(*v),
            Node::F64(v) => serializer.serialize_f64(*v),
            Node::Str(v) => serializer.serialize_str(v),
            Node::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Node::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

struct TreeSerializer;

fn single(variant: &'static str, inner: Node) -> Node {
    Node::Object(vec![(variant.to_owned(), inner)])
}

impl ser::Serializer for TreeSerializer {
    type Ok = Node;
    type Error = Error;
    type SerializeSeq = SeqBuilder;
    type SerializeTuple = SeqBuilder;
    type SerializeTupleStruct = SeqBuilder;
    type SerializeTupleVariant = VariantSeqBuilder;
    type SerializeMap = MapBuilder;
    type SerializeStruct = StructBuilder;
    type SerializeStructVariant = VariantStructBuilder;

    fn serialize_bool(self, v: bool) -> Result<Node, Error> {
        Ok(Node::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Node, Error> {
        Ok(Node::I64(v.into()))
    }
    fn serialize_i16(self, v: i16) -> Result<Node, Error> {
        Ok(Node::I64(v.into()))
    }
    fn serialize_i32(self, v: i32) -> Result<Node, Error> {
        Ok(Node::I64(v.into()))
    }
    fn serialize_i64(self, v: i64) -> Result<Node, Error> {
        Ok(Node::I64(v))
    }
    fn serialize_i128(self, v: i128) -> Result<Node, Error> {
        Ok(Node::I128(v))
    }
    fn serialize_u8(self, v: u8) -> Result<Node, Error> {
        Ok(Node::U64(v.into()))
    }
    fn serialize_u16(self, v: u16) -> Result<Node, Error> {
        Ok(Node::U64(v.into()))
    }
    fn serialize_u32(self, v: u32) -> Result<Node, Error> {
        Ok(Node::U64(v.into()))
    }
    fn serialize_u64(self, v: u64) -> Result<Node, Error> {
        Ok(Node::U64(v))
    }
    fn serialize_u128(self, v: u128) -> Result<Node, Error> {
        Ok(Node::U128(v))
    }
    fn serialize_f32(self, v: f32) -> Result<Node, Error> {
        Ok(Node::F32(v))
    }
    fn serialize_f64(self, v: f64) -> Result<Node, Error> {
        Ok(Node::F64(v))
    }
    fn serialize_char(self, v: char) -> Result<Node, Error> {
        Ok(Node::Str(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Node, Error> {
        Ok(Node::Str(v.to_owned()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Node, Error> {
        Ok(Node::Array(
            v.iter().map(|byte| Node::U64(u64::from(*byte))).collect(),
        ))
    }
    fn serialize_none(self) -> Result<Node, Error> {
        Ok(Node::Null)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Node, Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Node, Error> {
        Ok(Node::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Node, Error> {
        Ok(Node::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Node, Error> {
        Ok(Node::Str(variant.to_owned()))
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Node, Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Node, Error> {
        Ok(single(variant, value.serialize(TreeSerializer)?))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SeqBuilder, Error> {
        Ok(SeqBuilder(Vec::with_capacity(len.unwrap_or(0))))
    }
    fn serialize_tuple(self, len: usize) -> Result<SeqBuilder, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SeqBuilder, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantSeqBuilder, Error> {
        Ok(VariantSeqBuilder {
            variant,
            items: Vec::with_capacity(len),
        })
    }
    fn serialize_map(self, len: Option<usize>) -> Result<MapBuilder, Error> {
        Ok(MapBuilder {
            entries: Vec::with_capacity(len.unwrap_or(0)),
            // `Some(len)`: a real map (sorted in a build without
            // `preserve_order`). `None`: a `#[serde(flatten)]` struct, whose
            // fields keep their declaration order.
            sort: len.is_some(),
            all_string_keys: true,
            pending_key: None,
        })
    }
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<StructBuilder, Error> {
        Ok(StructBuilder(Vec::with_capacity(len)))
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<VariantStructBuilder, Error> {
        Ok(VariantStructBuilder {
            variant,
            fields: Vec::with_capacity(len),
        })
    }
}

struct SeqBuilder(Vec<Node>);

impl SeqBuilder {
    fn push<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        self.0.push(value.serialize(TreeSerializer)?);
        Ok(())
    }
}

impl ser::SerializeSeq for SeqBuilder {
    type Ok = Node;
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(Node::Array(self.0))
    }
}

impl ser::SerializeTuple for SeqBuilder {
    type Ok = Node;
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(Node::Array(self.0))
    }
}

impl ser::SerializeTupleStruct for SeqBuilder {
    type Ok = Node;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<Node, Error> {
        Ok(Node::Array(self.0))
    }
}

struct VariantSeqBuilder {
    variant: &'static str,
    items: Vec<Node>,
}

impl ser::SerializeTupleVariant for VariantSeqBuilder {
    type Ok = Node;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        self.items.push(value.serialize(TreeSerializer)?);
        Ok(())
    }
    fn end(self) -> Result<Node, Error> {
        Ok(single(self.variant, Node::Array(self.items)))
    }
}

struct MapBuilder {
    entries: Vec<(String, Node)>,
    sort: bool,
    /// False once any key was not a plain string (an integer-keyed
    /// `BTreeMap` iterates numerically, not by key text, and keeps that order).
    all_string_keys: bool,
    pending_key: Option<String>,
}

impl ser::SerializeMap for MapBuilder {
    type Ok = Node;
    type Error = Error;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Error> {
        let mut probe = KeySerializer { saw_str: false };
        let text = key.serialize(&mut probe)?;
        self.all_string_keys &= probe.saw_str;
        self.pending_key = Some(text);
        Ok(())
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        let key = self
            .pending_key
            .take()
            .ok_or_else(|| Error("serialize_value called before serialize_key".to_owned()))?;
        self.entries.push((key, value.serialize(TreeSerializer)?));
        Ok(())
    }
    fn end(mut self) -> Result<Node, Error> {
        if self.sort && self.all_string_keys {
            // Byte order of the UTF-8 key, as a `BTreeMap<String, _>` iterates.
            self.entries.sort_by(|a, b| a.0.cmp(&b.0));
        }
        Ok(Node::Object(self.entries))
    }
}

struct StructBuilder(Vec<(String, Node)>);

impl ser::SerializeStruct for StructBuilder {
    type Ok = Node;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.0
            .push((key.to_owned(), value.serialize(TreeSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<Node, Error> {
        Ok(Node::Object(self.0))
    }
}

struct VariantStructBuilder {
    variant: &'static str,
    fields: Vec<(String, Node)>,
}

impl ser::SerializeStructVariant for VariantStructBuilder {
    type Ok = Node;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.fields
            .push((key.to_owned(), value.serialize(TreeSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<Node, Error> {
        Ok(single(self.variant, Node::Object(self.fields)))
    }
}

/// Map keys follow `serde_json`'s own stringification rules.
struct KeySerializer {
    saw_str: bool,
}

fn float_key<T: Serialize + Copy>(value: T, finite: bool) -> Result<String, Error> {
    if !finite {
        return Err(Error("float key must be finite".to_owned()));
    }
    serde_json::to_string(&value).map_err(|error| Error(error.to_string()))
}

impl ser::Serializer for &mut KeySerializer {
    type Ok = String;
    type Error = Error;
    type SerializeSeq = Impossible<String, Error>;
    type SerializeTuple = Impossible<String, Error>;
    type SerializeTupleStruct = Impossible<String, Error>;
    type SerializeTupleVariant = Impossible<String, Error>;
    type SerializeMap = Impossible<String, Error>;
    type SerializeStruct = Impossible<String, Error>;
    type SerializeStructVariant = Impossible<String, Error>;

    fn serialize_bool(self, v: bool) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_i8(self, v: i8) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_i16(self, v: i16) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_i32(self, v: i32) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_i64(self, v: i64) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_i128(self, v: i128) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_u8(self, v: u8) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_u16(self, v: u16) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_u32(self, v: u32) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_u64(self, v: u64) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_u128(self, v: u128) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_f32(self, v: f32) -> Result<String, Error> {
        float_key(v, v.is_finite())
    }
    fn serialize_f64(self, v: f64) -> Result<String, Error> {
        float_key(v, v.is_finite())
    }
    fn serialize_char(self, v: char) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_str(self, v: &str) -> Result<String, Error> {
        self.saw_str = true;
        Ok(v.to_owned())
    }
    fn serialize_bytes(self, _v: &[u8]) -> Result<String, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_none(self) -> Result<String, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<String, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_unit(self) -> Result<String, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<String, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<String, Error> {
        Ok(variant.to_owned())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<String, Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Err(key_must_be_a_string())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(key_must_be_a_string())
    }
}

fn tree<T: ?Sized + Serialize>(value: &T) -> serde_json::Result<Node> {
    value
        .serialize(TreeSerializer)
        .map_err(<serde_json::Error as ser::Error>::custom)
}

/// Compact JSON, byte-identical to `serde_json::to_vec` in a build without
/// `preserve_order`.
///
/// # Errors
/// Returns the serializer's error when `value` cannot be represented.
pub fn to_vec<T: ?Sized + Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(&tree(value)?)
}

/// Pretty JSON, byte-identical to `serde_json::to_vec_pretty` in a build
/// without `preserve_order`.
///
/// # Errors
/// Returns the serializer's error when `value` cannot be represented.
pub fn to_vec_pretty<T: ?Sized + Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec_pretty(&tree(value)?)
}

/// Compact JSON string, byte-identical to `serde_json::to_string` in a build
/// without `preserve_order`.
///
/// # Errors
/// Returns the serializer's error when `value` cannot be represented.
pub fn to_string<T: ?Sized + Serialize>(value: &T) -> serde_json::Result<String> {
    serde_json::to_string(&tree(value)?)
}

/// Pretty JSON string, byte-identical to `serde_json::to_string_pretty` in a
/// build without `preserve_order`.
///
/// # Errors
/// Returns the serializer's error when `value` cannot be represented.
pub fn to_string_pretty<T: ?Sized + Serialize>(value: &T) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&tree(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    #[derive(Serialize)]
    struct Inner {
        zebra: u8,
        apple: Vec<Value>,
    }

    #[derive(Serialize)]
    struct Outer {
        z: Inner,
        a: Value,
        m: Option<Inner>,
    }

    #[derive(Serialize)]
    struct Flat {
        zeta: u8,
        #[serde(flatten)]
        inner: Inner,
        alpha: u8,
    }

    #[derive(Serialize)]
    enum External {
        Unit,
        Newtype(Inner),
        Tuple(u8, String),
        Struct { b: u8, a: u8 },
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "details")]
    enum Adjacent {
        Unit,
        Struct { b: u8, a: u8 },
        Newtype(Inner),
    }

    #[derive(Serialize)]
    #[serde(tag = "kind")]
    enum Internal {
        Struct { b: u8, a: u8 },
        Newtype(Inner),
    }

    #[derive(Serialize)]
    #[serde(untagged)]
    enum Untagged {
        Struct { b: u8, a: u8 },
        Num(u8),
    }

    fn inner() -> Inner {
        Inner {
            zebra: 1,
            apple: vec![json!({"y": 1, "x": 2})],
        }
    }

    /// Like [`inner`] but with no map anywhere, so serde_json's direct output
    /// is the same in every build.
    fn plain_inner() -> Inner {
        Inner {
            zebra: 1,
            apple: vec![json!(1), json!("two"), json!([3, null])],
        }
    }

    fn unordered_value() -> Value {
        // With `preserve_order` this keeps z before a, as the parse order.
        serde_json::from_str(r#"{"z":1,"a":{"y":[{"d":1,"c":2}],"b":3}}"#).unwrap()
    }

    #[test]
    fn struct_fields_keep_declaration_order() {
        assert_eq!(
            to_string(&inner()).unwrap(),
            r#"{"zebra":1,"apple":[{"x":2,"y":1}]}"#
        );
    }

    #[test]
    fn value_objects_are_sorted_at_every_depth() {
        assert_eq!(
            to_string(&unordered_value()).unwrap(),
            r#"{"a":{"b":3,"y":[{"c":2,"d":1}]},"z":1}"#
        );
    }

    #[test]
    fn struct_containing_a_value_sorts_only_the_value() {
        let outer = Outer {
            z: inner(),
            a: unordered_value(),
            m: None,
        };
        assert_eq!(
            to_string(&outer).unwrap(),
            r#"{"z":{"zebra":1,"apple":[{"x":2,"y":1}]},"a":{"a":{"b":3,"y":[{"c":2,"d":1}]},"z":1},"m":null}"#
        );
    }

    #[test]
    fn json_literal_holding_a_struct_is_sorted_like_a_value() {
        let value = json!({"b": inner(), "a": 1});
        assert_eq!(
            to_string(&value).unwrap(),
            r#"{"a":1,"b":{"apple":[{"x":2,"y":1}],"zebra":1}}"#
        );
    }

    #[test]
    fn btree_map_and_integer_keys_sort_by_key_string() {
        let mut map = BTreeMap::new();
        map.insert(10_u32, "ten");
        map.insert(9, "nine");
        // Integer keys keep the map's own (numeric) iteration order.
        assert_eq!(to_string(&map).unwrap(), r#"{"9":"nine","10":"ten"}"#);
        assert_eq!(
            to_string(&map).unwrap(),
            serde_json::to_string(&map).unwrap()
        );
        let mut strings = BTreeMap::new();
        strings.insert("b", 1);
        strings.insert("a", 2);
        assert_eq!(to_string(&strings).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn flattened_structs_keep_field_order() {
        let flat = Flat {
            zeta: 0,
            inner: plain_inner(),
            alpha: 9,
        };
        let direct = serde_json::to_string(&flat).unwrap();
        assert_eq!(to_string(&flat).unwrap(), direct);
        assert_eq!(
            direct,
            r#"{"zeta":0,"zebra":1,"apple":[1,"two",[3,null]],"alpha":9}"#
        );
    }

    #[test]
    fn enums_in_every_tagging_mode() {
        assert_eq!(to_string(&External::Unit).unwrap(), r#""Unit""#);
        assert_eq!(
            to_string(&External::Newtype(inner())).unwrap(),
            r#"{"Newtype":{"zebra":1,"apple":[{"x":2,"y":1}]}}"#
        );
        assert_eq!(
            to_string(&External::Tuple(1, "s".into())).unwrap(),
            r#"{"Tuple":[1,"s"]}"#
        );
        assert_eq!(
            to_string(&External::Struct { b: 1, a: 2 }).unwrap(),
            r#"{"Struct":{"b":1,"a":2}}"#
        );
        assert_eq!(
            to_string(&Adjacent::Struct { b: 1, a: 2 }).unwrap(),
            r#"{"kind":"Struct","details":{"b":1,"a":2}}"#
        );
        assert_eq!(to_string(&Adjacent::Unit).unwrap(), r#"{"kind":"Unit"}"#);
        assert_eq!(
            to_string(&Adjacent::Newtype(inner())).unwrap(),
            r#"{"kind":"Newtype","details":{"zebra":1,"apple":[{"x":2,"y":1}]}}"#
        );
        assert_eq!(
            to_string(&Internal::Struct { b: 1, a: 2 }).unwrap(),
            r#"{"kind":"Struct","b":1,"a":2}"#
        );
        assert_eq!(
            to_string(&Internal::Newtype(inner())).unwrap(),
            r#"{"kind":"Newtype","zebra":1,"apple":[{"x":2,"y":1}]}"#
        );
        assert_eq!(
            to_string(&Untagged::Struct { b: 1, a: 2 }).unwrap(),
            r#"{"b":1,"a":2}"#
        );
        assert_eq!(to_string(&Untagged::Num(3)).unwrap(), "3");
    }

    #[derive(Serialize)]
    #[serde(tag = "kind")]
    enum InternalMap {
        Struct(Inner),
        Tree(BTreeMap<String, u8>),
        Value(Value),
    }

    #[test]
    fn internally_tagged_newtype_struct_matches_serde_exactly() {
        // serde: serialize_struct(len + 1), tag first, then fields in order.
        let value = InternalMap::Struct(plain_inner());
        let expected = r#"{"kind":"Struct","zebra":1,"apple":[1,"two",[3,null]]}"#;
        assert_eq!(to_string(&value).unwrap(), expected);
        assert_eq!(serde_json::to_string(&value).unwrap(), expected);
    }

    #[test]
    fn internally_tagged_newtype_map_sorts_the_tag_with_the_keys() {
        // serde: serialize_map(Some(len + 1)), the tag entry first, then the
        // map in its own (here sorted) order. serde_json writes that order;
        // stable_json cannot tell the tag from a map entry and sorts it in.
        // This is the documented limitation, pinned so a change is seen.
        let tree: BTreeMap<String, u8> = [("a".to_owned(), 1), ("z".to_owned(), 2)].into();
        let value = InternalMap::Tree(tree);
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"kind":"Tree","a":1,"z":2}"#
        );
        assert_eq!(to_string(&value).unwrap(), r#"{"a":1,"kind":"Tree","z":2}"#);
        let value = InternalMap::Value(json!({"z": 2, "a": 1}));
        assert_eq!(
            to_string(&value).unwrap(),
            r#"{"a":1,"kind":"Value","z":2}"#
        );
    }

    #[test]
    fn numbers_match_serde_json() {
        #[derive(Serialize)]
        struct Numbers {
            max_u64: u64,
            min_i64: i64,
            big_u128: u128,
            neg_i128: i128,
            neg_zero: f64,
            small: f64,
            large: f64,
            third: f32,
            nan: f64,
            inf: f32,
            ch: char,
            bytes: serde_bytes_like::Bytes,
            unit: (),
            tuple: (u8, i8),
        }
        mod serde_bytes_like {
            pub struct Bytes(pub Vec<u8>);
            impl serde::Serialize for Bytes {
                fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    s.serialize_bytes(&self.0)
                }
            }
        }
        let numbers = Numbers {
            max_u64: u64::MAX,
            min_i64: i64::MIN,
            big_u128: u128::MAX,
            neg_i128: i128::MIN,
            neg_zero: -0.0,
            small: 1e-7,
            large: 1.5e300,
            third: 1.0 / 3.0,
            nan: f64::NAN,
            inf: f32::INFINITY,
            ch: 'é',
            bytes: serde_bytes_like::Bytes(vec![0, 1, 255]),
            unit: (),
            tuple: (7, -7),
        };
        assert_eq!(
            to_vec(&numbers).unwrap(),
            serde_json::to_vec(&numbers).unwrap()
        );
        assert_eq!(
            to_vec_pretty(&numbers).unwrap(),
            serde_json::to_vec_pretty(&numbers).unwrap()
        );
        let text = to_string(&numbers).unwrap();
        assert!(text.contains(r#""neg_zero":-0.0"#), "{text}");
        assert!(text.contains(r#""nan":null"#), "{text}");
        assert!(text.contains(r#""third":0.33333334"#), "{text}");
        assert!(text.contains("340282366920938463463374607431768211455"));
    }

    #[test]
    fn pretty_output_matches_a_literal() {
        let outer = Outer {
            z: Inner {
                zebra: 1,
                apple: vec![],
            },
            a: unordered_value(),
            m: None,
        };
        let expected = "{\n  \"z\": {\n    \"zebra\": 1,\n    \"apple\": []\n  },\n  \"a\": {\n    \"a\": {\n      \"b\": 3,\n      \"y\": [\n        {\n          \"c\": 2,\n          \"d\": 1\n        }\n      ]\n    },\n    \"z\": 1\n  },\n  \"m\": null\n}";
        assert_eq!(to_string_pretty(&outer).unwrap(), expected);
        assert_eq!(
            String::from_utf8(to_vec_pretty(&outer).unwrap()).unwrap(),
            expected
        );
        assert_eq!(to_string_pretty(&json!({})).unwrap(), "{}");
    }

    #[test]
    fn map_free_inputs_are_byte_identical_to_serde_json() {
        #[derive(Serialize)]
        struct Row {
            id: u32,
            name: String,
            ratio: f64,
            tags: Vec<String>,
            parent: Option<Box<Row>>,
            kind: External,
        }
        // Deterministic pseudo-random inputs; no maps anywhere.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let depth = next() % 4;
            let mut row: Option<Row> = None;
            for level in 0..=depth {
                let seed = next();
                row = Some(Row {
                    id: u32::try_from(seed % 100_000).unwrap(),
                    name: format!("n\u{e9}\"{seed}\n\u{1F600}"),
                    ratio: f64::from(u32::try_from(seed % 1000).unwrap()) / 7.0,
                    tags: (0..(seed % 4)).map(|i| format!("t{i}")).collect(),
                    parent: row.map(Box::new),
                    kind: match level % 4 {
                        0 => External::Unit,
                        1 => External::Newtype(plain_inner()),
                        2 => External::Tuple(1, "x".into()),
                        _ => External::Struct { b: 2, a: 1 },
                    },
                });
            }
            let row = row.unwrap();
            assert_eq!(to_vec(&row).unwrap(), serde_json::to_vec(&row).unwrap());
            assert_eq!(
                to_vec_pretty(&row).unwrap(),
                serde_json::to_vec_pretty(&row).unwrap()
            );
        }
    }

    #[test]
    fn non_string_keys_follow_serde_json_rules() {
        let mut flags = BTreeMap::new();
        flags.insert(true, 1);
        flags.insert(false, 0);
        assert_eq!(to_string(&flags).unwrap(), r#"{"false":0,"true":1}"#);
        let mut nested: BTreeMap<(u8, u8), u8> = BTreeMap::new();
        nested.insert((1, 2), 3);
        assert!(to_string(&nested).is_err());
        assert!(serde_json::to_string(&nested).is_err());
    }
}
