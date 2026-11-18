//! The helper function library from the Nuclei reference.
//!
//! Not implemented, and therefore making a template "not evaluated":
//! `generate_java_gadget`, `generate_dotnet_gadget`, `aes_gcm`, `print_debug`,
//! `wait_for`, `resolve`, `rand_ip`, and `generate_jwt` with any algorithm
//! other than HS256/HS384/HS512/none. `ip_format` indexes 10 and 11 are
//! undocumented beyond a single example and fail at evaluation as
//! unsupported.

use std::borrow::Cow;
use std::io::{Read, Write};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use md5::Md5;
use regex::RegexBuilder;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::eval::{values_equal, MAX_STRING_BYTES, REGEX_SIZE_LIMIT};
use super::value::{DslError, EvalContext, Value};

const MAX_DECODED_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RANDOM_LEN: usize = 64 * 1024;
const VARIADIC: usize = usize::MAX;

/// Helpers that exist in Nuclei but are deliberately not implemented.
pub const UNSUPPORTED: &[&str] = &[
    "generate_java_gadget",
    "generate_dotnet_gadget",
    "aes_gcm",
    "print_debug",
    "wait_for",
    "resolve",
    "rand_ip",
];

/// (name, minimum arguments, maximum arguments).
const FUNCTIONS: &[(&str, usize, usize)] = &[
    ("base64", 1, 1),
    ("base64_decode", 1, 1),
    ("base64_py", 1, 1),
    ("bin_to_dec", 1, 1),
    ("compare_versions", 2, VARIADIC),
    ("concat", 0, VARIADIC),
    ("contains", 2, 2),
    ("contains_all", 2, VARIADIC),
    ("contains_any", 2, VARIADIC),
    ("date_time", 1, 2),
    ("dec_to_hex", 1, 1),
    ("ends_with", 2, VARIADIC),
    ("equals_any", 2, VARIADIC),
    ("generate_jwt", 1, 4),
    ("gzip", 1, 1),
    ("gzip_decode", 1, 1),
    ("hex_decode", 1, 1),
    ("hex_encode", 1, 1),
    ("hex_to_dec", 1, 1),
    ("hmac", 3, 3),
    ("html_escape", 1, 1),
    ("html_unescape", 1, 1),
    ("ip_format", 2, 2),
    ("join", 1, VARIADIC),
    ("json_minify", 1, 1),
    ("json_prettify", 1, 1),
    ("len", 1, 1),
    ("line_ends_with", 2, VARIADIC),
    ("line_starts_with", 2, VARIADIC),
    ("md5", 1, 1),
    ("mmh3", 1, 1),
    ("oct_to_dec", 1, 1),
    ("rand_base", 1, 2),
    ("rand_char", 0, 1),
    ("rand_int", 0, 2),
    ("rand_text_alpha", 1, 2),
    ("rand_text_alphanumeric", 1, 2),
    ("rand_text_numeric", 1, 2),
    ("regex", 2, 2),
    ("regex_all", 2, VARIADIC),
    ("regex_any", 2, VARIADIC),
    ("remove_bad_chars", 2, 2),
    ("repeat", 2, 2),
    ("replace", 3, 3),
    ("replace_regex", 3, 3),
    ("reverse", 1, 1),
    ("sha1", 1, 1),
    ("sha256", 1, 1),
    ("sha512", 1, 1),
    ("starts_with", 2, VARIADIC),
    ("to_lower", 1, 1),
    ("tolower", 1, 1),
    ("to_number", 1, 1),
    ("to_string", 1, 1),
    ("to_unix_time", 1, 2),
    ("to_upper", 1, 1),
    ("toupper", 1, 1),
    ("trim", 2, 2),
    ("trim_left", 2, 2),
    ("trim_prefix", 2, 2),
    ("trim_right", 2, 2),
    ("trim_space", 1, 1),
    ("trim_suffix", 2, 2),
    ("unix_time", 0, 1),
    ("url_decode", 1, 1),
    ("url_encode", 1, 1),
    ("zlib", 1, 1),
    ("zlib_decode", 1, 1),
];

/// Every implemented helper name.
pub fn implemented_names() -> impl Iterator<Item = &'static str> {
    FUNCTIONS.iter().map(|(name, _, _)| *name)
}

pub fn is_implemented(name: &str) -> bool {
    FUNCTIONS.iter().any(|(n, _, _)| *n == name)
}

/// Checks that `name` exists and accepts `argc` arguments.
pub fn check_call(name: &str, argc: usize) -> Result<(), DslError> {
    let Some((_, min, max)) = FUNCTIONS.iter().find(|(n, _, _)| *n == name) else {
        return Err(DslError::UnknownFunction(name.to_string()));
    };
    if argc < *min || argc > *max {
        let expected = if *max == VARIADIC {
            format!("at least {min}")
        } else if min == max {
            min.to_string()
        } else {
            format!("{min} to {max}")
        };
        return Err(DslError::Arity {
            name: name.to_string(),
            expected,
            got: argc,
        });
    }
    Ok(())
}

fn text(v: &Value) -> Cow<'_, str> {
    v.to_text()
}

fn bytes(v: &Value) -> Cow<'_, [u8]> {
    v.to_bytes()
}

fn int_of(v: &Value, name: &str) -> Result<i64, DslError> {
    match v {
        Value::Int(n) => Ok(*n),
        Value::Float(f) if *f == f.trunc() && f.abs() < 9e18 => Ok(*f as i64),
        Value::String(s) => s
            .trim()
            .parse::<i64>()
            .map_err(|_| DslError::Type(format!("`{name}` needs an integer, got `{s}`"))),
        other => Err(DslError::Type(format!(
            "`{name}` needs an integer, got {}",
            other.type_name()
        ))),
    }
}

fn len_arg(v: &Value, name: &str) -> Result<usize, DslError> {
    let n = int_of(v, name)?;
    if n < 0 {
        return Err(DslError::Eval(format!(
            "`{name}` needs a non-negative count"
        )));
    }
    Ok(n as usize)
}

fn string_value(s: String) -> Result<Value, DslError> {
    if s.len() > MAX_STRING_BYTES {
        return Err(DslError::Limit("result is larger than 1 MiB".into()));
    }
    Ok(Value::from(s))
}

fn bytes_value(b: Vec<u8>) -> Result<Value, DslError> {
    if b.len() > MAX_STRING_BYTES {
        return Err(DslError::Limit("result is larger than 1 MiB".into()));
    }
    Ok(Value::Bytes(b))
}

/// Calls helper `name`. Arity is checked here as well so a malformed call can
/// never index out of range.
pub fn call(name: &str, args: &[Value], ctx: &mut dyn EvalContext) -> Result<Value, DslError> {
    check_call(name, args.len())?;
    let a = |i: usize| -> &Value { args.get(i).unwrap_or(&Value::Null) };
    match name {
        "base64" => Ok(Value::from(STANDARD.encode(bytes(a(0))))),
        "base64_decode" => STANDARD
            .decode(bytes(a(0)).as_ref())
            .map(Value::Bytes)
            .map_err(|e| DslError::Eval(format!("base64_decode: {e}"))),
        "base64_py" => {
            let encoded = STANDARD.encode(bytes(a(0)));
            let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 + 2);
            for chunk in encoded.as_bytes().chunks(76) {
                out.push_str(&String::from_utf8_lossy(chunk));
                out.push('\n');
            }
            string_value(out)
        }
        "bin_to_dec" => radix_to_dec(a(0), 2, &["0b", "0B"], "bin_to_dec"),
        "hex_to_dec" => radix_to_dec(a(0), 16, &["0x", "0X"], "hex_to_dec"),
        "oct_to_dec" => radix_to_dec(a(0), 8, &["0o", "0O"], "oct_to_dec"),
        "dec_to_hex" => Ok(Value::from(format!("{:x}", int_of(a(0), name)?))),
        "compare_versions" => {
            let version = text(a(0));
            for constraint in &args[1..] {
                if !version_satisfies(&version, &text(constraint))? {
                    return Ok(Value::Bool(false));
                }
            }
            Ok(Value::Bool(true))
        }
        "concat" => string_value(args.iter().map(|v| text(v).into_owned()).collect()),
        "join" => {
            let sep = text(a(0));
            let parts: Vec<String> = args[1..].iter().map(|v| text(v).into_owned()).collect();
            string_value(parts.join(&sep))
        }
        "contains" => Ok(Value::Bool(contains(a(0), a(1)))),
        "contains_all" => Ok(Value::Bool(args[1..].iter().all(|s| contains(a(0), s)))),
        "contains_any" => Ok(Value::Bool(args[1..].iter().any(|s| contains(a(0), s)))),
        "starts_with" => {
            let s = text(a(0));
            Ok(Value::Bool(
                args[1..].iter().any(|p| s.starts_with(text(p).as_ref())),
            ))
        }
        "ends_with" => {
            let s = text(a(0));
            Ok(Value::Bool(
                args[1..].iter().any(|p| s.ends_with(text(p).as_ref())),
            ))
        }
        "line_starts_with" => {
            let s = text(a(0));
            Ok(Value::Bool(s.lines().any(|line| {
                args[1..].iter().any(|p| line.starts_with(text(p).as_ref()))
            })))
        }
        "line_ends_with" => {
            let s = text(a(0));
            Ok(Value::Bool(s.lines().any(|line| {
                args[1..].iter().any(|p| line.ends_with(text(p).as_ref()))
            })))
        }
        "equals_any" => Ok(Value::Bool(args[1..].iter().any(|v| values_equal(a(0), v)))),
        "date_time" => {
            let ts = match args.get(1) {
                Some(v) => int_of(v, name)?,
                None => ctx.now_unix(),
            };
            string_value(format_time(&text(a(0)), ts))
        }
        "to_unix_time" => {
            let layout = args.get(1).map(|v| text(v).into_owned());
            parse_time(&text(a(0)), layout.as_deref()).map(Value::Int)
        }
        "unix_time" => {
            let extra = match args.first() {
                Some(v) => int_of(v, name)?,
                None => 0,
            };
            Ok(Value::Int(ctx.now_unix().saturating_add(extra)))
        }
        "generate_jwt" => generate_jwt(args, ctx),
        "gzip" => {
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&bytes(a(0)))
                .map_err(|e| DslError::Eval(e.to_string()))?;
            bytes_value(enc.finish().map_err(|e| DslError::Eval(e.to_string()))?)
        }
        "zlib" => {
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&bytes(a(0)))
                .map_err(|e| DslError::Eval(e.to_string()))?;
            bytes_value(enc.finish().map_err(|e| DslError::Eval(e.to_string()))?)
        }
        "gzip_decode" => inflate(GzDecoder::new(bytes(a(0)).as_ref()), name),
        "zlib_decode" => inflate(ZlibDecoder::new(bytes(a(0)).as_ref()), name),
        "hex_decode" => hex_decode(&text(a(0))).map(Value::Bytes),
        "hex_encode" => Ok(Value::from(hex_encode(&bytes(a(0))))),
        "hmac" => {
            let algo = text(a(0)).to_ascii_lowercase();
            let (data, key) = (bytes(a(1)), bytes(a(2)));
            let mac = match algo.as_str() {
                "md5" => hmac_with(64, |d| Md5::digest(d).to_vec(), &key, &data),
                "sha1" => hmac_with(64, |d| Sha1::digest(d).to_vec(), &key, &data),
                "sha256" => hmac_with(64, |d| Sha256::digest(d).to_vec(), &key, &data),
                "sha384" => hmac_with(128, |d| Sha384::digest(d).to_vec(), &key, &data),
                "sha512" => hmac_with(128, |d| Sha512::digest(d).to_vec(), &key, &data),
                other => {
                    return Err(DslError::Eval(format!("hmac: unknown algorithm `{other}`")));
                }
            };
            Ok(Value::from(hex_encode(&mac)))
        }
        "md5" => Ok(Value::from(hex_encode(&Md5::digest(bytes(a(0)).as_ref())))),
        "sha1" => Ok(Value::from(hex_encode(&Sha1::digest(bytes(a(0)).as_ref())))),
        "sha256" => Ok(Value::from(hex_encode(&Sha256::digest(
            bytes(a(0)).as_ref(),
        )))),
        "sha512" => Ok(Value::from(hex_encode(&Sha512::digest(
            bytes(a(0)).as_ref(),
        )))),
        "mmh3" => Ok(Value::from((mmh3_32(&bytes(a(0)), 0) as i32).to_string())),
        "html_escape" => string_value(html_escape(&text(a(0)))),
        "html_unescape" => string_value(html_unescape(&text(a(0)))),
        "json_minify" => json_reformat(&text(a(0)), false),
        "json_prettify" => json_reformat(&text(a(0)), true),
        "len" => Ok(Value::Int(bytes(a(0)).len() as i64)),
        "ip_format" => ip_format(&text(a(0)), int_of(a(1), name)?),
        "rand_base" => {
            let n = capped_len(a(0), name)?;
            let set = args.get(1).map(|v| text(v).into_owned());
            random_string(ctx, n, set.as_deref().unwrap_or(ALPHANUMERIC), "")
        }
        "rand_char" => {
            let set = args.first().map(|v| text(v).into_owned());
            random_string(ctx, 1, set.as_deref().unwrap_or(ALPHANUMERIC), "")
        }
        "rand_int" => {
            let min = match args.first() {
                Some(v) => int_of(v, name)?,
                None => 0,
            };
            let max = match args.get(1) {
                Some(v) => int_of(v, name)?,
                None => i32::MAX as i64,
            };
            if max <= min {
                return Ok(Value::Int(min));
            }
            let span = (max as i128 - min as i128) as u128;
            Ok(Value::Int(
                (min as i128 + (ctx.rand_u64() as u128 % span) as i128) as i64,
            ))
        }
        "rand_text_alpha" => {
            let n = capped_len(a(0), name)?;
            let bad = args
                .get(1)
                .map(|v| text(v).into_owned())
                .unwrap_or_default();
            random_string(ctx, n, ALPHA, &bad)
        }
        "rand_text_alphanumeric" => {
            let n = capped_len(a(0), name)?;
            let bad = args
                .get(1)
                .map(|v| text(v).into_owned())
                .unwrap_or_default();
            random_string(ctx, n, ALPHANUMERIC, &bad)
        }
        "rand_text_numeric" => {
            let n = capped_len(a(0), name)?;
            let bad = args
                .get(1)
                .map(|v| text(v).into_owned())
                .unwrap_or_default();
            random_string(ctx, n, "0123456789", &bad)
        }
        "regex" => Ok(Value::Bool(compile(&text(a(0)))?.is_match(&text(a(1))))),
        "regex_any" => {
            let re = compile(&text(a(0)))?;
            Ok(Value::Bool(args[1..].iter().any(|v| re.is_match(&text(v)))))
        }
        "regex_all" => {
            let re = compile(&text(a(0)))?;
            Ok(Value::Bool(args[1..].iter().all(|v| re.is_match(&text(v)))))
        }
        "remove_bad_chars" => {
            let cut = text(a(1));
            string_value(text(a(0)).chars().filter(|c| !cut.contains(*c)).collect())
        }
        "repeat" => {
            let s = text(a(0));
            let n = len_arg(a(1), name)?;
            if s.len().saturating_mul(n) > MAX_STRING_BYTES {
                return Err(DslError::Limit("repeat result is larger than 1 MiB".into()));
            }
            string_value(s.repeat(n))
        }
        "replace" => {
            let (s, old, new) = (text(a(0)), text(a(1)), text(a(2)));
            if old.is_empty() {
                return Ok(Value::from(s.into_owned()));
            }
            let occurrences = s.matches(old.as_ref()).count();
            let grown =
                s.len() as u64 + occurrences as u64 * new.len().saturating_sub(old.len()) as u64;
            if grown > MAX_STRING_BYTES as u64 {
                return Err(DslError::Limit(
                    "replace result is larger than 1 MiB".into(),
                ));
            }
            string_value(s.replace(old.as_ref(), &new))
        }
        "replace_regex" => {
            let re = compile(&text(a(1)))?;
            let out = re
                .replace_all(&text(a(0)), text(a(2)).as_ref())
                .into_owned();
            string_value(out)
        }
        "reverse" => string_value(text(a(0)).chars().rev().collect()),
        "to_lower" | "tolower" => string_value(text(a(0)).to_lowercase()),
        "to_upper" | "toupper" => string_value(text(a(0)).to_uppercase()),
        "to_number" => to_number(a(0)),
        "to_string" => Ok(Value::from(text(a(0)).into_owned())),
        "trim" => {
            let cut = text(a(1));
            Ok(Value::from(
                text(a(0)).trim_matches(|c| cut.contains(c)).to_string(),
            ))
        }
        "trim_left" => {
            let cut = text(a(1));
            Ok(Value::from(
                text(a(0))
                    .trim_start_matches(|c| cut.contains(c))
                    .to_string(),
            ))
        }
        "trim_right" => {
            let cut = text(a(1));
            Ok(Value::from(
                text(a(0)).trim_end_matches(|c| cut.contains(c)).to_string(),
            ))
        }
        "trim_prefix" => {
            let p = text(a(1));
            let s = text(a(0));
            Ok(Value::from(
                s.strip_prefix(p.as_ref()).unwrap_or(&s).to_string(),
            ))
        }
        "trim_suffix" => {
            let p = text(a(1));
            let s = text(a(0));
            Ok(Value::from(
                s.strip_suffix(p.as_ref()).unwrap_or(&s).to_string(),
            ))
        }
        "trim_space" => Ok(Value::from(text(a(0)).trim().to_string())),
        "url_encode" => Ok(Value::from(url_encode(&bytes(a(0))))),
        "url_decode" => url_decode(&text(a(0))),
        other => Err(DslError::UnknownFunction(other.to_string())),
    }
}

const ALPHA: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHANUMERIC: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn capped_len(v: &Value, name: &str) -> Result<usize, DslError> {
    let n = len_arg(v, name)?;
    if n > MAX_RANDOM_LEN {
        return Err(DslError::Limit(format!(
            "`{name}` length exceeds {MAX_RANDOM_LEN}"
        )));
    }
    Ok(n)
}

fn random_string(
    ctx: &mut dyn EvalContext,
    n: usize,
    set: &str,
    exclude: &str,
) -> Result<Value, DslError> {
    let chars: Vec<char> = set.chars().filter(|c| !exclude.contains(*c)).collect();
    if chars.is_empty() {
        return Err(DslError::Eval("empty character set".into()));
    }
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        let idx = (ctx.rand_u64() % chars.len() as u64) as usize;
        if let Some(c) = chars.get(idx) {
            out.push(*c);
        }
    }
    Ok(Value::from(out))
}

fn contains(hay: &Value, needle: &Value) -> bool {
    if matches!(hay, Value::Bytes(_)) || matches!(needle, Value::Bytes(_)) {
        let (h, n) = (hay.to_bytes(), needle.to_bytes());
        return n.is_empty() || h.windows(n.len()).any(|w| w == n.as_ref());
    }
    hay.to_text().contains(needle.to_text().as_ref())
}

fn compile(pattern: &str) -> Result<regex::Regex, DslError> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| DslError::Eval(format!("invalid regex: {e}")))
}

fn to_number(v: &Value) -> Result<Value, DslError> {
    match v {
        Value::Int(_) | Value::Float(_) => Ok(v.clone()),
        Value::String(s) => {
            let t = s.trim();
            if let Ok(n) = t.parse::<i64>() {
                Ok(Value::Int(n))
            } else if let Ok(f) = t.parse::<f64>() {
                Ok(Value::Float(f))
            } else {
                Err(DslError::Eval(format!("to_number: `{t}` is not a number")))
            }
        }
        other => Err(DslError::Type(format!(
            "to_number cannot convert {}",
            other.type_name()
        ))),
    }
}

fn radix_to_dec(v: &Value, radix: u32, prefixes: &[&str], name: &str) -> Result<Value, DslError> {
    let raw = text(v);
    let mut digits = raw.trim();
    for p in prefixes {
        if let Some(rest) = digits.strip_prefix(p) {
            digits = rest;
            break;
        }
    }
    let n = u64::from_str_radix(digits, radix)
        .map_err(|_| DslError::Eval(format!("{name}: `{raw}` is not a base-{radix} number")))?;
    Ok(match i64::try_from(n) {
        Ok(i) => Value::Int(i),
        Err(_) => Value::Float(n as f64),
    })
}

pub(crate) fn hex_encode(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>, DslError> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let raw = s.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(DslError::Eval("hex_decode: odd number of digits".into()));
    }
    let nibble = |c: u8| -> Result<u8, DslError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(DslError::Eval("hex_decode: invalid hex digit".into())),
        }
    };
    raw.chunks(2)
        .map(|pair| match pair {
            [hi, lo] => Ok(nibble(*hi)? << 4 | nibble(*lo)?),
            _ => Err(DslError::Eval("hex_decode: odd number of digits".into())),
        })
        .collect()
}

fn inflate<R: Read>(reader: R, name: &str) -> Result<Value, DslError> {
    let mut out = Vec::new();
    reader
        .take(MAX_DECODED_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| DslError::Eval(format!("{name}: {e}")))?;
    if out.len() as u64 > MAX_DECODED_BYTES {
        return Err(DslError::Limit(format!("{name}: output exceeds 4 MiB")));
    }
    Ok(Value::Bytes(out))
}

fn hmac_with(block: usize, hash: fn(&[u8]) -> Vec<u8>, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > block {
        hash(key)
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(data);
    let inner_hash = hash(&inner);
    let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

/// MurmurHash3, x86 32-bit variant.
pub(crate) fn mmh3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let mut k = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = chunks.remainder();
    let mut k = 0u32;
    for (i, b) in tail.iter().enumerate() {
        k |= (*b as u32) << (8 * i);
    }
    if !tail.is_empty() {
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            other => out.push(other),
        }
    }
    out
}

fn html_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let decoded = tail
            .find(';')
            .filter(|end| *end <= 10)
            .and_then(|end| decode_entity(&tail[1..end]).map(|c| (c, end + 1)));
        match decoded {
            Some((c, used)) => {
                out.push(c);
                rest = &tail[used..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn decode_entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{a0}'),
        "copy" => Some('\u{a9}'),
        "reg" => Some('\u{ae}'),
        _ => {
            let num = name.strip_prefix('#')?;
            let code = if let Some(hex) = num.strip_prefix(['x', 'X']) {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                num.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

fn url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn url_decode(s: &str) -> Result<Value, DslError> {
    let raw = s.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'%' => {
                let hex = s
                    .get(i + 1..i + 3)
                    .ok_or_else(|| DslError::Eval("url_decode: truncated percent escape".into()))?;
                let byte = u8::from_str_radix(hex, 16)
                    .map_err(|_| DslError::Eval("url_decode: invalid percent escape".into()))?;
                out.push(byte);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    Ok(match String::from_utf8(out) {
        Ok(s) => Value::from(s),
        Err(e) => Value::Bytes(e.into_bytes()),
    })
}

/// Serialises JSON with object keys sorted, as Go's `encoding/json` does for
/// maps, so `json_minify`/`generate_jwt` give the documented output.
fn write_json(v: &serde_json::Value, out: &mut String, indent: Option<&str>, depth: usize) {
    use serde_json::Value as J;
    let newline = |out: &mut String, depth: usize| {
        if let Some(unit) = indent {
            out.push('\n');
            for _ in 0..depth {
                out.push_str(unit);
            }
        }
    };
    match v {
        J::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, depth + 1);
                out.push_str(&serde_json::Value::String((*key).clone()).to_string());
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                if let Some(child) = map.get(key.as_str()) {
                    write_json(child, out, indent, depth + 1);
                }
            }
            newline(out, depth);
            out.push('}');
        }
        J::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, depth + 1);
                write_json(item, out, indent, depth + 1);
            }
            newline(out, depth);
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

fn json_reformat(src: &str, pretty: bool) -> Result<Value, DslError> {
    let parsed: serde_json::Value =
        serde_json::from_str(src).map_err(|e| DslError::Eval(format!("invalid JSON: {e}")))?;
    let mut out = String::new();
    write_json(&parsed, &mut out, pretty.then_some(" "), 0);
    string_value(out)
}

fn generate_jwt(args: &[Value], ctx: &mut dyn EvalContext) -> Result<Value, DslError> {
    let claims_src = args
        .first()
        .map(|v| text(v).into_owned())
        .unwrap_or_default();
    let alg = args
        .get(1)
        .map(|v| text(v).trim().to_ascii_uppercase())
        .unwrap_or_default();
    let secret = args
        .get(2)
        .map(|v| bytes(v).into_owned())
        .unwrap_or_default();
    let max_age = match args.get(3) {
        Some(v) if !text(v).trim().is_empty() => int_of(v, "generate_jwt")?,
        _ => 0,
    };
    let mut claims: serde_json::Value = serde_json::from_str(&claims_src)
        .map_err(|e| DslError::Eval(format!("generate_jwt: invalid JSON claims: {e}")))?;
    if !claims.is_object() {
        return Err(DslError::Eval(
            "generate_jwt: claims must be a JSON object".into(),
        ));
    }
    if max_age != 0 {
        if let Some(map) = claims.as_object_mut() {
            map.insert("exp".into(), max_age.into());
            map.insert("iat".into(), ctx.now_unix().into());
        }
    }
    let header_alg = match alg.as_str() {
        "" | "NONE" => "none",
        "HS256" => "HS256",
        "HS384" => "HS384",
        "HS512" => "HS512",
        other => {
            return Err(DslError::Unsupported(format!(
                "generate_jwt algorithm {other}"
            )));
        }
    };
    let mut payload = String::new();
    write_json(&claims, &mut payload, None, 0);
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(format!("{{\"alg\":\"{header_alg}\",\"typ\":\"JWT\"}}")),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = match header_alg {
        "HS256" => hmac_with(
            64,
            |d| Sha256::digest(d).to_vec(),
            &secret,
            signing_input.as_bytes(),
        ),
        "HS384" => hmac_with(
            128,
            |d| Sha384::digest(d).to_vec(),
            &secret,
            signing_input.as_bytes(),
        ),
        "HS512" => hmac_with(
            128,
            |d| Sha512::digest(d).to_vec(),
            &secret,
            signing_input.as_bytes(),
        ),
        _ => Vec::new(),
    };
    Ok(Value::from(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    )))
}

fn ip_format(ip: &str, index: i64) -> Result<Value, DslError> {
    let parts: Vec<&str> = ip.trim().split('.').collect();
    let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse::<u8>().ok()).collect();
    let [a, b, c, d] = octets[..] else {
        return Err(DslError::Eval(
            "ip_format: only IPv4 input is supported".into(),
        ));
    };
    if parts.len() != 4 {
        return Err(DslError::Eval(
            "ip_format: only IPv4 input is supported".into(),
        ));
    }
    let dword = u32::from_be_bytes([a, b, c, d]);
    let dotted = format!("{a}.{b}.{c}.{d}");
    let out = match index {
        1 => dotted,
        2 => {
            if b == 0 && c == 0 {
                format!("{a}.{d}")
            } else if c == 0 {
                format!("{a}.{b}.{d}")
            } else {
                dotted
            }
        }
        3 => [a, b, c, d]
            .iter()
            .map(|o| {
                if *o == 0 {
                    "0".to_string()
                } else {
                    format!("0{o:o}")
                }
            })
            .collect::<Vec<_>>()
            .join("."),
        4 => [a, b, c, d]
            .iter()
            .map(|o| format!("0x{o:x}"))
            .collect::<Vec<_>>()
            .join("."),
        5 => dword.to_string(),
        6 => format!("{dword:032b}"),
        7 => format!("{a}.0x{:x}", dword & 0x00ff_ffff),
        8 => format!(
            "00:00:00:00:00:ffff:{:04x}:{:04x}",
            dword >> 16,
            dword & 0xffff
        ),
        9 => dotted.bytes().map(|b| format!("%{b:02X}")).collect(),
        other => {
            return Err(DslError::Unsupported(format!("ip_format index {other}")));
        }
    };
    Ok(Value::from(out))
}

// ---------------------------------------------------------------- versions

type Version = (u64, u64, u64, Vec<String>);

fn parse_version(s: &str) -> Option<Version> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let s = s.split('+').next().unwrap_or(s);
    let (core, pre) = match s.split_once('-') {
        Some((core, pre)) => (core, pre.split('.').map(str::to_string).collect()),
        None => (s, Vec::new()),
    };
    let mut nums = core.split('.');
    let major = nums.next()?.parse().ok()?;
    let minor = nums.next().map_or(Some(0), |p| p.parse().ok())?;
    let patch = nums.next().map_or(Some(0), |p| p.parse().ok())?;
    if nums.next().is_some() {
        return None;
    }
    Some((major, minor, patch, pre))
}

fn cmp_version(a: &Version, b: &Version) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    (a.0, a.1, a.2)
        .cmp(&(b.0, b.1, b.2))
        .then_with(|| match (a.3.is_empty(), b.3.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => {
                for (x, y) in a.3.iter().zip(&b.3) {
                    let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                        (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                        (Ok(_), Err(_)) => Ordering::Less,
                        (Err(_), Ok(_)) => Ordering::Greater,
                        (Err(_), Err(_)) => x.cmp(y),
                    };
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                a.3.len().cmp(&b.3.len())
            }
        })
}

fn version_satisfies(version: &str, constraints: &str) -> Result<bool, DslError> {
    let v = parse_version(version)
        .ok_or_else(|| DslError::Eval(format!("compare_versions: bad version `{version}`")))?;
    // `||` separates alternatives; `,` joins constraints that must all hold.
    for alternative in constraints.split("||") {
        let mut all = true;
        for part in alternative.split(',') {
            if !single_constraint(&v, part.trim())? {
                all = false;
                break;
            }
        }
        if all {
            return Ok(true);
        }
    }
    Ok(false)
}

fn single_constraint(v: &Version, c: &str) -> Result<bool, DslError> {
    use std::cmp::Ordering::{Equal, Greater, Less};
    if c.is_empty() || c == "*" {
        return Ok(true);
    }
    let (op, rest) = ["<=", ">=", "!=", "==", "<", ">", "=", "^", "~"]
        .iter()
        .find_map(|op| c.strip_prefix(op).map(|r| (*op, r)))
        .unwrap_or(("=", c));
    let target = parse_version(rest)
        .ok_or_else(|| DslError::Eval(format!("compare_versions: bad constraint `{c}`")))?;
    let ord = cmp_version(v, &target);
    Ok(match op {
        "<" => ord == Less,
        "<=" => ord != Greater,
        ">" => ord == Greater,
        ">=" => ord != Less,
        "!=" => ord != Equal,
        "=" | "==" => ord == Equal,
        "^" => {
            ord != Less
                && if target.0 > 0 {
                    v.0 == target.0
                } else if target.1 > 0 {
                    v.0 == 0 && v.1 == target.1
                } else {
                    v.0 == 0 && v.1 == 0 && v.2 == target.2
                }
        }
        _ => ord != Less && v.0 == target.0 && v.1 == target.1,
    })
}

// -------------------------------------------------------------------- time

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const WEEKDAYS: [&str; 7] = [
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
];

/// Go layout tokens handled by `date_time` and `to_unix_time`, longest first.
const LAYOUT_TOKENS: &[&str] = &[
    "January", "Monday", "2006", "Z07:00", "-0700", "Jan", "Mon", "MST", "01", "02", "03", "04",
    "05", "06", "15", "PM",
];

fn format_time(layout: &str, ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, secs % 3600 / 60, secs % 60);
    let mut out = String::new();
    if layout.contains('%') {
        let mut chars = layout.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('Y') => out.push_str(&format!("{y:04}")),
                Some('y') => out.push_str(&format!("{:02}", y.rem_euclid(100))),
                Some('M') => out.push_str(&format!("{m:02}")),
                Some('D') => out.push_str(&format!("{d:02}")),
                Some('H') => out.push_str(&format!("{hh:02}")),
                Some('m') => out.push_str(&format!("{mm:02}")),
                Some('S') => out.push_str(&format!("{ss:02}")),
                Some(other) => {
                    out.push('%');
                    out.push(other);
                }
                None => out.push('%'),
            }
        }
        return out;
    }
    let mut rest = layout;
    while !rest.is_empty() {
        let token = LAYOUT_TOKENS.iter().find(|t| rest.starts_with(**t));
        match token {
            Some(&"2006") => out.push_str(&format!("{y:04}")),
            Some(&"06") => out.push_str(&format!("{:02}", y.rem_euclid(100))),
            Some(&"01") => out.push_str(&format!("{m:02}")),
            Some(&"02") => out.push_str(&format!("{d:02}")),
            Some(&"15") => out.push_str(&format!("{hh:02}")),
            Some(&"03") => out.push_str(&format!("{:02}", if hh % 12 == 0 { 12 } else { hh % 12 })),
            Some(&"04") => out.push_str(&format!("{mm:02}")),
            Some(&"05") => out.push_str(&format!("{ss:02}")),
            Some(&"PM") => out.push_str(if hh >= 12 { "PM" } else { "AM" }),
            Some(&"Jan") => out.push_str(&MONTHS[(m - 1).clamp(0, 11) as usize][..3]),
            Some(&"January") => out.push_str(MONTHS[(m - 1).clamp(0, 11) as usize]),
            Some(&"Mon") => out.push_str(&WEEKDAYS[days.rem_euclid(7) as usize][..3]),
            Some(&"Monday") => out.push_str(WEEKDAYS[days.rem_euclid(7) as usize]),
            Some(&"MST") => out.push_str("UTC"),
            Some(&"Z07:00") => out.push('Z'),
            Some(&"-0700") => out.push_str("+0000"),
            _ => {
                if let Some(c) = rest.chars().next() {
                    out.push(c);
                    rest = &rest[c.len_utf8()..];
                }
                continue;
            }
        }
        if let Some(t) = token {
            rest = &rest[t.len()..];
        }
    }
    out
}

fn take_digits(s: &str, min: usize, max: usize) -> Option<(i64, &str)> {
    let n = s.bytes().take(max).take_while(u8::is_ascii_digit).count();
    if n < min {
        return None;
    }
    Some((s[..n].parse().ok()?, &s[n..]))
}

fn parse_with_layout(input: &str, layout: &str) -> Option<i64> {
    let (mut y, mut mo, mut d, mut hh, mut mi, mut ss, mut offset) = (1970, 1, 1, 0, 0, 0, 0i64);
    let mut pm: Option<bool> = None;
    let (mut s, mut l) = (input.trim(), layout);
    while !l.is_empty() {
        let token = LAYOUT_TOKENS.iter().find(|t| l.starts_with(**t));
        match token {
            Some(&"2006") => (y, s) = take_digits(s, 4, 4)?,
            Some(&"06") => {
                let (v, r) = take_digits(s, 2, 2)?;
                y = if v >= 69 { 1900 + v } else { 2000 + v };
                s = r;
            }
            Some(&"01") => (mo, s) = take_digits(s, 2, 2)?,
            Some(&"02") => (d, s) = take_digits(s, 2, 2)?,
            Some(&"15") | Some(&"03") => (hh, s) = take_digits(s, 2, 2)?,
            Some(&"04") => (mi, s) = take_digits(s, 2, 2)?,
            Some(&"05") => (ss, s) = take_digits(s, 2, 2)?,
            Some(&"PM") => {
                pm = Some(s.get(..2)?.eq_ignore_ascii_case("pm"));
                s = &s[2..];
            }
            Some(&"Jan") | Some(&"January") => {
                let full = token == Some(&"January");
                let idx = MONTHS.iter().position(|name| {
                    let want = if full { name } else { &name[..3] };
                    s.get(..want.len())
                        .is_some_and(|h| h.eq_ignore_ascii_case(want))
                })?;
                let len = if full { MONTHS[idx].len() } else { 3 };
                mo = idx as i64 + 1;
                s = &s[len..];
            }
            Some(&"Z07:00") | Some(&"-0700") => {
                if let Some(r) = s.strip_prefix('Z') {
                    s = r;
                } else {
                    let sign = match s.chars().next()? {
                        '+' => 1,
                        '-' => -1,
                        _ => return None,
                    };
                    let (oh, r) = take_digits(&s[1..], 2, 2)?;
                    let r = r.strip_prefix(':').unwrap_or(r);
                    let (om, r) = take_digits(r, 2, 2)?;
                    offset = sign * (oh * 3600 + om * 60);
                    s = r;
                }
            }
            Some(&"MST") | Some(&"Mon") | Some(&"Monday") => {
                let n = s.chars().take_while(|c| c.is_ascii_alphabetic()).count();
                s = &s[n..];
            }
            _ => {
                let c = l.chars().next()?;
                s = s.strip_prefix(c)?;
                l = &l[c.len_utf8()..];
                continue;
            }
        }
        if let Some(t) = token {
            l = &l[t.len()..];
        }
    }
    if !s.is_empty() {
        return None;
    }
    if let Some(is_pm) = pm {
        hh = hh % 12 + if is_pm { 12 } else { 0 };
    }
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || hh > 23 || mi > 59 || ss > 60 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + hh * 3600 + mi * 60 + ss - offset)
}

fn parse_time(input: &str, layout: Option<&str>) -> Result<i64, DslError> {
    let attempt = match layout {
        Some(layout) => parse_with_layout(input, layout),
        None => [
            "2006-01-02T15:04:05Z07:00",
            "2006-01-02 15:04:05",
            "2006-01-02T15:04:05",
            "2006-01-02",
        ]
        .iter()
        .find_map(|l| parse_with_layout(input, l)),
    };
    attempt.ok_or_else(|| DslError::Eval(format!("to_unix_time: cannot parse `{input}`")))
}
