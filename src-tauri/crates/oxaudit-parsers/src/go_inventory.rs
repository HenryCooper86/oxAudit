//! Static Go declarations. go.sum is checksum history, never a selected build list.
use std::collections::{BTreeMap, BTreeSet};

use crate::models::{Dependency, DependencyOccurrence};

pub const SCOPE_NOTE: &str = "Go inventory is based on go.mod requirements and replacements. Static files do not establish the selected transitive/workspace build list; go.sum checksum history is excluded. Advisory coverage applies only to these declared coordinates.";

fn version(value: &str) -> bool {
    static VERSION: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$").unwrap()
    });
    if !VERSION.is_match(value) {
        return false;
    }
    let without_build = value.split('+').next().unwrap();
    without_build.split_once('-').map_or(true, |(_, pre)| {
        pre.split('.').all(|part| {
            !part.is_empty()
                && !(part.len() > 1
                    && part.starts_with('0')
                    && part.bytes().all(|c| c.is_ascii_digit()))
        })
    })
}

fn module(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "()=><\\\"`".contains(c))
}

fn local(value: &str) -> bool {
    matches!(value, "." | "..")
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with(".\\")
        || value.starts_with("..\\")
        || value.starts_with('\\')
        || value.as_bytes().get(1) == Some(&b':')
}

/// Go interpreted literals permit octal, hex and Unicode escapes, unlike JSON.
fn unquote(value: &str) -> Result<String, String> {
    let mut chars = value[1..value.len() - 1].chars();
    let mut bytes = Vec::new();
    while let Some(c) = chars.next() {
        if c != '\\' {
            bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
            continue;
        }
        let escape = chars.next().ok_or("incomplete Go string escape")?;
        let simple = match escape {
            'a' => Some(7),
            'b' => Some(8),
            'f' => Some(12),
            'n' => Some(b'\n'),
            'r' => Some(b'\r'),
            't' => Some(b'\t'),
            'v' => Some(11),
            '\\' => Some(b'\\'),
            '"' => Some(b'"'),
            _ => None,
        };
        if let Some(byte) = simple {
            bytes.push(byte);
            continue;
        }
        let (digits, radix, mut number) = match escape {
            'x' => (2, 16, 0),
            'u' => (4, 16, 0),
            'U' => (8, 16, 0),
            '0'..='7' => (2, 8, escape.to_digit(8).unwrap()),
            _ => return Err("invalid Go string escape".into()),
        };
        for _ in 0..digits {
            let digit = chars
                .next()
                .and_then(|c| c.to_digit(radix))
                .ok_or("invalid Go string escape digits")?;
            number = number
                .checked_mul(radix)
                .and_then(|n| n.checked_add(digit))
                .ok_or("Go string escape is out of range")?;
        }
        if escape == 'u' || escape == 'U' {
            let c = char::from_u32(number).ok_or("invalid Go Unicode escape")?;
            bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        } else {
            bytes.push(u8::try_from(number).map_err(|_| "Go byte escape is out of range")?);
        }
    }
    String::from_utf8(bytes).map_err(|_| "Go path string is not UTF-8".into())
}

/// Tokenize comments and quoted paths without treating // inside strings as a comment.
fn tokens(line: &str) -> Result<Vec<String>, String> {
    let mut chars = line.chars().peekable();
    let mut out = Vec::new();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            break;
        }
        if c == '"' || c == '`' {
            let mut quoted = String::from(c);
            let mut closed = false;
            while let Some(next) = chars.next() {
                quoted.push(next);
                if next == c {
                    closed = true;
                    break;
                }
                if next == '\\' && c == '"' {
                    quoted.push(chars.next().ok_or("unterminated quoted Go token")?);
                }
            }
            if !closed {
                return Err("unterminated quoted Go token".into());
            }
            out.push(if c == '`' {
                quoted[1..quoted.len() - 1].into()
            } else {
                unquote(&quoted)?
            });
        } else if c == '(' || c == ')' {
            out.push(c.to_string());
        } else if c == '=' && chars.peek() == Some(&'>') {
            chars.next();
            out.push("=>".into());
        } else {
            let mut token = String::from(c);
            while let Some(&next) = chars.peek() {
                if next.is_whitespace() || "()\"`".contains(next) {
                    break;
                }
                if next == '=' {
                    let mut lookahead = chars.clone();
                    lookahead.next();
                    if lookahead.peek() == Some(&'>') {
                        break;
                    }
                }
                if next == '/' {
                    let mut lookahead = chars.clone();
                    lookahead.next();
                    if lookahead.peek() == Some(&'/') {
                        break;
                    }
                }
                token.push(chars.next().unwrap());
            }
            out.push(token);
        }
    }
    Ok(out)
}

pub fn parse(content: &str, lockfile: &str) -> Result<Vec<Dependency>, String> {
    static GO_VERSION: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^([1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?([a-z]+[0-9]+)?$")
            .unwrap()
    });
    let mut requirements = Vec::new();
    let mut required_names = BTreeSet::new();
    let mut replacements = BTreeMap::new();
    let mut excluded = BTreeSet::new();
    let mut block: Option<String> = None;
    let mut saw_module = false;
    let mut saw_go = false;
    let mut saw_toolchain = false;
    for (index, line) in content.lines().enumerate() {
        let tokens = tokens(line).map_err(|e| format!("invalid go.mod line {}: {e}", index + 1))?;
        if tokens.is_empty() {
            continue;
        }
        let invalid = || format!("invalid go.mod directive on line {}", index + 1);
        if tokens == [")"] {
            if block.take().is_none() {
                return Err(invalid());
            }
            continue;
        }
        let (directive, args) = match block.as_deref() {
            Some(directive) => (directive, tokens.as_slice()),
            None => {
                if tokens.get(1).map(String::as_str) == Some("(") {
                    if !matches!(
                        tokens[0].as_str(),
                        "require"
                            | "exclude"
                            | "replace"
                            | "retract"
                            | "tool"
                            | "godebug"
                            | "ignore"
                    ) {
                        return Err(invalid());
                    }
                    if tokens.len() == 3 && tokens[2] == ")" {
                        continue;
                    }
                    if tokens.len() != 2 {
                        return Err(invalid());
                    }
                    block = Some(tokens[0].clone());
                    continue;
                }
                (tokens[0].as_str(), &tokens[1..])
            }
        };
        match directive {
            "module" => {
                if saw_module || args.len() != 1 || !module(&args[0]) {
                    return Err(invalid());
                }
                saw_module = true;
            }
            "require" | "exclude" => {
                if args.len() != 2 || !module(&args[0]) || !version(&args[1]) {
                    return Err(invalid());
                }
                if directive == "exclude" {
                    excluded.insert((args[0].clone(), args[1].clone()));
                } else {
                    if !required_names.insert(args[0].clone()) {
                        return Err(invalid());
                    }
                    requirements.push((args[0].clone(), args[1].clone()));
                }
            }
            "replace" => {
                let arrow = args.iter().position(|s| s == "=>").ok_or_else(invalid)?;
                let (left, right) = (&args[..arrow], &args[arrow + 1..]);
                if !(1..=2).contains(&left.len())
                    || !(1..=2).contains(&right.len())
                    || !module(&left[0])
                    || (left.len() == 2 && !version(&left[1]))
                    || (local(&right[0]) && right.len() != 1)
                    || (!local(&right[0])
                        && (right.len() != 2 || !module(&right[0]) || !version(&right[1])))
                {
                    return Err(invalid());
                }
                let key = (left[0].clone(), left.get(1).cloned());
                if replacements.insert(key, right.to_vec()).is_some() {
                    return Err(invalid());
                }
            }
            "go" => {
                if saw_go || args.len() != 1 || !GO_VERSION.is_match(&args[0]) {
                    return Err(invalid());
                }
                saw_go = true;
            }
            "toolchain" => {
                if saw_toolchain
                    || args.len() != 1
                    || !(args[0] == "default" || args[0] == "go1" || args[0].starts_with("go1."))
                {
                    return Err(invalid());
                }
                saw_toolchain = true;
            }
            "tool" | "ignore" => {
                if args.len() != 1 || !module(&args[0]) {
                    return Err(invalid());
                }
            }
            "godebug" => {
                if args.len() != 1
                    || !args[0].contains('=')
                    || args[0].contains([',', '"', '`', '\''])
                {
                    return Err(invalid());
                }
            }
            "retract" => {
                let interval = args.join(" ");
                let valid = if args.len() == 1 && version(&args[0]) {
                    true
                } else if let Some(inner) =
                    interval.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
                {
                    inner
                        .split_once(',')
                        .is_some_and(|(low, high)| version(low.trim()) && version(high.trim()))
                } else {
                    false
                };
                if !valid {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
    }
    if block.is_some() {
        return Err("invalid go.mod: unterminated directive block".into());
    }
    if !saw_module {
        return Err("invalid go.mod: missing module directive".into());
    }
    let mut out = Vec::new();
    for (name, declared) in requirements {
        if excluded.contains(&(name.clone(), declared.clone())) {
            return Err(format!("go.mod excludes required {name}@{declared}; resolve the selected build list before scanning"));
        }
        let replacement = replacements
            .get(&(name.clone(), Some(declared.clone())))
            .or_else(|| replacements.get(&(name.clone(), None)));
        let mut occurrence = DependencyOccurrence {
            status: "unavailable".into(),
            warnings: vec![SCOPE_NOTE.into()],
            ..Default::default()
        };
        let (resolved_name, resolved_version) = if let Some(target) = replacement {
            occurrence.warnings.push(format!(
                "Go replacement for {name}@{declared}: {}",
                target.join(" ")
            ));
            if local(&target[0]) {
                occurrence.local_workspace = true;
                occurrence.source = Some("local".into());
                occurrence.warnings.push("Local replacement has no registry version; advisory lookup is skipped. Review its source code.".into());
                (name, String::new())
            } else {
                (target[0].clone(), target[1].trim_start_matches('v').into())
            }
        } else {
            (name, declared.trim_start_matches('v').into())
        };
        out.push(Dependency {
            name: resolved_name,
            version: resolved_version,
            ecosystem: "Go".into(),
            occurrence,
            lockfile: lockfile.into(),
            license: None,
        });
    }
    Ok(out)
}

pub fn validate_sums(content: &str) -> Result<(), String> {
    for (index, line) in content.lines().enumerate() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.len() != 3
            || !module(fields[0])
            || !version(fields[1].strip_suffix("/go.mod").unwrap_or(fields[1]))
            || !fields[2].starts_with("h1:")
            || fields[2].len() <= 3
        {
            return Err(format!("invalid go.sum checksum row on line {}", index + 1));
        }
    }
    Ok(())
}
