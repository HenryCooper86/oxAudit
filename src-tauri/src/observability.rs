//! Logging and the diagnostics bundle.
//!
//! Before this existed the entire backend carried one `log::warn!` and three
//! `eprintln!`. A desktop tool cannot be debugged over the user's shoulder, so
//! when a scan died on someone's 400k-file monorepo the whole bug report was
//! "it stopped working".
//!
//! Two things follow from oxAudit being a *security* tool rather than an
//! ordinary desktop app:
//!
//! * **Nothing leaves the machine.** Logs are written to a file under the app
//!   data directory and stay there. There is no telemetry endpoint, no crash
//!   reporter, and no opt-out to explain, because there is nothing to opt out
//!   of. The user copies a bundle and decides who sees it.
//! * **The bundle is redacted before the user sees it, not after.** oxAudit
//!   handles API keys, scan targets that are often client code under NDA, and
//!   detected secrets. A diagnostics feature that leaks any of those is worse
//!   than no diagnostics feature.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Serialize;

/// Where the log file lives, once logging has started.
static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Keeps the non-blocking writer alive for the process's lifetime.
static GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

/// How much of the log tail a diagnostics bundle carries.
///
/// Enough to cover a failed scan, small enough to paste into an issue.
const TAIL_BYTES: u64 = 256 * 1024;

/// Start logging to `<app_data>/logs/oxaudit.log`.
///
/// Safe to call more than once; later calls do nothing. Failing to open the
/// file is not fatal — the application runs without a log rather than refusing
/// to start, which is the right trade for a diagnostic aid.
pub fn init(app_data_root: &Path) {
    if LOG_PATH.get().is_some() {
        return;
    }
    let directory = app_data_root.join("logs");
    if std::fs::create_dir_all(&directory).is_err() {
        return;
    }

    let appender = tracing_appender::rolling::daily(&directory, "oxaudit.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);

    // `info` by default; RUST_LOG overrides it for anyone chasing something
    // specific. Deliberately not user-configurable in the GUI: a setting that
    // silently raises verbosity is a setting that silently fills a disk.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_level(true)
        .finish();

    if tracing::subscriber::set_global_default(subscriber).is_err() {
        return;
    }
    let _ = GUARD.set(guard);
    let _ = LOG_PATH.set(directory.join("oxaudit.log"));

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "oxAudit started");
}

/// The directory logs are written to, if logging started.
pub fn log_directory() -> Option<PathBuf> {
    LOG_PATH
        .get()
        .and_then(|path| path.parent().map(Path::to_path_buf))
}

/// What a person needs in order to reproduce a problem, and nothing else.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    pub version: String,
    pub os: String,
    pub architecture: String,
    /// Whether an AI endpoint is configured. Never the URL, which is sometimes
    /// an internal host, and never the key.
    pub ai_configured: bool,
    pub log_path: Option<String>,
    pub log_bytes: u64,
    /// The tail of the log, with credentials and home directories removed.
    pub log_tail: String,
    pub notes: Vec<String>,
}

/// Build a diagnostics bundle from the current process state.
pub fn collect(ai_configured: bool, home: Option<&Path>) -> Diagnostics {
    let mut notes = Vec::new();
    let log_path = LOG_PATH.get().cloned();

    let (log_bytes, log_tail) = match &log_path {
        Some(path) => match read_tail(path, TAIL_BYTES) {
            Ok((size, tail)) => (size, redact(&tail, home)),
            Err(error) => {
                notes.push(format!("the log could not be read: {error}"));
                (0, String::new())
            }
        },
        None => {
            notes.push(
                "logging is not running, so no log is included; the rest of the bundle still \
                 applies"
                    .to_string(),
            );
            (0, String::new())
        }
    };

    notes.push(
        "Credentials, tokens, and home directory paths are removed from the log before it \
         reaches this bundle. Read it before sharing it anyway — a scan target's file names can \
         themselves be sensitive."
            .to_string(),
    );

    Diagnostics {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        ai_configured,
        log_path: log_path.map(|path| path.display().to_string()),
        log_bytes,
        log_tail,
        notes,
    }
}

/// Read at most `limit` bytes from the end of a file.
fn read_tail(path: &Path, limit: u64) -> std::io::Result<(u64, String)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    if size > limit {
        file.seek(SeekFrom::Start(size - limit))?;
    }
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok((size, String::from_utf8_lossy(&buffer).into_owned()))
}

/// Remove anything credential-shaped, plus the user's home directory.
///
/// This runs over log text, which oxAudit controls, so the goal is to catch
/// what could plausibly have been written rather than to parse arbitrary input.
/// It errs toward over-redaction: a redacted line that was harmless costs
/// nothing, and a leaked key costs a rotation at best.
pub fn redact(text: &str, home: Option<&Path>) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    // Vendor-shaped tokens, matched by prefix rather than by entropy.
    static TOKENS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?x)
            \b(?:
                  (?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}
                | github_pat_[A-Za-z0-9_]{20,}
                | glpat-[A-Za-z0-9_\-]{15,}
                | xox[baprs]-[0-9A-Za-z\-]{10,}
                | (?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{10,}
                | sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}
                | AIza[0-9A-Za-z_\-]{30,}
                | (?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
                | npm_[A-Za-z0-9]{30,}
                | hf_[A-Za-z0-9]{30,}
                | eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}
            )\b",
        )
        .expect("token redaction pattern")
    });

    // Anything assigned to a credential-shaped name, whatever its shape.
    static ASSIGNMENTS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)((?:api[_-]?key|apikey|token|secret|password|passwd|pwd|credential|authorization|bearer)[^A-Za-z0-9\r\n]{0,4})([A-Za-z0-9_\-\.=+/]{8,})"#,
        )
        .expect("assignment redaction pattern")
    });

    // Credentials embedded in a URL.
    static URL_AUTH: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@").expect("url auth"));

    let mut out = TOKENS.replace_all(text, "[REDACTED]").into_owned();
    out = ASSIGNMENTS.replace_all(&out, "${1}[REDACTED]").into_owned();
    out = URL_AUTH.replace_all(&out, "${1}[REDACTED]@").into_owned();

    // The home directory carries the user's name, and scan paths carry client
    // project names. Neither belongs in a bundle destined for an issue tracker.
    if let Some(home) = home {
        let home = home.to_string_lossy();
        if home.len() > 3 {
            out = out.replace(home.as_ref(), "~");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_tokens_are_removed() {
        for token in [
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "glpat-abcdefghijklmnopqrst",
            "xoxb-1234567890-abcdefghij",
            "sk_live_abcdefghij0123456789",
            "sk-ant-abcdefghijklmnopqrstuvwxyz",
            "AKIAIOSFODNN7EXAMPLE",
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        ] {
            let line = format!("provider call failed with {token} at 12:00");
            let redacted = redact(&line, None);
            assert!(
                !redacted.contains(token),
                "{token} survived redaction: {redacted}"
            );
            assert!(redacted.contains("[REDACTED]"));
        }
    }

    #[test]
    fn a_jwt_is_removed() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQabcdefghij";
        assert!(!redact(jwt, None).contains("eyJhbGciOiJIUzI1NiJ9"));
    }

    #[test]
    fn a_value_assigned_to_a_credential_name_is_removed_whatever_its_shape() {
        // The vendor list can never be complete, so the second pass catches
        // anything sitting next to a credential-shaped name.
        let line = r#"loaded settings: api_key="Zx8Z2vQ4mNbR7tYuI1oP3aS5dF6gH9jK" model=gpt"#;
        let redacted = redact(line, None);
        assert!(
            !redacted.contains("Zx8Z2vQ4mNbR7tYuI1oP3aS5dF6gH9jK"),
            "{redacted}"
        );
        assert!(redacted.contains("[REDACTED]"));
        // Non-credential context is preserved, or the log stops being useful.
        assert!(redacted.contains("model=gpt"));
    }

    #[test]
    fn credentials_in_a_url_are_removed_but_the_host_is_kept() {
        let line = "fetching https://alice:hunter2@internal.example/advisories";
        let redacted = redact(line, None);
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("alice"));
        // The host is what makes the line diagnostic.
        assert!(redacted.contains("internal.example"), "{redacted}");
    }

    #[test]
    fn the_home_directory_is_replaced() {
        let line = "scanning /Users/alice/clients/acme-corp/src";
        let redacted = redact(line, Some(Path::new("/Users/alice")));
        assert!(!redacted.contains("alice"), "{redacted}");
        assert!(redacted.starts_with("scanning ~/clients"), "{redacted}");
    }

    #[test]
    fn a_short_home_path_is_not_substituted() {
        // Replacing "/" everywhere would destroy the log.
        let line = "scanning /srv/project";
        assert_eq!(redact(line, Some(Path::new("/"))), line);
    }

    #[test]
    fn ordinary_log_lines_survive_intact() {
        let line = "scan completed: 339 files, 34 findings, 2229 ms";
        assert_eq!(redact(line, None), line);
    }

    #[test]
    fn the_bundle_never_carries_the_endpoint_or_the_key() {
        let diagnostics = collect(true, None);
        let serialized = serde_json::to_string(&diagnostics).expect("serializable");
        // `aiConfigured` is a boolean on purpose: the base URL is sometimes an
        // internal host, and the key is never in memory here at all.
        assert!(serialized.contains("\"aiConfigured\":true"));
        assert!(!serialized.contains("baseUrl"));
        assert!(!serialized.contains("apiKey"));
    }

    #[test]
    fn the_bundle_says_so_when_logging_is_not_running() {
        // Tests run without init(), which is the same state as a user whose
        // log file could not be opened. Silence there would be misread as
        // "nothing happened".
        let diagnostics = collect(false, None);
        assert!(
            diagnostics
                .notes
                .iter()
                .any(|note| note.contains("logging is not running")),
            "{:?}",
            diagnostics.notes
        );
    }

    #[test]
    fn the_bundle_tells_the_reader_to_check_it_before_sharing() {
        let diagnostics = collect(false, None);
        assert!(diagnostics
            .notes
            .iter()
            .any(|note| note.contains("before sharing")));
    }

    #[test]
    fn reading_a_tail_returns_only_the_end_of_a_large_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("big.log");
        let body: String = (0..5_000).map(|index| format!("line {index}\n")).collect();
        std::fs::write(&path, &body).expect("write");

        let (size, tail) = read_tail(&path, 1_024).expect("tail");
        assert_eq!(size as usize, body.len());
        assert!(tail.len() <= 1_024);
        // The tail is the *end*, which is where a failure is.
        assert!(tail.contains("line 4999"));
        assert!(!tail.contains("line 0\n"));
    }

    #[test]
    fn a_small_file_is_returned_whole() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("small.log");
        std::fs::write(&path, "one\ntwo\n").expect("write");
        let (size, tail) = read_tail(&path, 1_024).expect("tail");
        assert_eq!(size, 8);
        assert_eq!(tail, "one\ntwo\n");
    }
}
