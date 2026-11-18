//! The live-target executor: turns the user's targets and the live-scan
//! settings into a scope and limits, runs the selected templates through
//! `livenet` (the only code that opens connections), and maps what comes
//! back onto the shared [`Execution`].
//!
//! [`plan`] runs before any run is created: a target that does not parse, or
//! settings that cannot be used (an invalid proxy), are request errors and
//! nothing is sent. Everything after that belongs to one run.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use oxaudit_domain::NetworkExchangeEvidence;
use oxaudit_nuclei::TemplateMatch;

use super::exec::{redact_match, Execution, RawMatch, Subject, TargetSubject};
use super::select::Selected;
use super::{has_secret_tag, mask_value, NotEvaluatedRow, ResolvedHost, UnreachableTarget};
use crate::livenet::exchange::redact_url;
use crate::livenet::{
    self, Halt, LiveLimits, LiveProgress, LiveRunInput, LiveRunOutput, LiveTemplate, Scope,
    ScopeLimits,
};
use crate::models::LiveScanSettings;

/// Allowed ranges (the ones saving the settings enforces); a value outside
/// them, from a settings file written elsewhere, is clamped and the run
/// notes it.
use crate::models::{
    LIVE_PER_HOST_RANGE as PER_HOST, LIVE_RESPONSE_KB_RANGE as RESPONSE_KB, LIVE_RPS_RANGE as RPS,
    LIVE_TIMEOUT_SECONDS_RANGE as TIMEOUT_SECONDS,
};

/// Shortest matched or extracted value that is searched for and masked in
/// the stored request excerpt of a credential template.
const MIN_MASKED_VALUE_CHARS: usize = 4;

/// A live scan that passed its request checks: the parsed scope, the
/// limits, and notes about values that were clamped.
pub(crate) struct LivePlan {
    pub scope: Scope,
    pub limits: LiveLimits,
    pub notes: Vec<String>,
}

/// Parse the targets and build the limits. Called before the run exists,
/// so a bad target or unusable settings never create a run and never send
/// anything. The error names the offending target.
pub(crate) fn plan(
    targets: &[String],
    settings: &LiveScanSettings,
    rate_limit: Option<u32>,
) -> Result<LivePlan, String> {
    let scope = Scope::parse(targets, ScopeLimits::default())
        .map_err(|error| format!("invalid live target, so nothing was sent: {error}"))?;
    let (limits, notes) = limits(settings, rate_limit)?;
    Ok(LivePlan {
        scope,
        limits,
        notes,
    })
}

/// The run's limits from the settings snapshot, with the request's rate
/// limit (when given) in place of the settings' requests per second.
/// Numbers are clamped to their allowed ranges (each clamp is noted); the
/// result passes [`LiveLimits::validate`]. A proxy that is not an
/// `http://` or `https://` URL, or that carries credentials, is an error.
pub(crate) fn limits(
    settings: &LiveScanSettings,
    rate_limit: Option<u32>,
) -> Result<(LiveLimits, Vec<String>), String> {
    let mut notes = Vec::new();
    let mut clamp = |name: &str, value: u64, (low, high): (u64, u64)| -> u64 {
        let used = value.clamp(low, high);
        if used != value {
            notes.push(format!(
                "The live-scan {name} of {value} is outside {low} to {high}; {used} was used."
            ));
        }
        used
    };
    let rate_name = if rate_limit.is_some() {
        "rate limit for this scan (requests per second)"
    } else {
        "requests-per-second setting"
    };
    let requests_per_second = clamp(
        rate_name,
        u64::from(rate_limit.unwrap_or(settings.requests_per_second)),
        RPS,
    );
    let per_host = clamp(
        "concurrent requests per host",
        u64::from(settings.per_host_concurrency),
        PER_HOST,
    );
    let timeout = clamp(
        "timeout in seconds",
        u64::from(settings.timeout_seconds),
        TIMEOUT_SECONDS,
    );
    let response_kb = clamp(
        "response cap in KiB",
        u64::from(settings.max_response_kb),
        RESPONSE_KB,
    );
    let max_requests = clamp("request budget", settings.max_requests, (1, u64::MAX));
    let proxy = match settings
        .proxy
        .as_deref()
        .map(str::trim)
        .filter(|proxy| !proxy.is_empty())
    {
        None => None,
        Some(text) => {
            // The proxy text is not echoed: it may hold a credential.
            let url = reqwest::Url::parse(text).map_err(|error| {
                format!("The live-scan proxy setting is not a valid URL ({error}), so no scan was run. Fix or clear it in Settings.")
            })?;
            if !url.username().is_empty() || url.password().is_some() {
                return Err("The live-scan proxy setting carries a user name or password; credentials in the proxy URL are not supported because settings are not a secret store, so no scan was run. Use a proxy that does not need credentials in its URL.".into());
            }
            Some(url)
        }
    };
    let limits = LiveLimits {
        requests_per_second: u32::try_from(requests_per_second).unwrap_or(u32::MAX),
        per_host_concurrency: u32::try_from(per_host).unwrap_or(u32::MAX),
        timeout: Duration::from_secs(timeout),
        max_response_bytes: usize::try_from(response_kb * 1024).unwrap_or(usize::MAX),
        max_requests,
        proxy,
        ..LiveLimits::default()
    };
    limits.validate().map_err(|error| {
        format!("The live-scan settings cannot be used ({error}), so no scan was run.")
    })?;
    Ok((limits, notes))
}

/// Everything the live executor is given. The templates are already
/// filtered and sorted, are all supported, and all have at least one
/// network protocol block; `dos` and, unless switched on, intrusive
/// templates are already excluded (livenet refuses `dos` again).
pub(crate) struct LiveInput {
    pub plan: LivePlan,
    pub templates: Vec<Selected>,
    /// The work lease's cancel flag; livenet checks it before every attempt.
    pub cancel: Arc<AtomicBool>,
    pub progress: Arc<dyn Fn(LiveProgress) + Send + Sync>,
}

/// Run the selected templates against the planned scope. `RawMatch::template`
/// indexes `input.templates`. Unreachable targets, an exhausted request
/// budget, and any other reason the run did not finish make it Incomplete
/// (each with its own warning code); a cancellation sets
/// `Execution::cancelled`.
pub(crate) async fn run_live_targets(input: LiveInput) -> Result<Execution, String> {
    let LiveInput {
        plan,
        templates,
        cancel,
        progress,
    } = input;
    let live: Vec<LiveTemplate> = templates
        .iter()
        .map(|selected| LiveTemplate {
            template: selected.template.clone(),
            pack: selected.pack.clone(),
            file: selected.file.clone(),
        })
        .collect();
    let output = livenet::run_live(LiveRunInput {
        templates: &live,
        scope: plan.scope,
        limits: plan.limits,
        cancel,
        progress,
        user_agent_version: env!("CARGO_PKG_VERSION"),
    })
    .await;
    Ok(map_output(&templates, output, plan.notes))
}

/// The selected template a livenet row belongs to, by pack, file and id.
fn index_of(selected: &[Selected]) -> HashMap<(&str, &str, &str), usize> {
    selected
        .iter()
        .enumerate()
        .map(|(index, s)| {
            (
                (s.pack.as_str(), s.file.as_str(), s.template.id.as_str()),
                index,
            )
        })
        .collect()
}

pub(crate) fn map_output(
    selected: &[Selected],
    out: LiveRunOutput,
    plan_notes: Vec<String>,
) -> Execution {
    let index = index_of(selected);
    let mut exec = Execution {
        requests_sent: out.requests_sent,
        requests_refused: out.requests_refused,
        evaluated: out.evaluated as u64,
        notes: plan_notes,
        ..Execution::default()
    };

    for found in out.matches {
        let key = (
            found.pack.as_str(),
            found.file.as_str(),
            found.template_id.as_str(),
        );
        let Some(&template) = index.get(&key) else {
            exec.incomplete.push((
                "template_match_unattributed",
                format!(
                    "A match from template {} ({}/{}) against {} could not be attributed to a selected template and was not stored.",
                    found.template_id, found.pack, found.file, found.target
                ),
            ));
            continue;
        };
        let definition = &selected[template].template;
        let mut matched = found.matched;
        // The protocol the executor actually used for this exchange.
        matched.protocol = found.protocol;
        let mut exchange = found.evidence;
        if has_secret_tag(definition.tags()) {
            // Before `redact_match`, while the raw values are still known.
            let values = credential_values(&matched);
            matched.matched_at = redact_url(&mask_values(&matched.matched_at, &values), true);
            if let Some(exchange) = exchange.as_mut() {
                withhold_credentials(exchange, &values);
            }
        }
        redact_match(definition, &mut matched, None);
        exec.matches.push(RawMatch {
            template,
            found: matched,
            subject: Subject::Target(TargetSubject {
                target: found.target,
                exchange,
            }),
        });
    }

    for row in out.not_evaluated {
        exec.not_evaluated.push(NotEvaluatedRow {
            template_id: row.template_id,
            pack: row.pack,
            file: row.file,
            protocol: row.protocol.map(|protocol| protocol.as_str().to_owned()),
            target: (row.target != "*").then_some(row.target),
            reason: row.reason,
        });
    }

    for (target, reason) in out.unreachable_targets {
        exec.incomplete.push((
            "template_target_unreachable",
            format!(
                "Target {target} was not evaluated ({reason}); its templates were not evaluated against it."
            ),
        ));
        exec.unreachable.push(UnreachableTarget { target, reason });
    }

    if out.truncated > 0 {
        exec.incomplete.push((
            "template_plan_truncated",
            format!(
                "{} template check(s) were only partly evaluated because a planner cap cut their requests short (payload combinations, request conditions or iterate-all fan-out); each is listed as not evaluated with what was sent.",
                out.truncated
            ),
        ));
    }

    let halt_reason = out.halted.as_ref().map(|(_, reason)| reason.as_str());
    match &out.halted {
        Some((Halt::Cancelled, _)) => exec.cancelled = true,
        Some((Halt::BudgetExhausted, reason)) => exec.incomplete.push((
            "template_request_budget",
            format!(
                "The live scan stopped at its request budget: {reason}. The remaining checks were not evaluated."
            ),
        )),
        Some((Halt::TargetUnreachable, _)) | None => {}
    }
    for reason in out.incomplete_reasons {
        if Some(reason.as_str()) == halt_reason {
            continue;
        }
        exec.incomplete.push((
            "template_live_incomplete",
            format!("The live scan did not finish: {reason}."),
        ));
    }

    if out.requests_refused > 0 {
        exec.notes.push(format!(
            "{} request(s) were refused by scope and not sent; refused hosts: {}.",
            out.requests_refused,
            if out.refused_hosts.is_empty() {
                "none recorded".to_owned()
            } else {
                out.refused_hosts.join(", ")
            }
        ));
    }
    for (host, addresses) in &out.resolved {
        exec.notes.push(format!(
            "{host} was resolved once for this run to {}; every connection to it used these addresses.",
            addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    exec.notes.extend(out.notes);
    exec.refused_hosts = out.refused_hosts;
    exec.resolved = out
        .resolved
        .into_iter()
        .map(|(host, addresses)| ResolvedHost {
            host,
            addresses: addresses.iter().map(ToString::to_string).collect(),
        })
        .collect();
    exec
}

/// The matched and extracted values of a credential template that are long
/// enough to search for, longest first so a value containing another is
/// masked whole.
fn credential_values(matched: &TemplateMatch) -> Vec<String> {
    let mut values: Vec<String> = matched
        .extracted
        .iter()
        .flat_map(|(_, values)| values.iter())
        .chain(matched.matched_values.iter())
        .filter(|value| value.chars().count() >= MIN_MASKED_VALUE_CHARS)
        .cloned()
        .collect();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    values.dedup();
    values
}

/// `text` with every one of `values` replaced by its masked form.
fn mask_values(text: &str, values: &[String]) -> String {
    values.iter().fold(text.to_owned(), |text, value| {
        text.replace(value.as_str(), &mask_value(value))
    })
}

/// The request text with every query value of its request-line URL
/// redacted (a credential template may put the secret anywhere).
fn redact_request_line(request: &str) -> String {
    let (line, rest) = match request.find("\r\n") {
        Some(end) => request.split_at(end),
        None => (request, ""),
    };
    let mut parts: Vec<String> = line.splitn(3, ' ').map(str::to_owned).collect();
    if let Some(url) = parts.get_mut(1) {
        *url = redact_url(url, true);
    }
    format!("{}{rest}", parts.join(" "))
}

/// For a template that reports credentials, keep the exchange from carrying
/// the credential: the response body is withheld (an HTTP response keeps its
/// status line and already-redacted headers), and every matched or
/// extracted value (`credential_values`) is masked wherever it appears in
/// what is kept.
fn withhold_credentials(exchange: &mut NetworkExchangeEvidence, values: &[String]) {
    exchange.request = redact_request_line(&mask_values(&exchange.request, values));
    let kept = match exchange.response_excerpt.find("\r\n\r\n") {
        Some(end) if exchange.protocol == "http" => {
            format!(
                "{}\r\n\r\n[response body withheld: this template reports credentials]",
                mask_values(&exchange.response_excerpt[..end], values)
            )
        }
        _ => "[response withheld: this template reports credentials]".to_owned(),
    };
    exchange.response_excerpt = kept;
    exchange.response_truncated = true;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_become_limits_and_the_request_rate_overrides_the_setting() {
        let (built, notes) = limits(&LiveScanSettings::default(), None).unwrap();
        assert_eq!(built.requests_per_second, 50);
        assert_eq!(built.per_host_concurrency, 10);
        assert_eq!(built.timeout, Duration::from_secs(10));
        assert_eq!(built.max_response_bytes, 4096 * 1024);
        assert_eq!(built.max_requests, 100_000);
        assert!(built.proxy.is_none());
        assert!(notes.is_empty());

        let (built, _) = limits(&LiveScanSettings::default(), Some(7)).unwrap();
        assert_eq!(built.requests_per_second, 7, "the request's rate wins");
    }

    #[test]
    fn out_of_range_values_are_clamped_and_noted() {
        let settings = LiveScanSettings {
            requests_per_second: 0,
            per_host_concurrency: 500,
            timeout_seconds: 0,
            max_response_kb: 1_000_000,
            max_requests: 0,
            proxy: None,
        };
        let (built, notes) = limits(&settings, Some(5000)).unwrap();
        assert_eq!(built.requests_per_second, 1000);
        assert_eq!(built.per_host_concurrency, 100);
        assert_eq!(built.timeout, Duration::from_secs(1));
        assert_eq!(built.max_response_bytes, 32 * 1024 * 1024);
        assert_eq!(built.max_requests, 1);
        assert_eq!(notes.len(), 5, "{notes:?}");
        assert!(built.validate().is_ok());
    }

    #[test]
    fn a_proxy_must_be_an_http_url_without_credentials() {
        let with = |proxy: &str| LiveScanSettings {
            proxy: Some(proxy.into()),
            ..LiveScanSettings::default()
        };
        let (built, _) = limits(&with("http://proxy.invalid:3128"), None).unwrap();
        assert_eq!(built.proxy.unwrap().as_str(), "http://proxy.invalid:3128/");
        assert!(limits(&with("  "), None).unwrap().0.proxy.is_none());
        assert!(limits(&with("socks5://proxy.invalid:1080"), None)
            .unwrap_err()
            .contains("http:// or https://"));
        assert!(limits(&with("not a url"), None)
            .unwrap_err()
            .contains("not a valid URL"));
        let error = limits(&with("http://alice:s3cret@proxy.invalid:3128"), None).unwrap_err();
        assert!(error.contains("user name or password"), "{error}");
        assert!(!error.contains("s3cret"), "{error}");
    }

    #[test]
    fn a_planner_cap_makes_the_run_incomplete_with_its_own_code() {
        let out = LiveRunOutput {
            truncated: 2,
            evaluated: 3,
            ..LiveRunOutput::default()
        };
        let exec = map_output(&[], out, Vec::new());
        assert_eq!(exec.evaluated, 3);
        let (code, message) = exec
            .incomplete
            .iter()
            .find(|(code, _)| *code == "template_plan_truncated")
            .expect("a truncation reason");
        assert_eq!(*code, "template_plan_truncated");
        assert!(
            message.starts_with("2 template check(s) were only partly evaluated"),
            "{message}"
        );
    }

    #[test]
    fn a_bad_target_is_named_before_anything_runs() {
        let error = plan(
            &["http://127.0.0.1:8080".into(), "ftp://lab.invalid".into()],
            &LiveScanSettings::default(),
            None,
        )
        .err()
        .expect("refused");
        assert!(error.contains("target 2 (`ftp://lab.invalid`)"), "{error}");
        assert!(error.contains("nothing was sent"), "{error}");
    }

    #[test]
    fn credentials_are_withheld_from_the_exchange_of_a_credential_template() {
        let matched = TemplateMatch {
            template_id: "t".into(),
            name: "T".into(),
            severity: oxaudit_domain::Severity::High,
            matcher_names: Vec::new(),
            extracted: vec![("value".into(), vec!["AKIAIOSFODNN7EXAMPLE".into()])],
            protocol: oxaudit_nuclei::Protocol::Http,
            request_index: 0,
            matched_at: "http://127.0.0.1:1/".into(),
            lines: Vec::new(),
            matched_values: vec!["key=AKIAIOSFODNN7EXAMPLE".into()],
            warnings: Vec::new(),
        };
        let mut exchange = NetworkExchangeEvidence {
            artifact_id: oxaudit_domain::ArtifactId::new(),
            protocol: "http".into(),
            target: "http://127.0.0.1:1".into(),
            request: "GET http://127.0.0.1:1/?key=AKIAIOSFODNN7EXAMPLE HTTP/1.1\r\n\r\n".into(),
            response_excerpt: "HTTP/1.1 200 OK\r\nX-Echo: AKIAIOSFODNN7EXAMPLE\r\n\r\nkey=AKIAIOSFODNN7EXAMPLE other=hunter2".into(),
            response_truncated: false,
            matcher_names: Vec::new(),
            extracted: Vec::new(),
        };
        let values = credential_values(&matched);
        assert_eq!(values[0], "key=AKIAIOSFODNN7EXAMPLE", "longest first");
        // Every query value of the request line goes, not just the matched one.
        assert_eq!(
            redact_request_line("GET http://h.test/?q=visible&n=2 HTTP/1.1\r\nHost: h\r\n\r\n"),
            "GET http://h.test/?q=[REDACTED]&n=[REDACTED] HTTP/1.1\r\nHost: h\r\n\r\n"
        );
        assert_eq!(
            mask_values("https://x.test/?k=AKIAIOSFODNN7EXAMPLE", &values),
            "https://x.test/?k=AKIA\u{2026} (20 chars)"
        );
        withhold_credentials(&mut exchange, &values);
        for text in [&exchange.request, &exchange.response_excerpt] {
            assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "{text}");
        }
        assert!(!exchange.response_excerpt.contains("hunter2"));
        assert!(exchange.response_excerpt.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(exchange
            .response_excerpt
            .ends_with("[response body withheld: this template reports credentials]"));
        assert!(exchange.response_truncated);

        let mut tcp = NetworkExchangeEvidence {
            protocol: "tcp".into(),
            response_excerpt: "AKIAIOSFODNN7EXAMPLE".into(),
            ..exchange.clone()
        };
        withhold_credentials(&mut tcp, &values);
        assert_eq!(
            tcp.response_excerpt,
            "[response withheld: this template reports credentials]"
        );
    }
}
