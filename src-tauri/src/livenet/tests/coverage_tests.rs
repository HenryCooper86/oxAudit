//! Coverage honesty: planner caps, checks that got no answer, and template
//! evaluation warnings are all reported, never dropped.

use super::support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ip_target_with_only_dns_templates_evaluates_nothing_and_is_listed() {
    let t = template(
        "dns-only",
        "dns:\n  - name: \"{{FQDN}}\"\n    type: A\n    matchers:\n      - type: word\n        words: [IN]\n",
    );
    let out = run(&[t], &["10.0.0.9".to_string()], fast_limits(), plain_deps()).await;
    assert_eq!(out.evaluated, 0);
    assert_eq!(out.requests_sent, 0);
    let (target, reason) = out
        .unreachable_targets
        .first()
        .expect("the target is listed as not evaluated");
    assert_eq!(target, "10.0.0.9");
    assert!(
        reason.contains("no request of any template was answered"),
        "{reason}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_request_skipped_for_an_unresolved_variable_evaluates_nothing() {
    let server = serve(|_| Reply::now(response(200, &[], b"ok"))).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let t = template(
        "unresolved",
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/{{never_defined}}\"\n    matchers:\n      - type: status\n        status: [200]\n",
    );
    let out = run(
        &[t],
        std::slice::from_ref(&target),
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(server.hits(), 0);
    assert_eq!(out.evaluated, 0);
    assert!(
        out.not_evaluated[0].reason.contains("never_defined"),
        "{out:?}"
    );
    assert!(
        out.unreachable_targets.iter().any(|(t, _)| *t == target),
        "{:?}",
        out.unreachable_targets
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_errors_count_as_an_unanswered_target() {
    // Not HTTP at all: every exchange fails after the connection is made.
    let server = serve(|_| Reply::now(b"\x00\x01garbage that is not HTTP\r\n\r\n".to_vec())).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let out = run(
        &get_templates(1, "/"),
        std::slice::from_ref(&target),
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert!(server.hits() >= 1);
    assert_eq!(out.evaluated, 0);
    let (_, reason) = out
        .unreachable_targets
        .iter()
        .find(|(t, _)| *t == target)
        .expect("listed");
    assert!(reason.contains("exchange failed"), "{reason}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answered_check_counts_as_evaluated() {
    let server = serve(|_| Reply::now(response(404, &[], b"nope"))).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let out = run(
        &get_templates(2, "/"),
        &[target],
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(out.evaluated, 2);
    assert!(out.unreachable_targets.is_empty(), "{out:?}");
    assert!(out.matches.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_planner_cap_is_a_partly_evaluated_row_and_counted() {
    let server = serve(|_| Reply::now(response(200, &[], b"ok"))).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let values = (0..65)
        .map(|i| format!("'v{i}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let t = template(
        "conditions",
        &format!(
            "http:\n  - method: GET\n    path:\n      - \"{{{{BaseURL}}}}/{{{{p}}}}\"\n    payloads:\n      p: [{values}]\n    req-condition: true\n    matchers:\n      - type: dsl\n        dsl: ['status_code_1 == 200 && status_code_2 == 500']\n"
        ),
    );
    let out = run(
        &[t],
        std::slice::from_ref(&target),
        fast_limits(),
        plain_deps(),
    )
    .await;
    assert_eq!(server.hits(), 65);
    assert_eq!(out.evaluated, 1);
    assert_eq!(out.truncated, 1);
    let row = out
        .not_evaluated
        .iter()
        .find(|row| row.reason.starts_with("partly evaluated:"))
        .expect("a partly evaluated row");
    assert_eq!(row.target, target);
    assert!(
        row.reason.contains("request conditions disabled"),
        "{}",
        row.reason
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn template_evaluation_warnings_become_deduplicated_notes() {
    let server = serve(|_| Reply::now(response(200, &[], b"ok"))).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let t = template(
        "warns",
        "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a\"\n      - \"{{BaseURL}}/b\"\n    matchers:\n      - type: dsl\n        dsl: ['missing_var == 1']\n",
    );
    let out = run(&[t], &[target], fast_limits(), plain_deps()).await;
    assert_eq!(server.hits(), 2);
    let warnings: Vec<&String> = out
        .notes
        .iter()
        .filter(|n| n.contains("unknown variable `missing_var`"))
        .collect();
    assert_eq!(warnings.len(), 1, "{:?}", out.notes);
    assert!(
        warnings[0].starts_with("warns (warns.yaml): "),
        "{}",
        warnings[0]
    );
}
