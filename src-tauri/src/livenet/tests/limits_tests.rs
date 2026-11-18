use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::support::*;
use crate::livenet::limits::{Governor, Halt, LiveLimits};

#[test]
fn limits_validation() {
    assert!(LiveLimits::default().validate().is_ok());
    let d = LiveLimits::default();
    assert_eq!(d.requests_per_second, 50);
    assert_eq!(d.per_host_concurrency, 10);
    assert_eq!(d.timeout, Duration::from_secs(10));
    assert_eq!(d.max_response_bytes, 4 * 1024 * 1024);
    assert_eq!(d.max_requests, 100_000);
    assert_eq!(d.max_redirects_cap, 10);
    let bad = [
        LiveLimits {
            requests_per_second: 0,
            ..d.clone()
        },
        LiveLimits {
            requests_per_second: 1001,
            ..d.clone()
        },
        LiveLimits {
            per_host_concurrency: 0,
            ..d.clone()
        },
        LiveLimits {
            per_host_concurrency: 101,
            ..d.clone()
        },
        LiveLimits {
            timeout: Duration::from_millis(500),
            ..d.clone()
        },
        LiveLimits {
            timeout: Duration::from_secs(121),
            ..d.clone()
        },
        LiveLimits {
            max_response_bytes: 0,
            ..d.clone()
        },
        LiveLimits {
            max_response_bytes: 32 * 1024 * 1024 + 1,
            ..d.clone()
        },
        LiveLimits {
            max_requests: 0,
            ..d.clone()
        },
        LiveLimits {
            max_redirects_cap: 11,
            ..d.clone()
        },
        LiveLimits {
            max_host_errors: 0,
            ..d.clone()
        },
        LiveLimits {
            proxy: Some(reqwest::Url::parse("socks5://127.0.0.1:1080").expect("url")),
            ..d.clone()
        },
    ];
    for l in bad {
        assert!(l.validate().is_err(), "{l:?}");
    }
}

#[tokio::test]
async fn rate_limiter_spaces_requests() {
    let limits = LiveLimits {
        requests_per_second: 10,
        ..LiveLimits::default()
    };
    let gov = Governor::new(&limits, Arc::new(AtomicBool::new(false)));
    let start = Instant::now();
    for _ in 0..6 {
        drop(gov.admit("h", None).await.expect("admitted"));
    }
    // Six tokens at 10/s: the first is immediate, the rest 100 ms apart.
    assert!(
        start.elapsed() >= Duration::from_millis(480),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(gov.sent(), 6);
}

#[tokio::test]
async fn budget_and_cancellation_stop_admission() {
    let limits = LiveLimits {
        requests_per_second: 1000,
        max_requests: 3,
        ..LiveLimits::default()
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let gov = Governor::new(&limits, cancel.clone());
    for _ in 0..3 {
        drop(gov.admit("h", None).await.expect("within budget"));
    }
    assert_eq!(
        gov.admit("h", None).await.err(),
        Some(Halt::BudgetExhausted)
    );
    assert_eq!(gov.sent(), 3);
    assert_eq!(gov.halted(), Some(Halt::BudgetExhausted));

    let gov = Governor::new(&LiveLimits::default(), cancel.clone());
    cancel.store(true, Ordering::SeqCst);
    assert_eq!(gov.admit("h", None).await.err(), Some(Halt::Cancelled));
    assert_eq!(gov.sent(), 0);

    let gov = Governor::new(&LiveLimits::default(), Arc::new(AtomicBool::new(false)));
    let dead = AtomicBool::new(true);
    assert_eq!(
        gov.admit("h", Some(&dead)).await.err(),
        Some(Halt::TargetUnreachable)
    );
    assert_eq!(gov.sent(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_respects_the_rate_limit() {
    let server = serve(|_| Reply::now(response(200, &[], b"ok"))).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let limits = LiveLimits {
        requests_per_second: 5,
        ..fast_limits()
    };
    let start = Instant::now();
    let out = run(&get_templates(6, "/"), &[target], limits, plain_deps()).await;
    assert_eq!(out.requests_sent, 6);
    assert_eq!(server.hits(), 6);
    assert!(
        start.elapsed() >= Duration::from_millis(950),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_host_concurrency_is_never_exceeded() {
    let server = serve(|_| Reply {
        bytes: response(200, &[], b"ok"),
        delay: Duration::from_millis(150),
    })
    .await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let limits = LiveLimits {
        per_host_concurrency: 2,
        ..fast_limits()
    };
    let out = run(&get_templates(10, "/"), &[target], limits, plain_deps()).await;
    assert_eq!(out.matches.len(), 10);
    let peak = server.max_in_flight.load(Ordering::SeqCst);
    assert!(peak <= 2, "peak in flight {peak}");
    assert_eq!(peak, 2, "the limit is used, not serialised further");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_requests_stops_the_run() {
    let server = serve(|_| Reply::now(response(200, &[], b"ok"))).await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let limits = LiveLimits {
        max_requests: 3,
        per_host_concurrency: 1,
        ..fast_limits()
    };
    let out = run(&get_templates(8, "/"), &[target], limits, plain_deps()).await;
    assert_eq!(out.requests_sent, 3);
    assert_eq!(server.hits(), 3);
    assert!(
        out.incomplete_reasons.iter().any(|r| r.contains("budget")),
        "{:?}",
        out.incomplete_reasons
    );
    assert!(out
        .not_evaluated
        .iter()
        .any(|n| n.reason.contains("budget")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_target_cut_off() {
    let port = closed_port().await;
    let target = format!("http://127.0.0.1:{port}");
    let limits = LiveLimits {
        max_host_errors: 3,
        per_host_concurrency: 1,
        ..fast_limits()
    };
    let out = run(
        &get_templates(40, "/"),
        std::slice::from_ref(&target),
        limits,
        plain_deps(),
    )
    .await;
    assert_eq!(out.requests_sent, 3, "attempts stop at the cut-off");
    assert_eq!(out.unreachable_targets.len(), 1);
    assert_eq!(out.unreachable_targets[0].0, target);
    assert_eq!(
        out.not_evaluated.len(),
        40,
        "every template is listed as not evaluated: {:?}",
        out.not_evaluated
    );
    assert!(out
        .not_evaluated
        .iter()
        .any(|n| n.reason.contains("stopped answering") || n.reason.contains("unreachable")));
    assert!(
        out.incomplete_reasons.is_empty(),
        "an unreachable target is not a failed run"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_returns_promptly_and_sends_nothing_more() {
    let server = serve(|_| Reply {
        bytes: response(200, &[], b"ok"),
        delay: Duration::from_millis(200),
    })
    .await;
    let target = format!("http://127.0.0.1:{}", server.port());
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        flag.store(true, Ordering::SeqCst);
    });
    let limits = LiveLimits {
        per_host_concurrency: 2,
        ..fast_limits()
    };
    let start = Instant::now();
    let out = run_with_cancel(
        &get_templates(100, "/"),
        &[target],
        limits,
        plain_deps(),
        cancel,
    )
    .await;
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert!(out
        .incomplete_reasons
        .iter()
        .any(|r| r.contains("cancelled")));
    assert!(out.requests_sent < 100);
    let hits_at_return = server.hits();
    assert_eq!(hits_at_return as u64, out.requests_sent);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        server.hits(),
        hits_at_return,
        "nothing is sent after the run returns"
    );
    assert!(out
        .not_evaluated
        .iter()
        .any(|n| n.reason.contains("cancelled")));
}
