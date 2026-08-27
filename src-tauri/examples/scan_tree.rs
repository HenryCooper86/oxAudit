//! Reproduce the native scanner's measurements outside the app.
//!
//! `cargo run --release --example scan_tree -- <path> [--enrich]`
//!
//! `--enrich` performs live NVD and OSV lookups, which is how the numbers in
//! docs/binary-scanning-runtime.md were taken.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use oxaudit_lib::binscan::native::{enrich, scan};
use oxaudit_lib::cve::CveState;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let root = args.next().expect("usage: scan_tree <path> [--enrich]");
    let do_enrich = args.any(|a| a == "--enrich");

    let started = std::time::Instant::now();
    let scanned = scan::scan(
        std::path::Path::new(&root),
        Arc::new(AtomicBool::new(false)),
        Arc::new(|m| eprintln!("[progress] {m}")),
    )
    .expect("scan");
    let mut result = scanned.result;
    println!(
        "--- {} components in {:?} ---",
        result.components.len(),
        started.elapsed()
    );

    if do_enrich {
        let state = CveState::new(reqwest::Client::new());
        let enriched = enrich::enrich(
            &state,
            &std::env::temp_dir(),
            None,
            &scanned.queries,
            Arc::new(AtomicBool::new(false)),
            Arc::new(|m| eprintln!("[lookup] {m}")),
        )
        .await;
        enrich::apply(&mut result, enriched.found);
        for note in &enriched.notes {
            eprintln!("[note] {note}");
        }
    }

    for c in &result.components {
        println!(
            "{}\t{}\t{}\tpaths={}\tcves={}",
            c.vendor,
            c.product,
            c.version,
            c.paths.len(),
            c.vulnerabilities.len()
        );
        // Sort exploited-first so the actionable ones surface.
        let mut vulns = c.vulnerabilities.clone();
        vulns.sort_by(|a, b| {
            b.known_exploited.cmp(&a.known_exploited).then(
                b.epss_probability
                    .partial_cmp(&a.epss_probability)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });
        for v in vulns.iter().take(4) {
            let flag = if v.ransomware {
                "  [KEV+RANSOMWARE]"
            } else if v.known_exploited {
                "  [KEV exploited]"
            } else {
                ""
            };
            let epss = v
                .epss_probability
                .map(|p| format!(" epss={p:.3}"))
                .unwrap_or_default();
            println!(
                "        {} {} {}{}{}",
                v.cve_id, v.severity, v.source, epss, flag
            );
        }
    }
    println!("summary: {:?}", result.summary);
}
