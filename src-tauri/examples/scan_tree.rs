//! Reproduce the native scanner's measurements outside the app.
//!
//! `cargo run --release --example scan_tree -- <path> [--enrich]`
//!
//! `--enrich` performs live NVD and OSV lookups, which is how the numbers in
//! docs/binary-scanning-runtime.md were taken.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use vulncompanion_lib::binscan::native::{enrich, scan};
use vulncompanion_lib::cve::CveState;

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
        for v in c.vulnerabilities.iter().take(3) {
            println!(
                "        {} {} {} {}",
                v.cve_id,
                v.severity,
                v.source,
                v.fixed_in.clone().unwrap_or_default()
            );
        }
    }
    println!("summary: {:?}", result.summary);
}
