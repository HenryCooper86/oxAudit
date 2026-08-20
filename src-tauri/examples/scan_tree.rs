use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use vulncompanion_lib::binscan::native::scan;

fn main() {
    let root = std::env::args().nth(1).expect("usage: scan_tree <path>");
    let started = std::time::Instant::now();
    let result = scan::scan(
        std::path::Path::new(&root),
        Arc::new(AtomicBool::new(false)),
        Arc::new(|m| eprintln!("[progress] {m}")),
    )
    .expect("scan");
    println!("--- {} components in {:?} ---", result.components.len(), started.elapsed());
    for c in &result.components {
        println!("{}\t{}\t{}\tpaths={}", c.vendor, c.product, c.version, c.paths.len());
    }
}
