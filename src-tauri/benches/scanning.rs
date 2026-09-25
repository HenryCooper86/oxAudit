//! Throughput benchmarks for the scanning hot paths.
//!
//! "How long on our monorepo?" is the first question a security engineer asks
//! about a scanner, and until this existed the answer was unknown to us too.
//!
//! These measure the per-file work — rule matching and syntax analysis — rather
//! than a whole-project walk, because that is the part that scales with the
//! target and the part a rule change can quietly make quadratic. Directory
//! traversal and SQLite writes are dominated by the filesystem and are measured
//! by the end-to-end figure in the README instead.
//!
//! Syntax analysis is deliberately measured on its own. Adding tree-sitter cut
//! findings on this repository from 142 to 34 and cost roughly 20% of scan
//! time; a benchmark that folded the two together would hide the trade rather
//! than let it be judged.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oxaudit_lib::scanners;

/// A file with the shape real source has: mostly ordinary code, a few matches,
/// comments and strings that a text-only scanner would trip over.
fn javascript_source(repetitions: usize) -> String {
    let unit = r#"
// Never call eval(userInput) here — removed in #412, the argument is
// attacker controlled and this was a live RCE.
const WARNING = "Do not use eval(...) on untrusted input";

export function renderTemplate(template, context) {
  const compiled = compile(template);
  return compiled(context);
}

export function unsafeRender(userInput) {
  return eval(userInput);
}

export async function loadRecord(db, id) {
  return db.query("SELECT * FROM records WHERE id = ?", [id]);
}

const client = new ServiceClient({ apiKey: process.env.SERVICE_API_KEY });
"#;
    unit.repeat(repetitions)
}

fn python_source(repetitions: usize) -> String {
    let unit = r#"
import hashlib
import subprocess

# md5 was removed here in 2024; it is not collision resistant.
def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

def run_checked(target):
    return subprocess.run(["git", "clone", target], shell=False)

def run_unchecked(user_supplied):
    return subprocess.run(user_supplied, shell=True)
"#;
    unit.repeat(repetitions)
}

/// Rule matching alone, with no syntax analysis.
fn source_patterns(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("source_patterns");
    for repetitions in [1usize, 20, 200] {
        let js = javascript_source(repetitions);
        group.throughput(Throughput::Bytes(js.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("javascript", js.len()),
            &js,
            |bencher, source| {
                bencher.iter(|| {
                    scanners::patterns::scan_content(std::hint::black_box(source), "javascript")
                })
            },
        );

        let py = python_source(repetitions);
        group.throughput(Throughput::Bytes(py.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("python", py.len()),
            &py,
            |bencher, source| {
                bencher.iter(|| {
                    scanners::patterns::scan_content(std::hint::black_box(source), "python")
                })
            },
        );
    }
    group.finish();
}

/// The 44 secret rules, which run over every file regardless of language.
fn secret_rules(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("secret_rules");
    for repetitions in [1usize, 20, 200] {
        let source = javascript_source(repetitions);
        group.throughput(Throughput::Bytes(source.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(source.len()),
            &source,
            |bencher, source| {
                bencher.iter(|| {
                    scanners::benchmark_observations(std::hint::black_box(source), "", false, true)
                })
            },
        );
    }
    group.finish();
}

/// Parsing a file and collecting comment and string spans — the cost that
/// buys the precision improvement.
fn syntax_analysis(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("syntax_analysis");
    for (language, build) in [
        ("javascript", javascript_source as fn(usize) -> String),
        ("python", python_source as fn(usize) -> String),
    ] {
        for repetitions in [1usize, 20, 200] {
            let source = build(repetitions);
            group.throughput(Throughput::Bytes(source.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(language, source.len()),
                &source,
                |bencher, source| {
                    bencher
                        .iter(|| scanners::syntax::analyze(std::hint::black_box(source), language))
                },
            );
        }
    }
    group.finish();
}

/// A file in a language with no grammar must not pay for the parser it does
/// not get. This is the guard that the fallback stays free.
fn syntax_analysis_unsupported(criterion: &mut Criterion) {
    let source = javascript_source(20);
    criterion.bench_function("syntax_analysis/no_grammar", |bencher| {
        bencher.iter(|| scanners::syntax::analyze(std::hint::black_box(&source), "cobol"))
    });
}

criterion_group!(
    benches,
    source_patterns,
    secret_rules,
    syntax_analysis,
    syntax_analysis_unsupported
);
criterion_main!(benches);
