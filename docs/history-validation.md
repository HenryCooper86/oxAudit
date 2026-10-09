# Durable Git-history evidence

Desktop, server and CLI history scans now use one workflow. The process work
registry owns interactive history work alongside source, dependency, binary and
image scans. A history operation binds its canonical run ID while active;
category cancellation and operation-ID cancellation address that owned work.

History scans save `history` canonical runs and their projections, including
failed and cancelled attempts. Findings contain redacted secret evidence.
Explicit credential validation remains opt-in; raw validation material never
enters the projection, SQLite graph or exported report.

```bash
./src-tauri/target/debug/oxaudit-cli history /path/to/repository \
  --db /tmp/oxaudit-history-evidence/history.sqlite --format json --output /tmp/history.json
./src-tauri/target/debug/oxaudit-cli runs --kind history --db /tmp/oxaudit-history-evidence/history.sqlite --json
./src-tauri/target/debug/oxaudit-cli export --db /tmp/oxaudit-history-evidence/history.sqlite \
  --run RUN_ID --format sarif --output /tmp/history.sarif
```

History also supports direct standards output, such as `history ... --format
sarif`, through the same saved graph. `--db` retains that graph; without it the
CLI uses an in-memory database. Non-completed scans cannot pass the CLI's clean
exit contract. Returned partial evidence is written with exit 3; workflow
errors also exit 3 and leave their failed attempt available in `--db` for reload
and export. Finding-severity gates retain exit 1 for completed runs.

Each inspected UTF-8 blob retains its Git object ID, first enumerated repository
path, byte size and content SHA-256. Finding IDs map to those object IDs. The
canonical artifact location is `git:<object-id>!<historical-path>` and has no
working-tree canonical path. Recreating or editing a file at the same current
path therefore cannot change a saved report's identity. Relative finding paths
remain compatible with existing fingerprints and file baselines, but are
historical locations rather than evidence about today's file.

The receipt saves before/after HEAD and ref object identities. A ref change
marks coverage incomplete; failure to inspect final context records unknown
change state and incomplete coverage. No introduced-commit claim is computed.
The scan covers unique blobs reachable from refs, excludes dangling objects,
filters blobs above 1 MiB and skips non-UTF-8/quoted paths. The exact number of
oversized filtered blobs is unknown and is recorded as `null`, with a warning.
Other limits remain 100,000 candidate objects, 256 MiB accepted text, 10,000
findings, 64 MiB enumeration output and 120 seconds of Git work.

The Git producer queue retains at most two whole blobs. Cancellation polls both
the blob consumer and Git process wait, releases a blocked queue sender, kills
and reaps Git, and joins pipe-reader/writer threads before the blocking task
returns. The queue bound is only one part of memory use: candidate metadata,
accumulated redacted findings, Git's own memory and stored graph work are
additional bounded populations.

The immutable projection supplies observations; canonical run state is
authoritative when it is reloaded. A projection-save or terminal-save failure
must retain a failed attempt and cannot publish completion. Real SQLite tests
cover save/reload, historical SARIF locations, absent raw credential material,
failed/cancelled attempts, projection and terminal save failures, adapter work
ownership and early run-ID binding. Real Git tests exercise deleted secrets,
revision deduplication, queue backpressure, cancellation and resource coverage.
