# The headless server: the desktop GUI in a browser

`oxaudit-server` serves the same command surface the desktop app exposes
over Tauri IPC as HTTP + SSE, with the built frontend served from the same
port. Open the URL in any browser — laptop, tablet, phone — and the
workbench runs: source, dependency, binary, image, and history scanning,
reviews, rule packs, advisory databases, inventory, exports, verification,
compliance, reports, and schedules, all through the same engines as the
desktop. See [ADR 0004](architecture/adr/0004-headless-server.md) for the
design and trust model.

## Running it

```bash
# From a build of this repository:
npm run build                                   # the frontend → dist/
cargo build --release --locked --features server \
  --manifest-path src-tauri/Cargo.toml --bin oxaudit-server
./src-tauri/target/release/oxaudit-server --web-root ./dist
```

The first start generates an access token, prints it, and stores it
(`data/server-token`, chmod 600) so restarts reuse it. Open the printed
address in a browser and paste the token at the gate.

### Container distribution

Do not rely on an anonymous pull from `ghcr.io/henrycooper86/oxaudit`:
published v0.1.0 includes no container reference, and an anonymous registry
request was refused on 2026-10-20. Use the source-build commands above for
the current browser workbench. The
[installation matrix](getting-started.md#platform-availability-and-verification)
and [release checklist](release-checklist.md#container-availability) distinguish
workflow build capabilities from an actually available, verified distribution.

## Flags and environment

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--bind` | `OXAUDIT_SERVER_BIND` | `127.0.0.1:8080` | Listen address. **Loopback by default**; in the container this defaults to `0.0.0.0:8080`. |
| `--data-dir` | `OXAUDIT_SERVER_DATA_DIR` | `~/.oxaudit-server/data` | Findings database, rule packs, schedules, caches, the generated token. |
| `--config-dir` | `OXAUDIT_SERVER_CONFIG_DIR` | `~/.oxaudit-server/config` | `settings.json` and assistant sessions. |
| `--web-root` | `OXAUDIT_SERVER_WEB_ROOT` | none | The built frontend (`dist/`). Without it only the API is served. |
| `--token` | `OXAUDIT_SERVER_TOKEN` | generated | The access token every API call must present. |

## Security posture

- Every `/api` request requires the access token; the browser keeps it in
  local storage and shows a gate when it is missing or rejected.
- The bind default is loopback because a server that reads arbitrary local
  paths must never be reachable by accident. For remote access, terminate
  TLS at a reverse proxy or tunnel (Tailscale, ssh -L, Caddy, nginx) and
  keep the server off the raw network.
- The token gates data, not code: the served GUI assets are the same public
  bundle anyone can download from the repository.
- Static paths are decoded before traversal checks, and symlink targets must
  remain within the configured web root; request bodies are bounded at 64 MiB.

## Stated limits

- The **AI assistant** is not available through the server yet; the server
  refuses those commands with a stated reason, and the desktop app or CLI
  remains the way to run AI research.
- Import/export paths are paths **on the server's filesystem**; a browser
  cannot open a native save dialog. In Report Studio, enter **Report file on
  server** including the extension, then choose **Save to server**. The parent
  directory must already exist and the server process must be able to write
  there. Saving replaces an existing file at that path. The receipt identifies
  the saved server path; this does not download the file to the browser.
- Events ride one SSE stream; a client that falls behind is told what it
  missed (`hub://lagged`) rather than silently resuming.

## Browser import/export

Export Center uses explicit paths on the server; desktop mode keeps native file
dialogs. In a container, use paths visible inside the container, with the
appropriate volume mounted. These controls do not upload or download files.

1. Enter **Report file on server**, then choose **Inspect report**. Inspect the
   format, inventory, external claims, warnings and SHA-256 before importing.
   Choose **Import separate inventory** or **Retain external claims** when the
   preview supports that action. External claims remain `external-unverified`;
   they do not overwrite local findings or reviews.
2. Editing the import path clears its approval, including changing away and
   back to the same path. Inspect it again. If the file's contents change after
   inspection, import fails with a request to preview again.
3. Select a saved run and format. Enter **Export file on server**, including its
   extension, then choose **Save to server**. The destination parent must exist
   and be writable. Saving replaces an existing file; the success status names
   the destination. The saved report is complete even when its preview is
   truncated to 1 MiB.

Prefer absolute paths such as `/data/reports/run.json`; paths do not expand
`~` or environment variables. Missing files, malformed reports and unwritable
destinations produce visible errors. Correct the path or file and retry.
Pending actions cannot be submitted twice. Changing run, format or destination
while a desktop save dialog is pending invalidates that save; an already
submitted write retains its captured run, format and destination.

## Saved inventory

Inventory lists completed Dependency, Binary, Image, Firmware and Import runs
in pages of 50, so newer Source or History activity cannot hide old inventories.
Use the run pagination above the component list to reach older runs. Component
pages and searches are queried on the server; search covers package identity,
aliases, CPEs and advisory IDs across the whole selected inventory. Counts refer
to the full inventory and filtered result set, not just the visible page.

The first database open after upgrading builds derived inventory search indexes
under schema version 9. It preserves canonical evidence and processes the new
index backfill one stored row at a time. Large existing databases can take longer
to open during that migration. Full saved-run exports remain separate operations.
