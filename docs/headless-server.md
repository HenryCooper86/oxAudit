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

With the published container the GUI is one flag away:

```bash
docker run --rm -p 8080:8080 -v oxaudit-data:/data \
  --entrypoint oxaudit-server ghcr.io/henrycooper86/oxaudit
# then open http://localhost:8080 and paste the token from the container log
```

The same image is also the CLI: `docker run --rm -v "$PWD:/workspace"
ghcr.io/henrycooper86/oxaudit scan /workspace --format sarif`.

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
- Static paths are traversal-checked; request bodies are bounded at 64 MiB.

## Stated limits

- The **AI assistant** is not available through the server yet; the server
  refuses those commands with a stated reason, and the desktop app or CLI
  remains the way to run AI research.
- Import/export paths are paths **on the server's filesystem**; a browser
  cannot open a native save dialog, so the pages say so instead of
  pretending.
- Events ride one SSE stream; a client that falls behind is told what it
  missed (`hub://lagged`) rather than silently resuming.
