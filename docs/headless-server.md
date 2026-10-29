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

### Container

Each published release since v0.2.0 comes with a multi-architecture image
(linux/amd64, linux/arm64) carrying both `oxaudit-cli` and `oxaudit-server`
with the built GUI. The release asset `oxaudit-container.txt` holds its reference pinned by
digest; for [v0.2.6](https://github.com/HenryCooper86/oxAudit/releases/tag/v0.2.6)
that is
`ghcr.io/henrycooper86/oxaudit@sha256:173ebb003c1e9855d3e07ff7140b7f6b827e52f088ce954af98bec9e44ceb4cf`.
Use the digest, not a tag, and verify the image's signature as shown in the
[installation guide](getting-started.md#what-verification-proves). An
anonymous pull by that digest succeeded on 2026-10-29.

The image's entrypoint is the CLI, so the server is one flag away. Inside the
container the server binds `0.0.0.0:8080`, serves the GUI from `/app/dist`,
and keeps all state under `/data`; it runs as the unprivileged `scanner`
user, which must own the `/data` volume. Images up to and including v0.2.6
do not create `/data`, so a fresh named volume is owned by root and the
server exits with "cannot prepare the data directory". With those images,
give the volume to `scanner` once before the first start (the `chown` line
below); later images create `/data` owned by `scanner` and need no extra
step:

```bash
IMAGE=ghcr.io/henrycooper86/oxaudit@sha256:173ebb003c1e9855d3e07ff7140b7f6b827e52f088ce954af98bec9e44ceb4cf
docker run --rm --user 0 -v oxaudit-data:/data --entrypoint chown "$IMAGE" scanner:scanner /data
docker run -d --name oxaudit -p 127.0.0.1:8080:8080 -v oxaudit-data:/data \
  --entrypoint oxaudit-server "$IMAGE"
docker logs oxaudit        # prints the generated access token on first start
```

The token is stored in the volume (`/data/server-token`, chmod 600), so
restarts reuse it; open `http://127.0.0.1:8080` and paste it at the gate.
Publishing the port as `127.0.0.1:8080:8080` keeps the loopback default on
the host: Docker's plain `-p 8080:8080`, as in the release notes, listens on
every host interface. Paths you enter in the browser are paths inside the
container, so mount the projects to scan as further volumes (for example
`-v "$PWD:/workspace"`); see [Browser import/export](#browser-importexport).

## Remote access

Reach the server from another device only through TLS: a reverse proxy or
tunnel (Tailscale, `ssh -L`, Caddy, nginx) in front of the loopback-bound
port, as described under [Security posture](#security-posture). Opening the
workbench from a remote browser over plain HTTP is not a supported setup:
the access token and every result would cross the network unencrypted.

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
