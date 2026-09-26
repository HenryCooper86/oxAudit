# ADR 0004: The headless server — the desktop's command surface over HTTP

Date: 2026-09-26
Status: Accepted

## Context

oxAudit's engine is one Rust library with two faces: the Tauri desktop app
and the CLI. Users on tablets, Chromebooks, locked-down corporate laptops,
or ARM servers have no way to run the desktop app — and the CLI does not
give them the review, triage, compliance, and reporting surfaces that make
the desktop app the primary product. All desktop IPC already funnels through
one invoke wrapper (`src/lib/api.ts`) and one event subscription point, so
there is a single seam where a different transport can be swapped in without
touching page code.

## Decision

A feature-gated `oxaudit-server` binary serves the same command surface the
desktop registers with Tauri's `invoke_handler`, as HTTP plus SSE, with the
built frontend served from the same port:

- `invoke(cmd, args)` → `POST /api/invoke/{cmd}`, answered by an
  `{"ok", "data" | "error"}` envelope. Structured `CommandError`s and plain
  string errors travel as the desktop's invoke rejections do, so the
  frontend's existing error normalization is unchanged.
- `listen(event, handler)` → one shared SSE stream at `/api/events`. Frames
  keep the desktop event names (`scan://progress`, `run://event`,
  `schedule://completed`, …), so the pages cannot tell the transports apart.
- Scan-producing commands call **extracted engine functions** — the Tauri
  command bodies were lifted into `*_engine` / `*_inner` functions taking
  references and an event sink, and both the Tauri command and the server
  dispatch call them. There is one scan implementation, not two.

The frontend detects the server through `/env.js` (served only by the
server), swapping `invoke`/`listen` for fetch/SSE in one place. Native
dialogs and editor opening are refused with stated reasons in browser mode;
typed paths remain the input path for everything the server can reach.

### Trust model

A scan server reads every file it is pointed at and writes findings its
operator will act on. Therefore:

- Every `/api` request must present the access token (`Authorization:
  Bearer`, or `?token=` on the SSE endpoint, which `EventSource` cannot
  authenticate with headers). The token is supplied by flag or environment,
  or generated on first start, printed, and stored owner-only beside the
  data directory.
- The bind address defaults to loopback. Binding a network interface is a
  deliberate act — in the container, `OXAUDIT_SERVER_BIND=0.0.0.0:8080` is
  that deliberate act, and remote access is expected to run through a TLS-
  terminating proxy or tunnel.
- Static assets carry no secrets and need no token; the token gates data,
  not code.

### Container

The published image carries the CLI (the default entrypoint, so pipeline
usage stays `docker run image scan /workspace …`) and the server with the
built GUI, state under a mounted `/data` volume.

## Stated limits (v1)

- The **AI assistant** is refused by the server with a stated reason: its
  streaming engine is still wired to the Tauri handle. Everything else —
  source, dependency, binary, image, and history scanning, reviews, rule
  packs, advisory databases, exports and imports (paths are on the server's
  filesystem), verification, compliance, reports, schedules, CVE research —
  runs through the same engines as the desktop.
- Native file dialogs do not exist in a browser; import/export paths are
  typed paths on the server.
- SSE can lag a slow client; missed frames are announced as `hub://lagged`
  rather than silently resumed. Progress events carry absolute counts, so a
  gap self-heals on the next event.
- The AI refusal is a v1 boundary, not a principle: wiring the chat engine
  behind the same event-sink seam is the planned follow-up.

## Consequences

- New desktop commands should land with a `_inner` (service-level) or
  `_engine` (scan) function so the server dispatch can adopt them in one
  arm; a command that only exists as a Tauri wrapper is incomplete.
- The server feature adds axum to the dependency graph only for builds that
  ask for it; desktop and CLI graphs are unchanged.
- Verification and gates: `cargo test --workspace --all-features` compiles
  and runs the server's tests; the desktop and CLI builds never pull the
  feature.
