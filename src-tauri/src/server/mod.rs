//! The headless server: the desktop's command surface over HTTP + SSE, with
//! the browser GUI served from the same port.
//!
//! Trust model (ADR 0004): a scan server can read every file it is pointed
//! at, so it must never be an unauthenticated network service. Every `/api`
//! request carries a bearer token (the browser keeps it and shows a gate
//! when it is missing); the server binds to loopback unless explicitly told
//! otherwise; static assets carry no secrets and need no token.
//!
//! Transport mapping: `invoke(cmd, args)` becomes
//! `POST /api/invoke/{cmd}` with a JSON body and an `{"ok", "data"|"error"}`
//! envelope; `listen(event, handler)` becomes one shared SSE stream at
//! `/api/events` carrying `{event, payload}` frames. Progress events keep
//! their desktop names (`scan://progress`, `run://event`, …) so the
//! frontend needs no per-feature changes.

pub mod dispatch;
pub mod hub;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::Value;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::commands::AppState;
use crate::findings::service::FindingsState;
use crate::server::hub::{EventHub, HubEvents, HubRunEvents};

pub struct ServerConfig {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub web_root: Option<PathBuf>,
    pub token: String,
}

/// Everything a dispatched command needs, mirroring the states the Tauri
/// app manages plus the directories the desktop resolves from the app handle.
pub struct ServerContext {
    pub app: AppState,
    pub findings: FindingsState,
    pub cve: crate::cve::CveState,
    pub rule_packs: crate::rulepack_store::RulePacksState,
    pub schedules: crate::schedule_store::ScheduleState,
    pub hub: Arc<EventHub>,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub config_dir: PathBuf,
    pub web_root: Option<PathBuf>,
}

impl ServerContext {
    pub fn events(&self) -> HubEvents {
        HubEvents::new(self.hub.clone())
    }

    pub fn run_events(&self) -> HubRunEvents {
        HubRunEvents::new(self.hub.clone())
    }

    pub fn settings_path(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }

    pub fn session_store(&self) -> Result<crate::sessions::SessionStore, String> {
        crate::sessions::SessionStore::open_in_dir(self.config_dir.join("sessions"))
    }
}

/// Bootstrap states exactly as the desktop does, then serve.
pub fn run(config: ServerConfig) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the async runtime: {error}"))?;
    runtime.block_on(serve(config))
}

async fn serve(config: ServerConfig) -> Result<(), String> {
    TOKEN
        .set(config.token.clone())
        .map_err(|_| "server token already initialized".to_string())?;
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|error| format!("cannot create the data directory: {error}"))?;
    std::fs::create_dir_all(&config.config_dir)
        .map_err(|error| format!("cannot create the config directory: {error}"))?;
    std::fs::create_dir_all(config.data_dir.join("cache"))
        .map_err(|error| format!("cannot create the cache directory: {error}"))?;

    crate::observability::init(&config.data_dir);

    let app = AppState::new();
    let cve = crate::cve::CveState::new(app.http.clone());

    // Persisted settings, exactly as the desktop loads them, minus the
    // legacy-profile migration (a fresh server has none).
    let settings = crate::settings::load_secure_from_path(
        &config.config_dir.join("settings.json"),
        app.credentials.as_ref(),
    )
    .unwrap_or_else(|error| {
        log::warn!("persisted settings could not be loaded: {error}");
        crate::models::AppSettings::default()
    });
    *app.settings.lock().unwrap() = settings;

    let findings = crate::initialize_findings_state(&config.data_dir, chrono::Utc::now());
    let rule_packs = match crate::rulepack_store::RulePackStore::open(
        &config.data_dir.join("rule-packs.sqlite3"),
    ) {
        Ok(store) => crate::rulepack_store::RulePacksState::available(store),
        Err(error) => {
            log::warn!("rule-pack store unavailable: {error}");
            crate::rulepack_store::RulePacksState::unavailable(error)
        }
    };
    let schedules = match crate::schedule_store::ScheduleStore::open(
        &config.data_dir.join("schedules.sqlite3"),
    ) {
        Ok(store) => crate::schedule_store::ScheduleState::available(store),
        Err(error) => {
            log::warn!("schedule store unavailable: {error}");
            crate::schedule_store::ScheduleState::unavailable(error)
        }
    };

    let hub = Arc::new(EventHub::new());
    let ctx = Arc::new(ServerContext {
        app,
        findings,
        cve,
        rule_packs,
        schedules,
        hub: hub.clone(),
        data_dir: config.data_dir.clone(),
        cache_dir: config.data_dir.join("cache"),
        config_dir: config.config_dir.clone(),
        web_root: config.web_root.clone(),
    });

    // The re-scan ticker, same cadence and semantics as the desktop's.
    let ticker_ctx = ctx.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // the first tick fires immediately; skip it
        loop {
            ticker.tick().await;
            let Ok(store) = ticker_ctx.schedules.store() else {
                continue;
            };
            let schedules = store.list();
            let due = crate::schedule_store::due(&schedules, chrono::Utc::now());
            for schedule in due {
                let _ = store.mark_started(&schedule.project_id, &chrono::Utc::now().to_rfc3339());
                tracing::info!(project = %schedule.project_id, "scheduled rescan starting");
                let hub_events = ticker_ctx.events();
                let hub = ticker_ctx.hub.clone();
                let project_id = schedule.project_id.clone();
                let path = schedule.canonical_path.clone();
                let publish = move |result: &Result<
                    crate::findings::domain::ScanRunDetail,
                    crate::findings::error::CommandError,
                >| {
                    hub.publish(
                        "schedule://completed",
                        serde_json::json!({
                            "projectId": project_id,
                            "canonicalPath": path,
                            "ok": result.is_ok(),
                            "runId": result.as_ref().ok().map(|detail| detail.run_id.clone()),
                            "findings": result.as_ref().ok().map(|detail| detail.summary.total_findings),
                            "error": result.as_ref().err().map(|error| error.to_string()),
                        }),
                    );
                };
                let _ = crate::commands::schedule::run_scheduled_scan_engine(
                    &ticker_ctx.app,
                    &ticker_ctx.findings,
                    &ticker_ctx.cve,
                    Some(&ticker_ctx.rule_packs),
                    &hub_events,
                    &publish,
                    &schedule.canonical_path,
                )
                .await;
            }
        }
    });

    let api = Router::new()
        .route("/api/invoke/{cmd}", post(invoke))
        .route("/api/events", get(events))
        .layer(middleware::from_fn_with_state(ctx.clone(), authenticate))
        .with_state(ctx.clone());

    let app_router = api
        .route("/env.js", get(env_js))
        .fallback(static_files)
        .with_state(ctx.clone())
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("cannot bind {}: {error}", config.bind))?;
    log::info!("oxAudit server listening on {}", config.bind);
    axum::serve(listener, app_router)
        .await
        .map_err(|error| format!("server error: {error}"))
}

/// Constant-time-enough token check: compare SHA-256 digests byte by byte,
/// so neither length nor prefix positions leak.
fn token_matches(provided: &str, expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    let a = Sha256::digest(provided.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn provided_token(req: &Request<axum::body::Body>) -> Option<String> {
    if let Some(value) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(text) = value.to_str() {
            if let Some(token) = text.strip_prefix("Bearer ") {
                return Some(token.trim().to_string());
            }
        }
    }
    // EventSource cannot set headers; the events stream also accepts the
    // token as a query parameter.
    let query = req.uri().query()?;
    for pair in query.split('&') {
        if let Some(token) = pair.strip_prefix("token=") {
            return Some(token.to_string());
        }
    }
    None
}

async fn authenticate(
    State(ctx): State<Arc<ServerContext>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(provided) = provided_token(&req) else {
        return (StatusCode::UNAUTHORIZED, "missing access token").into_response();
    };
    if !token_matches(&provided, ctx_token(&ctx)) {
        return (StatusCode::UNAUTHORIZED, "invalid access token").into_response();
    }
    next.run(req).await
}

fn ctx_token(_ctx: &ServerContext) -> &str {
    // The token is config, not state; it is set before serve() starts.
    TOKEN.get().expect("server token initialized")
}

static TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

async fn invoke(
    State(ctx): State<Arc<ServerContext>>,
    axum::extract::Path(cmd): axum::extract::Path<String>,
    Json(args): Json<Value>,
) -> Json<Value> {
    let outcome = dispatch::dispatch(&ctx, &cmd, args).await;
    Json(match outcome {
        Ok(data) => serde_json::json!({ "ok": true, "data": data }),
        Err(error) => serde_json::json!({ "ok": false, "error": error }),
    })
}

async fn events(
    State(ctx): State<Arc<ServerContext>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = ctx.hub.subscribe();
    let stream = BroadcastStream::new(rx).map(|item| match item {
        Ok((name, payload)) => Ok(Event::default().event(name).data(payload.to_string())),
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(missed)) => {
            // Tell the client it missed frames rather than resuming silently.
            Ok(Event::default()
                .event("hub://lagged")
                .data(serde_json::json!({ "missed": missed }).to_string()))
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Tells the served frontend it is talking to the headless server, so the
/// transport swaps invoke/listen for fetch/SSE.
async fn env_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        "window.OXAUDIT_SERVER = true;\n",
    )
}

async fn static_files(
    State(ctx): State<Arc<ServerContext>>,
    req: Request<axum::body::Body>,
) -> Response {
    let Some(web_root) = &ctx.web_root else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "This server was started without a web root, so no GUI is served.\n\
             Start it with --web-root pointing at the built frontend.",
        )
            .into_response();
    };
    let raw = req.uri().path().trim_start_matches('/');
    let raw = if raw.is_empty() { "index.html" } else { raw };
    // Percent-decode the minimum the browsers require; reject traversal.
    if raw.contains("..") {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    }
    let candidate = web_root.join(req_path_bytes(raw));
    let path = if candidate.is_file() {
        candidate
    } else {
        // SPA fallback: unknown paths get the app shell.
        web_root.join("index.html")
    };
    match std::fs::read(&path) {
        Ok(bytes) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            let mut response = (StatusCode::OK, bytes).into_response();
            if let Ok(value) = header::HeaderValue::from_str(mime.essence_str()) {
                response.headers_mut().insert(header::CONTENT_TYPE, value);
            }
            if path.file_name().is_some_and(|name| name != "index.html") {
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    "public, max-age=3600".parse().unwrap(),
                );
            } else {
                response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
            }
            response
        }
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn req_path_bytes(raw: &str) -> PathBuf {
    // Split off any query string remainder; the percent-decoding here covers
    // the characters a static asset name can contain.
    let without_query = raw.split('?').next().unwrap_or(raw);
    percent_encoding::percent_decode_str(without_query)
        .decode_utf8_lossy()
        .into_owned()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> (Arc<ServerContext>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("data");
        let config_dir = dir.path().join("config");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        let app = AppState::new();
        let cve = crate::cve::CveState::new(app.http.clone());
        let findings = crate::initialize_findings_state(&data_dir, chrono::Utc::now());
        let rule_packs = crate::rulepack_store::RulePacksState::unavailable("test".into());
        let schedules = crate::schedule_store::ScheduleState::unavailable("test".into());
        let hub = Arc::new(EventHub::new());
        let ctx = Arc::new(ServerContext {
            app,
            findings,
            cve,
            rule_packs,
            schedules,
            hub: hub.clone(),
            data_dir,
            cache_dir: dir.path().join("cache"),
            config_dir,
            web_root: None,
        });
        (ctx, dir)
    }

    #[test]
    fn token_check_requires_exact_equality() {
        assert!(token_matches("secret-token", "secret-token"));
        assert!(!token_matches("secret-toke", "secret-token"));
        assert!(!token_matches("secret-token-longer", "secret-token"));
        assert!(!token_matches("", "secret-token"));
    }

    #[tokio::test]
    async fn a_state_free_command_answers_from_the_real_engine() {
        let (ctx, _dir) = test_context();
        let result = dispatch::dispatch(&ctx, "list_compiled_grammars", serde_json::json!({}))
            .await
            .expect("command succeeds");
        let grammars = result.as_array().expect("array of grammar names");
        assert!(
            !grammars.is_empty(),
            "the full-feature build compiles grammars"
        );
    }

    #[tokio::test]
    async fn unknown_commands_are_refused_with_a_stated_reason() {
        let (ctx, _dir) = test_context();
        let error = dispatch::dispatch(&ctx, "not_a_command", serde_json::json!({}))
            .await
            .expect_err("unknown command is an error");
        assert_eq!(error["code"], "dataOperationFailed");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("not part of it"),
            "the refusal names the command surface"
        );
    }

    #[tokio::test]
    async fn command_errors_travel_as_envelope_errors_not_successes() {
        let (ctx, _dir) = test_context();
        let outcome = dispatch::dispatch(
            &ctx,
            "list_source_runs",
            serde_json::json!({"projectId": "missing"}),
        )
        .await;
        let error = outcome.expect_err("a missing project is an error");
        assert_eq!(error["code"], "notFound");
        // The regression this pins: an Err must never end up on the Ok side
        // of the invoke envelope.
    }

    #[tokio::test]
    async fn the_default_advisory_path_lands_in_the_server_data_dir() {
        let (ctx, _dir) = test_context();
        let path = dispatch::dispatch(&ctx, "default_advisory_db_path", serde_json::json!({}))
            .await
            .expect("command succeeds");
        let expected = ctx.data_dir.join("advisories.sqlite3");
        assert_eq!(
            path.as_str().unwrap(),
            expected.to_string_lossy().replace('\\', "/")
        );
    }
}
