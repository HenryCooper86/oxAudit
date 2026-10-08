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
                        crate::commands::schedule::completion_payload(&project_id, &path, result),
                    );
                };
                let _ = crate::commands::schedule::run_scheduled_scan_engine(
                    &ticker_ctx.app,
                    &ticker_ctx.findings,
                    &ticker_ctx.cve,
                    Some(&ticker_ctx.rule_packs),
                    &hub_events,
                    &publish,
                    crate::commands::schedule::ScheduledScanTarget {
                        canonical_path: &schedule.canonical_path,
                        project_id: &schedule.project_id,
                        schedules: Some(store),
                    },
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
            return percent_encoding::percent_decode_str(token)
                .decode_utf8()
                .ok()
                .map(|value| value.into_owned());
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
    let relative = match req_path_bytes(raw) {
        Ok(path) => path,
        Err(()) => return (StatusCode::BAD_REQUEST, "invalid path").into_response(),
    };
    let Ok(root) = web_root.canonicalize() else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let candidate = root.join(relative).canonicalize();
    if candidate
        .as_ref()
        .is_ok_and(|path| !path.starts_with(&root))
    {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    }
    let path = match candidate {
        Ok(path) if path.is_file() => path,
        _ => {
            // SPA fallback: unknown paths get the app shell, which must
            // satisfy the same containment check as every other asset.
            let Ok(path) = root.join("index.html").canonicalize() else {
                return (StatusCode::NOT_FOUND, "not found").into_response();
            };
            if !path.starts_with(&root) {
                return (StatusCode::BAD_REQUEST, "invalid path").into_response();
            }
            path
        }
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

fn req_path_bytes(raw: &str) -> Result<PathBuf, ()> {
    // Validate after decoding: encoded separators and dot segments have
    // exactly the same filesystem meaning as their literal counterparts.
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| ())?;
    if decoded.contains(['\\', '\0']) {
        return Err(());
    }
    let path = PathBuf::from(decoded.as_ref());
    if !path
        .components()
        .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(());
    }
    Ok(path)
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

    #[test]
    fn events_query_tokens_are_percent_decoded() {
        let request = Request::builder()
            .uri("/api/events?token=custom%2Btoken%2Fwith%3Dsymbols")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            provided_token(&request).as_deref(),
            Some("custom+token/with=symbols")
        );
    }

    async fn static_response(ctx: Arc<ServerContext>, uri: &str) -> Response {
        static_files(
            State(ctx),
            Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
    }

    fn web_context() -> (Arc<ServerContext>, tempfile::TempDir) {
        let (mut ctx, directory) = test_context();
        let web_root = directory.path().join("web");
        std::fs::create_dir(&web_root).unwrap();
        std::fs::write(web_root.join("index.html"), "app shell").unwrap();
        std::fs::write(directory.path().join("private.txt"), "private contents").unwrap();
        Arc::get_mut(&mut ctx).unwrap().web_root = Some(web_root);
        (ctx, directory)
    }

    #[tokio::test]
    async fn static_assets_reject_encoded_traversal_and_absolute_paths() {
        let (ctx, directory) = web_context();
        let absolute = format!(
            "/%2F{}",
            directory
                .path()
                .join("private.txt")
                .display()
                .to_string()
                .trim_start_matches('/')
        );
        for uri in [
            "/%2e%2e/private.txt",
            "/%2e%2e%2fprivate.txt",
            "/..%5cprivate.txt",
            &absolute,
        ] {
            let response = static_response(ctx.clone(), uri).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn static_assets_never_follow_symlinks_outside_the_web_root() {
        let (ctx, directory) = web_context();
        std::os::unix::fs::symlink(
            directory.path().join("private.txt"),
            ctx.web_root.as_ref().unwrap().join("leak.txt"),
        )
        .unwrap();
        let response = static_response(ctx, "/leak.txt").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn static_assets_allow_encoded_names_and_spa_routes() {
        let (ctx, _directory) = web_context();
        std::fs::write(
            ctx.web_root.as_ref().unwrap().join("build.. notes.txt"),
            "asset",
        )
        .unwrap();
        for (uri, expected) in [
            ("/build..%20notes.txt", "asset"),
            ("/project/results", "app shell"),
        ] {
            let response = static_response(ctx.clone(), uri).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(body.as_ref(), expected.as_bytes());
        }
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

    #[tokio::test]
    async fn schedule_removal_accepts_the_frontends_project_id() {
        let (mut ctx, directory) = test_context();
        let store =
            crate::schedule_store::ScheduleStore::open(&directory.path().join("schedules.sqlite3"))
                .unwrap();
        Arc::get_mut(&mut ctx).unwrap().schedules =
            crate::schedule_store::ScheduleState::available(store);
        dispatch::dispatch(
            &ctx,
            "set_scan_schedule",
            serde_json::json!({
                "projectId": "project-one", "canonicalPath": directory.path(),
                "displayName": "Project", "intervalHours": 1, "enabled": true
            }),
        )
        .await
        .unwrap();
        dispatch::dispatch(
            &ctx,
            "remove_scan_schedule",
            serde_json::json!({"projectId": "project-one"}),
        )
        .await
        .unwrap();
        assert_eq!(
            dispatch::dispatch(&ctx, "list_scan_schedules", serde_json::json!({}))
                .await
                .unwrap(),
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn save_retries_accept_the_frontends_retry_token() {
        let (ctx, _directory) = test_context();
        let error = dispatch::dispatch(
            &ctx,
            "retry_source_run_save",
            serde_json::json!({"retryToken": "missing"}),
        )
        .await
        .unwrap_err();
        assert_eq!(error["code"], "notFound");
    }

    #[tokio::test]
    async fn source_rechecks_repeat_the_original_options_through_the_server() {
        let (ctx, directory) = test_context();
        let project = directory.path().join("project");
        std::fs::create_dir_all(project.join("ignored")).unwrap();
        std::fs::write(
            project.join("handler.js"),
            "function run(input) { eval(input); }\n",
        )
        .unwrap();
        std::fs::write(
            project.join("ignored/other.js"),
            "function run(input) { eval(input); }\n",
        )
        .unwrap();
        let original = dispatch::dispatch(
            &ctx,
            "scan_project",
            serde_json::json!({"options": {
                "path": project, "includeGit": false, "followSymlinks": false,
                "maxFileSizeKb": 512, "scanSecrets": false, "scanVulnerabilities": true,
                "extraIgnoredDirs": ["ignored"]
            }}),
        )
        .await
        .unwrap();
        assert_eq!(original["status"], "completed");
        std::fs::write(
            project.join("handler.js"),
            "function run(input) { return JSON.parse(input); }\n",
        )
        .unwrap();
        let rechecked = dispatch::dispatch(
            &ctx,
            "recheck_source_run",
            serde_json::json!({
                "originalRunId": original["runId"], "projectId": original["projectId"]
            }),
        )
        .await
        .unwrap();
        assert_eq!(rechecked["run"]["status"], "completed");
        assert_ne!(rechecked["run"]["runId"], original["runId"]);
        assert_eq!(rechecked["run"]["summary"]["totalFindings"], 0);
        assert_eq!(rechecked["options"]["scanSecrets"], false);
        assert_eq!(rechecked["options"]["maxFileSizeKb"], 512);
        assert!(rechecked["options"]["extraIgnoredDirs"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("ignored")));
    }

    fn write_custom_pack(directory: &std::path::Path, pattern: &str) -> PathBuf {
        use oxaudit_scanners::{
            FixtureExpectation, RuleDefinition, RuleEngine, RulePack, RulePackMetadata, RuleScope,
        };
        use sha2::{Digest, Sha256};
        let provenance = |hash: String| oxaudit_domain::Provenance {
            authors: vec!["oxAudit contributors".into()],
            source: "independent test fixture".into(),
            license: "Apache-2.0".into(),
            creation_method: oxaudit_domain::CreationMethod::IndependentlyDerived,
            content_sha256: hash,
        };
        let fixture = |id: &str| FixtureExpectation {
            id: id.into(),
            path: format!("{id}.txt"),
            sha256: format!("{:x}", Sha256::digest(id.as_bytes())),
            expected_values: Vec::new(),
        };
        let rules = vec![RuleDefinition {
            id: "source.custom".into(),
            version: "1".into(),
            title: "Custom dangerous call".into(),
            description: "Detect a custom call".into(),
            recommendation: "Use a safe parser".into(),
            engine: RuleEngine::SourceRegex,
            severity: oxaudit_domain::Severity::High,
            scope: RuleScope {
                languages: vec!["javascript".into()],
                platforms: Vec::new(),
                architectures: Vec::new(),
                file_extensions: Vec::new(),
            },
            pattern: pattern.into(),
            classifications: Vec::new(),
            provenance: provenance("b".repeat(64)),
            positive_fixtures: vec![fixture("positive")],
            negative_fixtures: vec![fixture("negative")],
        }];
        let hash = RulePack::computed_content_sha256(&rules).unwrap();
        let pack = RulePack {
            pack: RulePackMetadata {
                schema_version: 1,
                id: oxaudit_domain::RulePackId::parse("rulepack.recheck").unwrap(),
                name: "Recheck pack".into(),
                version: "1.0.0".into(),
                minimum_oxaudit_version: "0.1.0".into(),
                content_sha256: hash.clone(),
                provenance: provenance(hash),
            },
            rules,
        };
        std::fs::write(directory.join("positive.txt"), "positive").unwrap();
        std::fs::write(directory.join("negative.txt"), "negative").unwrap();
        let path = directory.join("pack.toml");
        std::fs::write(&path, toml::to_string(&pack).unwrap()).unwrap();
        path
    }

    async fn custom_pack_scan(
        one_off: bool,
    ) -> (Arc<ServerContext>, tempfile::TempDir, Value, PathBuf) {
        let (mut ctx, directory) = test_context();
        let store =
            crate::rulepack_store::RulePackStore::open(&directory.path().join("packs.sqlite3"))
                .unwrap();
        Arc::get_mut(&mut ctx).unwrap().rule_packs =
            crate::rulepack_store::RulePacksState::available(store);
        let pack_path = write_custom_pack(directory.path(), r"dangerousEval\([^)]+\)");
        if !one_off {
            dispatch::dispatch(
                &ctx,
                "install_rule_pack",
                serde_json::json!({"path": pack_path}),
            )
            .await
            .unwrap();
        }
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("handler.js"),
            "function run(input) { dangerousEval(input); }\n",
        )
        .unwrap();
        let original = dispatch::dispatch(&ctx, "scan_project", serde_json::json!({"options": {
            "path": project, "includeGit": false, "followSymlinks": false,
            "maxFileSizeKb": 512, "scanSecrets": false, "scanVulnerabilities": true,
            "extraIgnoredDirs": [], "extraRulePackFiles": if one_off { vec![pack_path.clone()] } else { Vec::new() }
        }})).await.unwrap();
        assert_eq!(original["summary"]["totalFindings"], 1);
        (ctx, directory, original, pack_path)
    }

    async fn recheck_custom(ctx: &ServerContext, original: &Value) -> Result<Value, Value> {
        dispatch::dispatch(
            ctx,
            "recheck_source_run",
            serde_json::json!({
                "originalRunId": original["runId"], "projectId": original["projectId"]
            }),
        )
        .await
    }

    #[tokio::test]
    async fn rechecks_keep_installed_and_one_off_pack_findings_detected() {
        for one_off in [false, true] {
            let (ctx, directory, original, _pack_path) = custom_pack_scan(one_off).await;
            if !one_off {
                dispatch::dispatch(
                    &ctx,
                    "set_rule_pack_enabled",
                    serde_json::json!({"id": "rulepack.recheck", "enabled": false}),
                )
                .await
                .unwrap();
            }
            let rechecked = recheck_custom(&ctx, &original).await.unwrap();
            assert_eq!(
                rechecked["run"]["summary"]["totalFindings"], 1,
                "one_off={one_off}"
            );
            assert_eq!(rechecked["run"]["findings"][0]["diffStatus"], "unchanged");
            std::fs::write(
                directory.path().join("project/handler.js"),
                "function run(input) { return JSON.parse(input); }\n",
            )
            .unwrap();
            let fixed = recheck_custom(&ctx, &original).await.unwrap();
            assert_eq!(fixed["run"]["summary"]["totalFindings"], 0);
            let comparison = dispatch::dispatch(
                &ctx,
                "compare_source_runs",
                serde_json::json!({
                    "currentRunId": fixed["run"]["runId"], "baselineRunId": original["runId"]
                }),
            )
            .await
            .unwrap();
            assert_eq!(comparison[0]["diffStatus"], "resolved");
        }
    }

    #[tokio::test]
    async fn source_scans_capture_absolute_one_off_paths_for_rechecks() {
        let (ctx, directory) = test_context();
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        let packs = tempfile::tempdir_in(&cwd).unwrap();
        let path = write_custom_pack(packs.path(), r"dangerousEval\([^)]+\)");
        let relative = path.strip_prefix(&cwd).unwrap();
        let project = directory.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("handler.js"), "dangerousEval(input);\n").unwrap();
        let original = dispatch::dispatch(
            &ctx,
            "scan_project",
            serde_json::json!({"options": {
                "path": project, "includeGit": false, "followSymlinks": false,
                "maxFileSizeKb": 512, "scanSecrets": false, "scanVulnerabilities": true,
                "extraIgnoredDirs": [], "extraRulePackFiles": [relative]
            }}),
        )
        .await
        .unwrap();
        assert_eq!(original["summary"]["totalFindings"], 1);
        let options = ctx
            .findings
            .service()
            .unwrap()
            .recheck_options(
                original["runId"].as_str().unwrap(),
                original["projectId"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(
            options.extra_rule_pack_files,
            [path.to_string_lossy().into_owned()]
        );
    }

    #[tokio::test]
    async fn rechecks_preserve_distinct_pack_contents_with_the_same_id() {
        for installed in [true, false] {
            let (ctx, directory, first, _pack_path) = custom_pack_scan(!installed).await;
            let extra_directory = directory.path().join("extra-pack");
            std::fs::create_dir(&extra_directory).unwrap();
            let extra = write_custom_pack(&extra_directory, r"otherEval\([^)]+\)");
            let mut options = ctx
                .findings
                .service()
                .unwrap()
                .recheck_options(
                    first["runId"].as_str().unwrap(),
                    first["projectId"].as_str().unwrap(),
                )
                .unwrap();
            options
                .extra_rule_pack_files
                .push(extra.to_string_lossy().into_owned());
            let original = dispatch::dispatch(
                &ctx,
                "scan_project",
                serde_json::json!({"options": options}),
            )
            .await
            .unwrap();
            assert_eq!(original["summary"]["totalFindings"], 1);
            if installed {
                dispatch::dispatch(
                    &ctx,
                    "set_rule_pack_enabled",
                    serde_json::json!({"id": "rulepack.recheck", "enabled": false}),
                )
                .await
                .unwrap();
            }
            let rechecked = recheck_custom(&ctx, &original).await.unwrap();
            assert_eq!(
                rechecked["run"]["summary"]["totalFindings"], 1,
                "installed={installed}"
            );
            assert_eq!(rechecked["run"]["findings"][0]["diffStatus"], "unchanged");
            if installed {
                dispatch::dispatch(
                    &ctx,
                    "remove_rule_pack",
                    serde_json::json!({"id": "rulepack.recheck"}),
                )
                .await
                .unwrap();
                assert_eq!(
                    recheck_custom(&ctx, &original).await.unwrap_err()["code"],
                    "dataOperationFailed"
                );
            }
        }
    }

    #[tokio::test]
    async fn changed_pack_snapshots_cannot_claim_that_a_finding_is_resolved() {
        for one_off in [false, true] {
            let (ctx, directory, original, pack_path) = custom_pack_scan(one_off).await;
            write_custom_pack(directory.path(), r"differentEval\([^)]+\)");
            if !one_off {
                dispatch::dispatch(
                    &ctx,
                    "install_rule_pack",
                    serde_json::json!({"path": pack_path}),
                )
                .await
                .unwrap();
            }
            let rechecked = recheck_custom(&ctx, &original).await.unwrap();
            assert_eq!(rechecked["run"]["summary"]["totalFindings"], 0);
            let comparison = dispatch::dispatch(
                &ctx,
                "compare_source_runs",
                serde_json::json!({
                    "currentRunId": rechecked["run"]["runId"], "baselineRunId": original["runId"]
                }),
            )
            .await
            .unwrap();
            assert_eq!(
                comparison[0]["diffStatus"], "notEvaluated",
                "one_off={one_off}"
            );
            assert_eq!(comparison[0]["resolvedByRunId"], Value::Null);
            let history = dispatch::dispatch(
                &ctx,
                "list_source_runs",
                serde_json::json!({"projectId": original["projectId"]}),
            )
            .await
            .unwrap();
            assert_eq!(history[0]["resolvedFindings"], 0);
        }
    }

    #[tokio::test]
    async fn missing_required_packs_fail_rechecks_instead_of_reporting_absence() {
        for one_off in [false, true] {
            let (ctx, _directory, original, pack_path) = custom_pack_scan(one_off).await;
            if one_off {
                std::fs::remove_file(pack_path).unwrap();
            } else {
                dispatch::dispatch(
                    &ctx,
                    "remove_rule_pack",
                    serde_json::json!({"id": "rulepack.recheck"}),
                )
                .await
                .unwrap();
            }
            let error = recheck_custom(&ctx, &original).await.unwrap_err();
            assert_eq!(error["code"], "dataOperationFailed");
        }
    }

    #[tokio::test]
    async fn rechecks_do_not_require_packs_from_baseline_only_observations() {
        let (ctx, _directory, first, _pack_path) = custom_pack_scan(false).await;
        dispatch::dispatch(
            &ctx,
            "remove_rule_pack",
            serde_json::json!({"id": "rulepack.recheck"}),
        )
        .await
        .unwrap();
        let options = ctx
            .findings
            .service()
            .unwrap()
            .recheck_options(
                first["runId"].as_str().unwrap(),
                first["projectId"].as_str().unwrap(),
            )
            .unwrap();
        let without_pack = dispatch::dispatch(
            &ctx,
            "scan_project",
            serde_json::json!({"options": options}),
        )
        .await
        .unwrap();
        assert_eq!(without_pack["summary"]["totalFindings"], 0);
        assert_eq!(without_pack["findings"][0]["diffStatus"], "notEvaluated");
        let rechecked = recheck_custom(&ctx, &without_pack).await.unwrap();
        assert_eq!(rechecked["run"]["status"], "completed");
    }
}
