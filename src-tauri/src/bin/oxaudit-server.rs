//! oxAudit headless server: the desktop's command surface over HTTP + SSE
//! with the browser GUI served alongside. Everything lives in
//! `oxaudit_lib::server` so the server runs the same engines the desktop
//! app and the CLI run.

use clap::Parser;
use oxaudit_lib::server::ServerConfig;

/// Serve oxAudit's scan surface to browsers over HTTP.
#[derive(Parser, Debug)]
#[command(name = "oxaudit-server", about, version)]
struct Args {
    /// Address and port to bind. Loopback by default: a server that can
    /// read arbitrary local paths should not be reachable from the network
    /// by accident — bind 0.0.0.0 deliberately (e.g. inside a container),
    /// behind a tunnel or reverse proxy that terminates TLS.
    #[arg(long, default_value_t = default_bind())]
    bind: std::net::SocketAddr,

    /// Directory for the findings database, caches, and schedules
    /// (defaults to ~/.oxaudit-server/data; containers typically mount /data
    /// here).
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,

    /// Directory for settings.json and assistant sessions
    /// (defaults to ~/.oxaudit-server/config).
    #[arg(long)]
    config_dir: Option<std::path::PathBuf>,

    /// Root of the built frontend to serve (the repository's dist/ after
    /// `npm run build`). Without it, only the API is served.
    #[arg(long)]
    web_root: Option<std::path::PathBuf>,

    /// Access token every API call must present as `Authorization: Bearer
    /// <token>`. Falls back to OXAUDIT_SERVER_TOKEN, then to a freshly
    /// generated token printed on startup and stored beside the data
    /// directory with owner-only permissions.
    #[arg(long)]
    token: Option<String>,
}

/// The container entrypoint supplies its bind address through the
/// environment; a bare host defaults to loopback, never to the network.
fn default_bind() -> std::net::SocketAddr {
    std::env::var("OXAUDIT_SERVER_BIND")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:8080".parse().expect("valid default bind"))
}

fn resolve_token(args: &Args, data_dir: &std::path::Path) -> Result<String, String> {
    if let Some(token) = &args.token {
        if token.trim().is_empty() {
            return Err("--token must not be empty".into());
        }
        return Ok(token.trim().to_string());
    }
    if let Ok(token) = std::env::var("OXAUDIT_SERVER_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(token.trim().to_string());
        }
    }
    // Generated tokens are persisted owner-only so the operator can look
    // the token up again after a restart without it ever appearing in a
    // shell history line.
    let token_path = data_dir.join("server-token");
    if let Ok(existing) = std::fs::read_to_string(&token_path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            eprintln!(
                "Reusing the access token stored at {}",
                token_path.display()
            );
            return Ok(trimmed.to_string());
        }
    }
    let token = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = token_path.parent() {
        oxaudit_lib::private_storage::ensure_private_dir(parent)
            .map_err(|error| format!("cannot prepare the data directory: {error}"))?;
    }
    std::fs::write(&token_path, format!("{token}\n"))
        .map_err(|error| format!("cannot store the generated token: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
    }
    eprintln!(
        "Generated a new access token, stored at {} (chmod 600):\n\n  {}\n",
        token_path.display(),
        token
    );
    Ok(token)
}

fn home_dir() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn main() {
    let args = Args::parse();
    let data_dir = args
        .data_dir
        .clone()
        .or_else(|| std::env::var_os("OXAUDIT_SERVER_DATA_DIR").map(std::path::PathBuf::from))
        .unwrap_or_else(|| home_dir().join(".oxaudit-server").join("data"));
    let config_dir = args
        .config_dir
        .clone()
        .or_else(|| std::env::var_os("OXAUDIT_SERVER_CONFIG_DIR").map(std::path::PathBuf::from))
        .unwrap_or_else(|| home_dir().join(".oxaudit-server").join("config"));
    let web_root = args
        .web_root
        .clone()
        .or_else(|| std::env::var_os("OXAUDIT_SERVER_WEB_ROOT").map(std::path::PathBuf::from));
    let token = match resolve_token(&args, &data_dir) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("oxaudit-server: {error}");
            std::process::exit(2);
        }
    };
    let config = ServerConfig {
        bind: args.bind,
        data_dir,
        config_dir,
        web_root,
        token,
    };
    if let Err(error) = oxaudit_lib::server::run(config) {
        eprintln!("oxaudit-server: {error}");
        std::process::exit(3);
    }
}
