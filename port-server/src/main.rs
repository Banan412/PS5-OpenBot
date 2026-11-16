#[cfg(target_vendor = "sie")]
use ps5_rt as _;

mod approvals_api;
mod bootstrap;
mod bots;
mod compat_extra;
mod compat_routes;
mod conversations;
mod copilot;
mod direct_threads;
#[allow(dead_code)]
mod event_journal;
#[allow(dead_code)]
mod governance;
mod local_auth;
#[allow(dead_code)]
mod model;
mod notifications;
mod origin;
mod preferences;
mod realtime;
mod routines;
#[allow(dead_code)]
mod run_engine;
mod runs;
#[allow(dead_code)]
mod storage;
mod virtual_computer;
mod www_assets;

#[cfg(feature = "embedded-www")]
mod embedded_assets {
    include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));
}

use axum::{
    extract::{Request, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
#[cfg(test)]
use axum::body::Body;
use percent_encoding::percent_decode_str;
use std::{
    env,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
struct AppState {
    root: Arc<PathBuf>,
}

fn app(
    root: PathBuf,
    auth: Option<local_auth::AuthState>,
    runs: Option<runs::RunState>,
    workspace_root: Option<PathBuf>,
) -> Router {
    let copilot = match (&auth, &runs) {
        (Some(auth), Some(runs)) => Some(copilot::Copilot::new(auth.clone(), runs.clone())),
        _ => None,
    };
    let router = Router::new()
        .route("/healthz", get(|| async { "OpenBot server running" }))
        .fallback(static_handler)
        .with_state(AppState {
            root: Arc::new(root),
        })
        .merge(bootstrap::router());
    let router = match auth {
        Some(state) => {
            let vc_state = runs
                .as_ref()
                .and_then(|r| r.virtual_computer_state())
                .unwrap_or_else(|| {
                    let ws_root = workspace_root
                        .unwrap_or_else(|| std::env::temp_dir().join("openbot-workspaces"));
                    virtual_computer::VirtualComputerState::new(state.clone(), ws_root)
                });
            router
                .merge(bots::router(state.clone()))
                .merge(conversations::router(state.clone()))
                .merge(direct_threads::router(state.clone()))
                .merge(preferences::router(state.clone()))
                .merge(notifications::router(state.clone()))
                .merge(compat_routes::router(state.clone()))
                .merge(routines::router(state.clone(), runs.clone()))
                .merge(approvals_api::router_with_runs(state.clone(), runs.clone()))
                .merge(virtual_computer::router(vc_state))
                .merge(realtime::router(realtime::Gateway::new(
                    state.clone(),
                    runs.clone(),
                )))
                .merge(local_auth::router(state))
        }
        None => router,
    };
    let router = match runs {
        Some(state) => router.merge(runs::router(state)),
        None => router,
    };
    match copilot {
        Some(state) => router.merge(copilot::router(state)),
        None => router,
    }
}

async fn static_handler(State(state): State<AppState>, request: Request) -> Response {
    let path = request.uri().path();
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if request.headers().contains_key(header::UPGRADE) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let decoded = match percent_decode_str(path).decode_utf8() {
        Ok(value) => value,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if decoded == "/api" || decoded.starts_with("/api/") {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "OpenBot API is not implemented",
        )
            .into_response();
    }
    if decoded.contains('\\') || decoded.contains(':') || decoded.contains('\0') {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let relative = Path::new(decoded.trim_start_matches('/'));
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let is_head = request.method() == Method::HEAD;
    let accepts_gzip = www_assets::accepts_gzip(request.headers());
    if !relative.as_os_str().is_empty() {
        if let Some(response) = serve_file(&state.root, relative, is_head, accepts_gzip).await {
            return response;
        }
    }
    let accepts_html = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().split(';').next() == Some("text/html"))
        })
        .unwrap_or(false);
    let navigate = request
        .headers()
        .get("sec-fetch-mode")
        .map(|v| v == "navigate")
        .unwrap_or(true);
    let has_extension = relative
        .file_name()
        .and_then(|v| Path::new(v).extension())
        .is_some();
    if accepts_html
        && navigate
        && !has_extension
        && decoded != "/assets"
        && !decoded.starts_with("/assets/")
    {
        if let Some(response) =
            serve_file(&state.root, Path::new("index.html"), is_head, accepts_gzip).await
        {
            return response;
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn serve_file(
    root: &Path,
    relative: &Path,
    head: bool,
    accepts_gzip: bool,
) -> Option<Response> {
    #[cfg(feature = "embedded-www")]
    {
        let _ = root;
        www_assets::response_for_embedded(
            relative,
            head,
            accepts_gzip,
            embedded_assets::asset_with_gzip,
        )
    }
    #[cfg(not(feature = "embedded-www"))]
    {
        www_assets::response_for_file(root, relative, head, accepts_gzip).await
    }
}

fn load_env_file(path: &Path) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim();
            let val = v.trim().trim_matches('"').trim_matches('\'');
            if !key.is_empty() {
                out.insert(key.to_owned(), val.to_owned());
            }
        }
    }
    out
}

fn cfg_value(
    key: &str,
    file_cfg: &std::collections::BTreeMap<String, String>,
    ps5_default: Option<&str>,
) -> Option<String> {
    if let Ok(v) = env::var(key) {
        return Some(v);
    }
    if let Some(v) = file_cfg.get(key) {
        return Some(v.clone());
    }
    if cfg!(target_vendor = "sie") {
        ps5_default.map(str::to_owned)
    } else {
        None
    }
}

fn safe_log(msg: &str) {
    use std::io::Write;
    let mut err = std::io::stderr();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.write_all(b"\n");
    let _ = err.flush();
}

#[cfg(target_vendor = "sie")]
fn parse_pid_record(raw: &str) -> Option<(i32, Option<i64>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.split_once(':') {
        Some((p, b)) => Some((p.trim().parse().ok()?, Some(b.trim().parse().ok()?))),
        None => Some((trimmed.parse().ok()?, None)),
    }
}

#[cfg(target_vendor = "sie")]
fn probe_writable_dir(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".write_probe");
    match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(target_vendor = "sie")]
fn resolve_ps5_data_dir() -> PathBuf {
    let preferred = Path::new("/data/openbot");
    for attempt in 0..48 {
        if probe_writable_dir(preferred) {
            return preferred.to_path_buf();
        }
        if attempt == 0 {
            safe_log("[ps5-openbot] waiting for /data mount readiness...");
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let fallback = Path::new("/download0/openbot");
    if probe_writable_dir(fallback) {
        safe_log("[ps5-openbot] /data unavailable; using /download0/openbot");
        return fallback.to_path_buf();
    }
    preferred.to_path_buf()
}

#[cfg(target_vendor = "sie")]
fn prepare_ps5_environment(data_dir: &Path, setup_token_file: &str) -> PathBuf {
    let _ = std::fs::create_dir_all(data_dir.join("workspaces"));
    let _ = std::fs::create_dir_all(data_dir.join("www"));
    let token_path = Path::new(setup_token_file);
    if !token_path.exists() {
        if let Some(parent) = token_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut raw = [0u8; 24];
        if getrandom::getrandom(&mut raw).is_ok() {
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            if std::fs::write(token_path, &hex).is_ok() {
                safe_log(&format!("Generated initial PS5 setup token at {}", token_path.display()));
            }
        }
    }

    let pid_path = data_dir.join("openbot.pid");
    let my_pid = ps5_rt::current_pid();
    let boot = ps5_rt::kernel_boot_time_secs();
    if let Ok(raw) = std::fs::read_to_string(&pid_path) {
        if let Some((old_pid, old_boot)) = parse_pid_record(&raw) {
            let stale_boot = match (old_boot, boot) {
                (Some(a), Some(b)) => a.abs_diff(b) > 5,
                _ => false,
            };
            if !stale_boot
                && old_pid > 1
                && old_pid != my_pid
                && ps5_rt::is_pid_alive(old_pid)
                && ps5_rt::is_pid_openbot(old_pid)
            {
                safe_log(&format!("Stopping previous openbot instance pid={old_pid}"));
                let _ = ps5_rt::kill_pid(old_pid, ps5_rt::SIGTERM);
                for _ in 0..15 {
                    if !ps5_rt::is_pid_alive(old_pid) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }
    }
    pid_path
}

#[cfg(target_vendor = "sie")]
fn write_ps5_pid(pid_path: &Path) {
    let my_pid = ps5_rt::current_pid();
    let boot = ps5_rt::kernel_boot_time_secs();
    let record = match boot {
        Some(b) => format!("{my_pid}:{b}\n"),
        None => format!("{my_pid}\n"),
    };
    let _ = std::fs::write(pid_path, record);
}

#[cfg(target_vendor = "sie")]
fn cleanup_ps5_pid(pid_path: &Path) {
    let my_pid = ps5_rt::current_pid();
    if let Ok(raw) = std::fs::read_to_string(pid_path) {
        if let Some((pid, _)) = parse_pid_record(&raw) {
            if pid == my_pid {
                let _ = std::fs::remove_file(pid_path);
            }
        }
    }
}

#[cfg(target_vendor = "sie")]
fn append_startup_error(data_dir: &Path, msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("startup_error.log"))
    {
        use std::io::Write;
        let _ = writeln!(f, "{msg}");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_vendor = "sie")]
    {
        let _ = ps5_rt::set_process_name("ps5-openbot.elf");
        ps5_rt::ignore_daemon_signals();
    }

    #[cfg(target_vendor = "sie")]
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_stack_size(1024 * 1024)
        .enable_all()
        .build()?;
    #[cfg(not(target_vendor = "sie"))]
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let res = rt.block_on(async_main());
    #[cfg(target_vendor = "sie")]
    {
        drop(rt);
        let code = if res.is_ok() { 0 } else { 1 };
        if let Err(ref e) = res {
            let msg = format!("openbot-port-server exiting with error: {e}");
            safe_log(&msg);
            append_startup_error(Path::new("/data/openbot"), &msg);
        }
        unsafe {
            extern "C" {
                fn _exit(status: i32) -> !;
            }
            _exit(code)
        }
    }
    #[cfg(not(target_vendor = "sie"))]
    res
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_vendor = "sie")]
    let ps5_data_dir = resolve_ps5_data_dir();
    #[cfg(not(target_vendor = "sie"))]
    let ps5_data_dir = PathBuf::from("/data/openbot");

    let file_cfg = load_env_file(&ps5_data_dir.join("openbot.env"));
    #[cfg(target_vendor = "sie")]
    let ps5_www_default = ps5_data_dir.join("www").to_string_lossy().into_owned();
    #[cfg(not(target_vendor = "sie"))]
    let ps5_www_default = "/data/openbot/www".to_owned();
    #[cfg(target_vendor = "sie")]
    let ps5_db_default = ps5_data_dir.join("openbot.db").to_string_lossy().into_owned();
    #[cfg(not(target_vendor = "sie"))]
    let ps5_db_default = "/data/openbot/openbot.db".to_owned();
    #[cfg(target_vendor = "sie")]
    let ps5_ws_default = ps5_data_dir.join("workspaces").to_string_lossy().into_owned();
    #[cfg(not(target_vendor = "sie"))]
    let ps5_ws_default = "/data/openbot/workspaces".to_owned();
    #[cfg(target_vendor = "sie")]
    let ps5_tok_default = ps5_data_dir.join("setup.token").to_string_lossy().into_owned();
    #[cfg(not(target_vendor = "sie"))]
    let ps5_tok_default = "/data/openbot/setup.token".to_owned();

    #[cfg(target_vendor = "sie")]
    let pid_path = Some(prepare_ps5_environment(
        &ps5_data_dir,
        cfg_value("OPENBOT_SETUP_TOKEN_FILE", &file_cfg, Some(&ps5_tok_default))
            .as_deref()
            .unwrap_or(&ps5_tok_default),
    ));

    let bind: SocketAddr = cfg_value("OPENBOT_BIND", &file_cfg, Some("0.0.0.0:3010"))
        .unwrap_or_else(|| "127.0.0.1:3010".into())
        .parse()?;
    #[cfg(not(feature = "embedded-www"))]
    let dir = cfg_value("OPENBOT_WWW_DIR", &file_cfg, Some(&ps5_www_default))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../app/dist"));
    #[cfg(not(feature = "embedded-www"))]
    let root = {
        let mut last_err = None;
        let mut found = None;
        let tries = if cfg!(target_vendor = "sie") { 20 } else { 1 };
        for i in 0..tries {
            match tokio::fs::canonicalize(&dir).await {
                Ok(p) => {
                    found = Some(p);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    if i + 1 < tries {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    }
                }
            }
        }
        match found {
            Some(p) => p,
            None => {
                return Err(format!(
                    "cannot open asset directory {}: {}",
                    dir.display(),
                    last_err.unwrap()
                )
                .into())
            }
        }
    };
    #[cfg(not(feature = "embedded-www"))]
    if !tokio::fs::metadata(&root).await?.is_dir() {
        return Err("asset path is not a directory".into());
    }
    #[cfg(feature = "embedded-www")]
    let root = PathBuf::new();
    let listener = tokio::net::TcpListener::bind(bind).await?;
    #[cfg(target_vendor = "sie")]
    if let Some(ref p) = pid_path {
        write_ps5_pid(p);
    }
    #[cfg(not(feature = "embedded-www"))]
    safe_log(&format!(
        "Serving static assets from {} on {}",
        root.display(),
        listener.local_addr()?
    ));
    #[cfg(feature = "embedded-www")]
    safe_log(&format!("Serving embedded website on {}", listener.local_addr()?));
    if let SocketAddr::V4(addr) = listener.local_addr()? {
        if addr.ip().is_unspecified() {
            match origin::system_ipv4() {
                Ok(mut ips) => {
                    ips.retain(|ip| !ip.is_loopback() && !ip.is_unspecified());
                    ips.sort_unstable();
                    ips.dedup();
                    for ip in ips {
                        safe_log(&format!("Possible network address: http://{}:{}/", ip, addr.port()));
                    }
                }
                Err(error) => safe_log(&format!("Could not enumerate network addresses: {error}")),
            }
        }
    }
    let db_path_str = cfg_value("OPENBOT_DB_PATH", &file_cfg, Some(&ps5_db_default));
    let auth = match cfg_value("OPENBOT_ALLOWED_ORIGIN", &file_cfg, Some("auto")) {
        Some(origin) => {
            let path = PathBuf::from(
                db_path_str
                    .as_deref()
                    .ok_or("OPENBOT_DB_PATH is required when local authentication is enabled")?,
            );
            let db = Arc::new(storage::Storage::open(path)?);
            let setup = match cfg_value(
                "OPENBOT_SETUP_TOKEN_FILE",
                &file_cfg,
                Some(&ps5_tok_default),
            ) {
                Some(path) => match std::fs::read_to_string(&path) {
                    Ok(s) => Some(s),
                    Err(e) if cfg!(target_vendor = "sie") && e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(e.into()),
                },
                None => None,
            };
            let token = setup.as_deref().map(|s| s.trim_end_matches(['\r', '\n']));
            let state = if origin == "auto" {
                let addr = match listener.local_addr()? {
                    SocketAddr::V4(addr) => addr,
                    SocketAddr::V6(_) => {
                        return Err("automatic origin requires an IPv4 listener".into())
                    }
                };
                local_auth::AuthState::new_automatic(
                    db,
                    *addr.ip(),
                    addr.port(),
                    token,
                )?
            } else {
                local_auth::AuthState::new(db, &origin, token)?
            };
            let open_setup = cfg!(target_vendor = "sie")
                || cfg_value("OPENBOT_OPEN_SETUP", &file_cfg, None).as_deref() == Some("1");
            let state = if open_setup {
                let require_token =
                    cfg_value("OPENBOT_REQUIRE_SETUP_TOKEN", &file_cfg, Some("0")).as_deref() == Some("1");
                state.with_ps5_open_setup(require_token)
            } else {
                state
            };
            Some(state)
        }
        None => None,
    };
    let workspace_root = cfg_value(
        "OPENBOT_WORKSPACE_DIR",
        &file_cfg,
        Some(&ps5_ws_default),
    )
    .map(PathBuf::from)
    .or_else(|| {
        db_path_str
            .as_deref()
            .map(PathBuf::from)
            .and_then(|p| p.parent().map(|d| d.join("workspaces")))
    });
    if let Some(ref ws_root) = workspace_root {
        let _ = std::fs::create_dir_all(ws_root);
    }
    let runs = match (
        cfg_value("OPENBOT_MODEL_URL", &file_cfg, Some("http://127.0.0.1:8081/v1")),
        cfg_value("OPENBOT_MODEL_ID", &file_cfg, Some("auto")),
    ) {
        (Some(url), Some(model)) => {
            let a = auth
                .clone()
                .ok_or("model runs require local authentication")?;
            let vc_root = workspace_root
                .clone()
                .unwrap_or_else(|| std::env::temp_dir().join("openbot-workspaces"));
            let rs = runs::RunState::new(a.clone(), &url, model)?;
            let rs = if cfg_value("OPENBOT_ENABLE_TOOLS", &file_cfg, Some("1")).as_deref() != Some("0") {
                rs.with_virtual_computer(virtual_computer::VirtualComputerState::new(a, vc_root))
            } else {
                rs
            };
            Some(rs)
        }
        (None, None) => None,
        _ => return Err("set both OPENBOT_MODEL_URL and OPENBOT_MODEL_ID".into()),
    };
    #[cfg(target_vendor = "sie")]
    ps5_rt::detach_stdio();

    if let Some(ref auth_state) = auth {
        routines::spawn_scheduler(auth_state.clone(), runs.clone());
    }
    axum::serve(listener, app(root, auth, runs, workspace_root))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    #[cfg(target_vendor = "sie")]
    cleanup_ps5_pid(&pid_path.unwrap());
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(all(test, not(feature = "embedded-www")))]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use tower::ServiceExt;

    #[cfg(not(feature = "embedded-www"))]
    #[tokio::test]
    async fn static_routes_never_mask_missing_api_assets_or_upgrades() {
        let dir = std::env::temp_dir().join(format!("openbot-static-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("index.html"), "<html>app</html>").unwrap();
        std::fs::write(dir.join("assets/app.js"), "console.log(1)").unwrap();
        let server = app(std::fs::canonicalize(&dir).unwrap(), None, None, None);
        for (path, expected) in [
            ("/api/v2/test", StatusCode::NOT_IMPLEMENTED),
            ("/%61pi/test", StatusCode::NOT_IMPLEMENTED),
            ("/assets/missing.js", StatusCode::NOT_FOUND),
            ("/assets/missing", StatusCode::NOT_FOUND),
            ("/%2e%2e/private", StatusCode::BAD_REQUEST),
            ("/conversations/123", StatusCode::OK),
        ] {
            let response = server
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("accept", "text/html")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path}");
        }
        let response = server
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/assets/app.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .contains("javascript"));
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "console.log(1)"
        );
        let response = server
            .oneshot(
                Request::builder()
                    .uri("/conversation")
                    .header("accept", "text/html")
                    .header("upgrade", "websocket")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, feature = "embedded-www"))]
mod embedded_tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn embedded_spa_fallback_does_not_mask_api_or_missing_assets() {
        let server = app(PathBuf::new(), None, None, None);
        for (path, status) in [
            ("/", StatusCode::OK),
            ("/some/deep/link", StatusCode::OK),
            ("/assets/missing.js", StatusCode::NOT_FOUND),
            ("/api/missing", StatusCode::NOT_IMPLEMENTED),
        ] {
            let response = server
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("accept", "text/html")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{path}");
            if status == StatusCode::OK {
                assert!(to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap()
                    .starts_with(b"<!doctype html>"));
            }
        }
    }
}
