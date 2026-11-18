//! In-process PS5-safe virtual computer: jailed per-bot workspace, pure-Rust
//! virtual POSIX shell, SSRF-hardened web fetch, PNG/JPEG screen renderer,
//! and live screen/terminal WebSockets. Zero fork/exec, zero external crates.

use crate::local_auth::{self, AuthState, Identity};
use crate::origin;
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, Query, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::redirect::Policy;
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::{Component, Path as StdPath, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::{Notify, Semaphore};

pub const SCREEN_WIDTH: u32 = 640;
pub const SCREEN_HEIGHT: u32 = 400;

const MAX_FILE_SIZE: usize = 512 * 1024;
const MAX_WORKSPACE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILE_COUNT: usize = 512;
const MAX_FETCH_BYTES: usize = 384 * 1024;
const MAX_PROXY_BYTES: usize = 12 * 1024 * 1024;
const MAX_PAGE_TEXT_CHARS: usize = 8 * 1024;
const MAX_PREVIEW_HTML_BYTES: usize = 24 * 1024;
const MAX_TOOL_OUTPUT_CHARS: usize = 3072;
const MAX_BRIDGE_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SHELL_OUTPUT: usize = 256 * 1024;
const MAX_SHELL_STATEMENTS: usize = 32;
const MAX_TERMINAL_HISTORY: usize = 32;
const MAX_IDEMPOTENCY_ENTRIES: usize = 128;
const MAX_SOCKETS: usize = 16;
const CHROME_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

fn generate_proxy_token() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut bytes);
    let mut out = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Public State & Dispatcher
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct VirtualComputerState {
    inner: Arc<VirtualComputerInner>,
}

struct VirtualComputerInner {
    auth: AuthState,
    workspace_root: PathBuf,
    computers: Mutex<HashMap<String, Arc<Mutex<BotComputer>>>>,
    idempotency: Mutex<VecDeque<IdempotencyRecord>>,
    sockets: Arc<Semaphore>,
    dns_jobs: Arc<Semaphore>,
    dns_cache: Mutex<HashMap<(String, u16, bool), (Vec<SocketAddr>, Instant)>>,
    http_clients: Mutex<HashMap<(String, u16, bool, bool), (reqwest::Client, Instant)>>,
    viewer_seq: AtomicU64,
}

#[derive(Clone)]
struct IdempotencyRecord {
    actor_id: String,
    org_id: String,
    bot_id: String,
    op: String,
    key: String,
    fingerprint: [u8; 32],
    status: StatusCode,
    body: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ControlHolder {
    Bot,
    Human,
}

impl ControlHolder {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bot => "bot",
            Self::Human => "human",
        }
    }
}

#[derive(Clone)]
struct ControlRequestState {
    id: String,
    tool_call_id: Option<String>,
    reason: String,
    source: String,
    status: String,
    created_at: String,
    updated_at: String,
}

struct BotComputer {
    bot_id: String,
    proxy_token: String,
    allow_all_web_pages: bool,
    cwd: String,
    holder: ControlHolder,
    held_by: Option<String>,
    since: String,
    active_request: Option<ControlRequestState>,
    current_url: String,
    page_title: String,
    page_text: String,
    page_html: String,
    bridge_png: Option<Vec<u8>>,
    last_input: String,
    cursor_x: u32,
    cursor_y: u32,
    terminal_lines: VecDeque<String>,
    screen_revision: u64,
    screen_notify: Arc<Notify>,
    active_screen_viewer: u64,
    cookie_jar: HashMap<(String, String), String>,
}

#[derive(Clone)]
struct ScreenSnapshot {
    bot_id: String,
    proxy_token: String,
    holder: ControlHolder,
    current_url: String,
    page_title: String,
    page_text: String,
    page_html: String,
    bridge_png: Option<Vec<u8>>,
    last_input: String,
    cursor_x: u32,
    cursor_y: u32,
    terminal_lines: Vec<String>,
    revision: u64,
}

impl BotComputer {
    fn new(bot_id: String) -> Self {
        let mut terminal_lines = VecDeque::with_capacity(MAX_TERMINAL_HISTORY);
        terminal_lines.push_back("OpenBot-PS5 Virtual Computer ready.".to_owned());
        Self {
            bot_id,
            proxy_token: generate_proxy_token(),
            allow_all_web_pages: allow_all_web_pages_from_env(),
            cwd: String::new(),
            holder: ControlHolder::Bot,
            held_by: None,
            since: now_iso(),
            active_request: None,
            current_url: "about:blank".to_owned(),
            page_title: "Virtual Computer".to_owned(),
            page_text: "No page loaded yet. Use computer_web_fetch or terminal.".to_owned(),
            page_html: String::new(),
            bridge_png: None,
            last_input: String::new(),
            cursor_x: SCREEN_WIDTH / 2,
            cursor_y: SCREEN_HEIGHT / 2,
            terminal_lines,
            screen_revision: 1,
            screen_notify: Arc::new(Notify::new()),
            active_screen_viewer: 0,
            cookie_jar: HashMap::new(),
        }
    }

    fn snapshot(&self) -> ScreenSnapshot {
        ScreenSnapshot {
            bot_id: self.bot_id.clone(),
            proxy_token: self.proxy_token.clone(),
            holder: self.holder,
            current_url: self.current_url.clone(),
            page_title: self.page_title.clone(),
            page_text: self.page_text.clone(),
            page_html: self.page_html.clone(),
            bridge_png: self.bridge_png.clone(),
            last_input: self.last_input.clone(),
            cursor_x: self.cursor_x,
            cursor_y: self.cursor_y,
            terminal_lines: self.terminal_lines.iter().cloned().collect(),
            revision: self.screen_revision,
        }
    }

    fn push_terminal_line(&mut self, line: &str) {
        for part in line.lines() {
            if self.terminal_lines.len() >= MAX_TERMINAL_HISTORY {
                self.terminal_lines.pop_front();
            }
            let clipped: String = part.chars().take(120).collect();
            self.terminal_lines.push_back(clipped);
        }
        self.bump_screen();
    }

    fn bump_screen(&mut self) {
        self.screen_revision = self.screen_revision.saturating_add(1);
        self.screen_notify.notify_waiters();
    }

    fn control_json(&self) -> Value {
        let req_val = self.active_request.as_ref().map(|r| {
            let mut obj = json!({
                "id": r.id,
                "reason": r.reason,
                "source": r.source,
                "status": r.status,
                "createdAt": r.created_at,
                "updatedAt": r.updated_at,
            });
            if let Some(tc) = &r.tool_call_id {
                obj.as_object_mut()
                    .unwrap()
                    .insert("toolCallId".to_owned(), Value::String(tc.clone()));
            }
            obj
        });
        let waiting = self
            .active_request
            .as_ref()
            .is_some_and(|r| r.status == "waiting");
        let reason = self
            .active_request
            .as_ref()
            .filter(|r| r.status == "waiting" || r.status == "taken")
            .map(|r| Value::String(r.reason.clone()))
            .unwrap_or(Value::Null);
        let mut out = json!({
            "holder": self.holder.as_str(),
            "since": self.since,
            "requested": waiting,
            "reason": reason,
            "transitioning": false,
            "resumeSnapshotRequired": false,
            "recoveryRequired": false,
        });
        if let Some(req) = req_val {
            out.as_object_mut()
                .unwrap()
                .insert("request".to_owned(), req);
        }
        if let Some(by) = &self.held_by {
            out.as_object_mut()
                .unwrap()
                .insert("heldBy".to_owned(), Value::String(by.clone()));
        }
        out
    }
}

impl VirtualComputerState {
    pub fn new(auth: AuthState, workspace_root: PathBuf) -> Self {
        Self {
            inner: Arc::new(VirtualComputerInner {
                auth,
                workspace_root,
                computers: Mutex::new(HashMap::new()),
                idempotency: Mutex::new(VecDeque::new()),
                sockets: Arc::new(Semaphore::new(MAX_SOCKETS)),
                dns_jobs: Arc::new(Semaphore::new(8)),
                dns_cache: Mutex::new(HashMap::new()),
                http_clients: Mutex::new(HashMap::new()),
                viewer_seq: AtomicU64::new(1),
            }),
        }
    }

    async fn pooled_client_for_url(
        &self,
        url: &reqwest::Url,
        allow_private: bool,
        long_timeout: bool,
    ) -> Result<reqwest::Client, String> {
        let host = url
            .host_str()
            .unwrap_or("")
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        let port = url.port_or_known_default().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let client_key = (host.clone(), port, allow_private, long_timeout);
        let now = Instant::now();
        let ttl = Duration::from_secs(300);

        if let Ok(mut clients) = self.inner.http_clients.lock() {
            if let Some((cached, ts)) = clients.get(&client_key) {
                if now.duration_since(*ts) < ttl {
                    return Ok(cached.clone());
                }
            }
            if clients.len() >= 128 {
                clients.retain(|_, (_, ts)| now.duration_since(*ts) < ttl);
                if clients.len() >= 128 {
                    clients.clear();
                }
            }
        }

        let dns_key = (host.clone(), port, allow_private);
        let cached_addrs = if let Ok(dns) = self.inner.dns_cache.lock() {
            if let Some((addrs, ts)) = dns.get(&dns_key) {
                if now.duration_since(*ts) < ttl {
                    Some(addrs.clone())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let pinned_addrs = match cached_addrs {
            Some(a) => a,
            None => {
                let resolved = resolve_validated_addrs(url, &self.inner.dns_jobs, allow_private).await?;
                if let Ok(mut dns) = self.inner.dns_cache.lock() {
                    if dns.len() >= 256 {
                        dns.retain(|_, (_, ts)| now.duration_since(*ts) < ttl);
                        if dns.len() >= 256 {
                            dns.clear();
                        }
                    }
                    dns.insert(dns_key, (resolved.clone(), now));
                }
                resolved
            }
        };

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(if long_timeout { 60 } else { 20 }))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_nodelay(true)
            .redirect(Policy::none())
            .no_proxy();
        if host.parse::<IpAddr>().is_err() {
            builder = builder.resolve_to_addrs(&host, &pinned_addrs);
        }
        let client = builder
            .build()
            .map_err(|e| format!("HTTP client error: {e}"))?;
        if let Ok(mut clients) = self.inner.http_clients.lock() {
            clients.insert(client_key, (client.clone(), now));
        }
        Ok(client)
    }

    fn bot_handle(&self, bot_id: &str) -> Result<Arc<Mutex<BotComputer>>, String> {
        validate_bot_id(bot_id)?;
        let mut map = self
            .inner
            .computers
            .lock()
            .map_err(|_| "computer state unavailable".to_owned())?;
        if let Some(existing) = map.get(bot_id) {
            return Ok(existing.clone());
        }
        if map.len() >= 256 {
            let idle_key = map
                .iter()
                .find(|(_, v)| Arc::strong_count(v) == 1)
                .map(|(k, _)| k.clone());
            if let Some(k) = idle_key {
                map.remove(&k);
            } else {
                return Err("too many active virtual computers".to_owned());
            }
        }
        let created = Arc::new(Mutex::new(BotComputer::new(bot_id.to_owned())));
        map.insert(bot_id.to_owned(), created.clone());
        Ok(created)
    }

    pub(crate) fn proxy_url_for(&self, bot_id: &str, raw_url: &str) -> Option<String> {
        let parsed = validate_fetch_url_with_policy(raw_url.trim(), true).ok()?;
        let handle = self.bot_handle(bot_id).ok()?;
        let mut guard = handle.lock().ok()?;
        guard.allow_all_web_pages = true;
        build_proxy_url(bot_id, &guard.proxy_token, parsed.as_str())
    }

    fn workspace_for_verified_bot(&self, bot_id: &str) -> Result<WorkspaceEngine, String> {
        validate_bot_id(bot_id)?;
        let bot_dir = self.inner.workspace_root.join(bot_id);
        WorkspaceEngine::open_or_create(&self.inner.workspace_root, &bot_dir)
    }

    async fn verify_bot_exists(&self, bot_id: &str) -> Result<bool, String> {
        validate_bot_id(bot_id)?;
        let permit = self
            .inner
            .auth
            .db_jobs
            .clone()
            .try_acquire_owned()
            .map_err(|_| "database busy".to_owned())?;
        let db = self.inner.auth.db.clone();
        let id = bot_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            db.try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM port_bots WHERE id=?1)",
                    params![id],
                    |r| r.get::<_, bool>(0),
                )?)
            })
        })
        .await
        .map_err(|_| "database task failed".to_owned())?
        .map_err(|_| "database query failed".to_owned())
    }

    async fn verify_bot_owner(
        &self,
        organization_id: &str,
        owner_id: &str,
        bot_id: &str,
    ) -> Result<bool, StatusCode> {
        if validate_bot_id(bot_id).is_err() {
            return Ok(false);
        }
        if bot_id == "ps5-virtual" {
            return Ok(true);
        }
        let permit = self
            .inner
            .auth
            .db_jobs
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let db = self.inner.auth.db.clone();
        let org = organization_id.to_owned();
        let owner = owner_id.to_owned();
        let bot = bot_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            db.try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3)",
                    params![bot, org, owner],
                    |r| r.get::<_, bool>(0),
                )?)
            })
        })
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }

    /// Built-in virtual tool dispatcher (PS5-safe, zero fork/exec).
    pub async fn execute_tool(
        &self,
        bot_id: &str,
        tool_name: &str,
        args_json: Value,
    ) -> Result<Value, String> {
        if !self.verify_bot_exists(bot_id).await? {
            return Err("bot not found".to_owned());
        }
        self.execute_tool_verified(bot_id, tool_name, args_json, false, false)
            .await
    }

    pub fn stage_uploaded_file(
        &self,
        _organization_id: &str,
        _owner_id: &str,
        bot_id: &str,
        safe_name: &str,
        bytes: &[u8],
    ) {
        if bytes.len() > MAX_FILE_SIZE {
            return;
        }
        if let Ok(engine) = self.workspace_for_verified_bot(bot_id) {
            let uploads_dir = engine.root().join("uploads");
            let _ = fs::create_dir_all(&uploads_dir);
            let _ = fs::write(uploads_dir.join(safe_name), bytes);
        }
    }

    /// Owner-scoped virtual tool dispatcher verifying org + owner in `port_bots`.
    pub async fn execute_tool_for_owner(
        &self,
        organization_id: &str,
        owner_id: &str,
        bot_id: &str,
        tool_name: &str,
        args_json: Value,
    ) -> Result<Value, String> {
        self.execute_tool_for_owner_with_policy(
            organization_id,
            owner_id,
            bot_id,
            tool_name,
            args_json,
            false,
        )
        .await
    }

    /// Owner-scoped virtual tool dispatcher with explicit web policy override (e.g. Turbo mode).
    pub async fn execute_tool_for_owner_with_policy(
        &self,
        organization_id: &str,
        owner_id: &str,
        bot_id: &str,
        tool_name: &str,
        args_json: Value,
        allow_all_web_pages: bool,
    ) -> Result<Value, String> {
        self.execute_tool_for_owner_with_control(
            organization_id,
            owner_id,
            bot_id,
            tool_name,
            args_json,
            false,
            allow_all_web_pages,
        )
        .await
    }

    async fn execute_tool_for_owner_with_control(
        &self,
        organization_id: &str,
        owner_id: &str,
        bot_id: &str,
        tool_name: &str,
        args_json: Value,
        allow_human_control: bool,
        allow_all_web_pages: bool,
    ) -> Result<Value, String> {
        let ok = self
            .verify_bot_owner(organization_id, owner_id, bot_id)
            .await
            .map_err(|_| "bot authorization check failed".to_owned())?;
        if !ok {
            return Err("bot not found".to_owned());
        }
        self.execute_tool_verified(
            bot_id,
            tool_name,
            args_json,
            allow_human_control,
            allow_all_web_pages,
        )
        .await
    }

    async fn execute_tool_verified(
        &self,
        bot_id: &str,
        tool_name: &str,
        args_json: Value,
        allow_human_control: bool,
        allow_all_web_pages: bool,
    ) -> Result<Value, String> {
        let handle = self.bot_handle(bot_id)?;
        let cwd = {
            let guard = handle
                .lock()
                .map_err(|_| "computer state unavailable".to_owned())?;
            if guard.holder == ControlHolder::Human && !allow_human_control {
                return Err("a person is currently driving this computer".to_owned());
            }
            guard.cwd.clone()
        };

        if tool_name == "computer_web_fetch" || tool_name == "computer_navigate" {
            let url = args_json
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing string argument 'url'".to_owned())?
                .to_owned();
            let fetched = web_fetch_or_bridge_with_policy(
                &url,
                bot_id,
                self.inner.dns_jobs.clone(),
                allow_all_web_pages,
            )
            .await?;
            let mut guard = handle
                .lock()
                .map_err(|_| "computer state unavailable".to_owned())?;
            guard.current_url = fetched.url.clone();
            guard.page_title = fetched.title.clone();
            guard.page_text = fetched.text.clone();
            guard.page_html = fetched.html.clone();
            guard.bridge_png = fetched.bridge_png.clone();
            guard.allow_all_web_pages = allow_all_web_pages || allow_all_web_pages_from_env();
            guard.screen_revision = guard.screen_revision.saturating_add(1);
            guard.push_terminal_line(&format!("web_fetch {} -> {}", fetched.status, fetched.url));
            guard.screen_notify.notify_waiters();
            return Ok(bounded_web_fetch_tool_output(&fetched));
        }

        let engine = self.workspace_for_verified_bot(bot_id)?;
        let tool = tool_name.to_owned();
        let (result, new_cwd, term_note) = tokio::task::spawn_blocking(move || {
            let mut virtual_cwd = cwd;
            let res = engine.dispatch_tool(&tool, &args_json, &mut virtual_cwd)?;
            let note = match tool.as_str() {
                "computer_run_command" => {
                    let cmd = args_json
                        .get("command")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let out = res.get("stdout").and_then(Value::as_str).unwrap_or("");
                    let err = res.get("stderr").and_then(Value::as_str).unwrap_or("");
                    Some(format!("$ {cmd}\n{out}{err}"))
                }
                "computer_write_file" => {
                    let p = args_json.get("path").and_then(Value::as_str).unwrap_or("");
                    Some(format!("wrote {p}"))
                }
                _ => None,
            };
            Ok::<_, String>((res, virtual_cwd, note))
        })
        .await
        .map_err(|_| "workspace task failed".to_owned())??;

        let mut guard = handle
            .lock()
            .map_err(|_| "computer state unavailable".to_owned())?;
        guard.cwd = new_cwd;
        if let Some(note) = term_note {
            guard.push_terminal_line(&note);
        }
        Ok(result)
    }
}

fn validate_bot_id(bot_id: &str) -> Result<(), String> {
    if bot_id.is_empty()
        || bot_id.len() > 128
        || !bot_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid bot identifier".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WorkspaceEngine (Strict Path Jail & File Tools)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct WorkspaceEngine {
    canon_root: PathBuf,
}

impl WorkspaceEngine {
    pub fn open_or_create(base_root: &StdPath, bot_dir: &StdPath) -> Result<Self, String> {
        reject_symlink_ancestors(base_root)?;
        fs::create_dir_all(bot_dir).map_err(|e| format!("failed to prepare workspace: {e}"))?;
        let meta = fs::symlink_metadata(bot_dir)
            .map_err(|e| format!("failed to inspect workspace: {e}"))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err("workspace root must be a real directory, not a symlink".to_owned());
        }
        let canon_base = fs::canonicalize(base_root)
            .map_err(|e| format!("failed to canonicalize base root: {e}"))?;
        let canon_root = fs::canonicalize(bot_dir)
            .map_err(|e| format!("failed to canonicalize bot workspace: {e}"))?;
        if !canon_root.starts_with(&canon_base) {
            return Err("workspace escaped base directory".to_owned());
        }
        Ok(Self { canon_root })
    }

    pub fn root(&self) -> &StdPath {
        &self.canon_root
    }

    /// Strict path jail: rejects NUL, `\`, `:`, absolute paths, `..`, `.`, and symlinks.
    pub fn resolve_jailed_path(&self, rel: &str, allow_empty: bool) -> Result<PathBuf, String> {
        if rel.is_empty() {
            return if allow_empty {
                Ok(self.canon_root.clone())
            } else {
                Err("path must not be empty".to_owned())
            };
        }
        if rel.contains('\0') || rel.contains('\\') || rel.contains(':') {
            return Err("path contains forbidden characters".to_owned());
        }
        if rel.starts_with('/') {
            return Err("absolute paths are forbidden".to_owned());
        }
        let mut parts = Vec::new();
        for seg in rel.split('/') {
            if seg.is_empty() || seg == "." || seg == ".." {
                return Err("path contains forbidden segment (empty, '.', or '..')".to_owned());
            }
            parts.push(seg);
        }
        let rel_path = StdPath::new(rel);
        if rel_path.is_absolute()
            || rel_path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("path must contain only normal relative components".to_owned());
        }

        let mut cur = self.canon_root.clone();
        for seg in parts {
            cur.push(seg);
            match fs::symlink_metadata(&cur) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err("symlinks are forbidden in workspace".to_owned());
                    }
                    let canon = fs::canonicalize(&cur)
                        .map_err(|e| format!("canonicalize failed: {e}"))?;
                    if !canon.starts_with(&self.canon_root) {
                        return Err("path escaped workspace jail".to_owned());
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(format!("path inspection failed: {e}")),
            }
        }
        Ok(cur)
    }

    fn workspace_usage(&self) -> Result<(usize, u64), String> {
        let mut files = 0usize;
        let mut bytes = 0u64;
        let mut stack = vec![self.canon_root.clone()];
        while let Some(dir) = stack.pop() {
            let rd = fs::read_dir(&dir).map_err(|e| format!("read_dir failed: {e}"))?;
            for entry in rd {
                let entry = entry.map_err(|e| format!("dir entry error: {e}"))?;
                let path = entry.path();
                let meta = fs::symlink_metadata(&path)
                    .map_err(|e| format!("metadata error: {e}"))?;
                if meta.file_type().is_symlink() {
                    return Err("symlink encountered inside workspace".to_owned());
                }
                if meta.is_dir() {
                    stack.push(path);
                } else if meta.is_file() {
                    files = files.saturating_add(1);
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
        Ok((files, bytes))
    }

    pub fn read_file(&self, rel: &str) -> Result<Value, String> {
        let target = self.resolve_jailed_path(rel, false)?;
        let meta = fs::symlink_metadata(&target).map_err(|_| "file not found".to_owned())?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("target is not a regular file".to_owned());
        }
        let canon = fs::canonicalize(&target).map_err(|_| "file not found".to_owned())?;
        if !canon.starts_with(&self.canon_root) {
            return Err("path escaped workspace jail".to_owned());
        }
        let file = fs::File::open(&canon).map_err(|e| format!("open failed: {e}"))?;
        let mut buf = Vec::new();
        file.take((MAX_FILE_SIZE + 1) as u64)
            .read_to_end(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if buf.len() > MAX_FILE_SIZE {
            return Err("file exceeds 512 KiB size limit".to_owned());
        }
        let bytes = buf.len();
        let text = String::from_utf8(buf).map_err(|_| "file is not valid UTF-8".to_owned())?;
        Ok(json!({
            "path": rel,
            "text": text,
            "truncated": false,
            "bytes": bytes,
        }))
    }

    pub fn write_file(&self, rel: &str, contents: &str, append: bool) -> Result<Value, String> {
        let target = self.resolve_jailed_path(rel, false)?;
        let (file_count, total_bytes) = self.workspace_usage()?;

        let existing_len = match fs::symlink_metadata(&target) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || meta.is_dir() {
                    return Err("target cannot be a symlink or directory".to_owned());
                }
                Some(meta.len())
            }
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(format!("stat failed: {e}")),
        };

        let new_file_bytes = if append {
            existing_len.unwrap_or(0).saturating_add(contents.len() as u64)
        } else {
            contents.len() as u64
        };
        if new_file_bytes > MAX_FILE_SIZE as u64 {
            return Err("file would exceed 512 KiB limit".to_owned());
        }
        if existing_len.is_none() && file_count >= MAX_FILE_COUNT {
            return Err("workspace file count limit (512) reached".to_owned());
        }
        let projected_total = total_bytes
            .saturating_sub(existing_len.unwrap_or(0))
            .saturating_add(new_file_bytes);
        if projected_total > MAX_WORKSPACE_BYTES {
            return Err("workspace 32 MiB quota exceeded".to_owned());
        }

        if let Some(parent) = target.parent() {
            self.create_jailed_dirs(parent)?;
        }
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true);
        if append {
            opts.append(true);
        } else {
            opts.truncate(true);
        }
        let mut file = opts.open(&target).map_err(|e| format!("write open failed: {e}"))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("write failed: {e}"))?;
        let canon = fs::canonicalize(&target).map_err(|e| format!("verify failed: {e}"))?;
        if !canon.starts_with(&self.canon_root) {
            return Err("written path escaped workspace".to_owned());
        }
        Ok(json!({
            "path": rel,
            "bytes": contents.len(),
            "appended": append,
        }))
    }

    fn create_jailed_dirs(&self, dir: &StdPath) -> Result<(), String> {
        let rel = dir
            .strip_prefix(&self.canon_root)
            .map_err(|_| "directory outside jail".to_owned())?;
        let mut cur = self.canon_root.clone();
        for comp in rel.components() {
            let Component::Normal(seg) = comp else {
                return Err("invalid directory component".to_owned());
            };
            cur.push(seg);
            match fs::symlink_metadata(&cur) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || !meta.is_dir() {
                        return Err("parent path component is not a directory".to_owned());
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    fs::create_dir(&cur).map_err(|e| format!("mkdir failed: {e}"))?;
                }
                Err(e) => return Err(format!("stat failed: {e}")),
            }
            let canon = fs::canonicalize(&cur).map_err(|e| format!("canonicalize failed: {e}"))?;
            if !canon.starts_with(&self.canon_root) {
                return Err("directory escaped workspace jail".to_owned());
            }
        }
        Ok(())
    }

    pub fn list_files(&self, rel: &str) -> Result<Value, String> {
        let dir = self.resolve_jailed_path(rel, true)?;
        let meta = fs::symlink_metadata(&dir).map_err(|_| "directory not found".to_owned())?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err("target is not a directory".to_owned());
        }
        let mut entries = Vec::new();
        let mut names = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| format!("read_dir failed: {e}"))? {
            let entry = entry.map_err(|e| format!("entry error: {e}"))?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)
                .map_err(|e| format!("metadata error: {e}"))?;
            if meta.file_type().is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let entry_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            names.push((name, entry_rel, meta));
        }
        names.sort_by(|a, b| a.0.cmp(&b.0));
        let truncated = names.len() > MAX_FILE_COUNT;
        for (_, entry_rel, meta) in names.into_iter().take(MAX_FILE_COUNT) {
            if meta.is_dir() {
                entries.push(json!({ "path": entry_rel, "kind": "folder" }));
            } else if meta.is_file() {
                entries.push(json!({ "path": entry_rel, "kind": "file", "bytes": meta.len() }));
            }
        }
        Ok(json!({
            "path": rel,
            "entries": entries,
            "truncated": truncated,
        }))
    }

    pub fn grep_search(&self, query: &str, rel: &str, case_sensitive: bool) -> Result<Value, String> {
        if query.is_empty() || query.len() > 1024 || query.contains('\0') {
            return Err("invalid grep query".to_owned());
        }
        let start = self.resolve_jailed_path(rel, true)?;
        let meta = fs::symlink_metadata(&start).map_err(|_| "search path not found".to_owned())?;
        if meta.file_type().is_symlink() {
            return Err("symlinks are forbidden".to_owned());
        }

        let needle = if case_sensitive {
            query.to_owned()
        } else {
            query.to_lowercase()
        };
        let mut matches = Vec::new();
        let mut truncated = false;
        let mut stack = vec![start];
        let mut scanned = 0usize;

        while let Some(path) = stack.pop() {
            if matches.len() >= 100 || scanned >= MAX_FILE_COUNT {
                truncated = true;
                break;
            }
            let m = fs::symlink_metadata(&path).map_err(|e| format!("stat failed: {e}"))?;
            if m.file_type().is_symlink() {
                continue;
            }
            if m.is_dir() {
                let mut children: Vec<PathBuf> = fs::read_dir(&path)
                    .map_err(|e| format!("read_dir failed: {e}"))?
                    .filter_map(|e| e.ok().map(|x| x.path()))
                    .collect();
                children.sort();
                children.reverse();
                stack.extend(children);
            } else if m.is_file() {
                scanned += 1;
                if m.len() > MAX_FILE_SIZE as u64 {
                    continue;
                }
                let Ok(bytes) = fs::read(&path) else { continue };
                let Ok(text) = String::from_utf8(bytes) else { continue };
                let rel_file = path
                    .strip_prefix(&self.canon_root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                for (idx, line) in text.lines().enumerate() {
                    let hit = if case_sensitive {
                        line.contains(&needle)
                    } else {
                        line.to_lowercase().contains(&needle)
                    };
                    if hit {
                        let clipped: String = line.chars().take(300).collect();
                        matches.push(json!({
                            "path": rel_file,
                            "line": idx + 1,
                            "text": clipped,
                        }));
                        if matches.len() >= 100 {
                            truncated = true;
                            break;
                        }
                    }
                }
            }
        }
        Ok(json!({
            "query": query,
            "matches": matches,
            "truncated": truncated,
        }))
    }

    pub fn dispatch_tool(
        &self,
        tool_name: &str,
        args: &Value,
        cwd: &mut String,
    ) -> Result<Value, String> {
        match tool_name {
            "computer_read_file" => {
                let path = args
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing string argument 'path'".to_owned())?;
                self.read_file(path)
            }
            "computer_write_file" => {
                let path = args
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing string argument 'path'".to_owned())?;
                let contents = args
                    .get("contents")
                    .or_else(|| args.get("content"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing string argument 'contents'".to_owned())?;
                let append = args.get("append").and_then(Value::as_bool).unwrap_or(false);
                self.write_file(path, contents, append)
            }
            "computer_list_files" => {
                let path = args.get("path").and_then(Value::as_str).unwrap_or("");
                self.list_files(path)
            }
            "computer_grep_search" => {
                let query = args
                    .get("query")
                    .or_else(|| args.get("pattern"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing string argument 'query'".to_owned())?;
                let path = args.get("path").and_then(Value::as_str).unwrap_or("");
                let case_sensitive = args
                    .get("caseSensitive")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                self.grep_search(query, path, case_sensitive)
            }
            "computer_run_command" => {
                let command = args
                    .get("command")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "missing string argument 'command'".to_owned())?;
                Ok(VirtualShell::run(self, cwd, command))
            }
            _ => Err(format!("unknown tool '{tool_name}'")),
        }
    }
}

fn reject_symlink_ancestors(path: &StdPath) -> Result<(), String> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        match fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err("symlink in workspace root path is forbidden".to_owned());
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => break,
            Err(e) => return Err(format!("failed to inspect workspace ancestor: {e}")),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// In-Process Virtual POSIX Shell (Zero fork/exec)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChainOp {
    Seq, // ;
    And, // &&
    Or,  // ||
}

#[derive(Clone)]
enum Token {
    Word(String),
    Pipe,
    Semi,
    AndIf,
    OrIf,
    RedirTrunc,
    RedirAppend,
}

struct SimpleCmd {
    args: Vec<String>,
    redir: Option<(String, bool)>,
}

struct Pipeline {
    stages: Vec<SimpleCmd>,
}

struct VirtualShell;

impl VirtualShell {
    pub fn run(engine: &WorkspaceEngine, cwd: &mut String, input: &str) -> Value {
        let start = Instant::now();
        if input.trim().is_empty() {
            return json!({
                "command": input,
                "exitCode": 0,
                "stdout": "",
                "stderr": "",
                "truncated": false,
                "timedOut": false,
                "elapsedMs": 0,
            });
        }
        let tokens = match tokenize_shell(input) {
            Ok(t) => t,
            Err(e) => {
                return json!({
                    "command": input,
                    "exitCode": 2,
                    "stdout": "",
                    "stderr": format!("shell: {e}\n"),
                    "truncated": false,
                    "timedOut": false,
                    "elapsedMs": start.elapsed().as_millis() as u64,
                });
            }
        };
        let chains = match parse_chains(&tokens) {
            Ok(c) => c,
            Err(e) => {
                return json!({
                    "command": input,
                    "exitCode": 2,
                    "stdout": "",
                    "stderr": format!("shell: {e}\n"),
                    "truncated": false,
                    "timedOut": false,
                    "elapsedMs": start.elapsed().as_millis() as u64,
                });
            }
        };
        if chains.len() > MAX_SHELL_STATEMENTS {
            return json!({
                "command": input,
                "exitCode": 2,
                "stdout": "",
                "stderr": "shell: too many chained statements\n",
                "truncated": false,
                "timedOut": false,
                "elapsedMs": start.elapsed().as_millis() as u64,
            });
        }

        let mut total_stdout = String::new();
        let mut total_stderr = String::new();
        let mut last_code = 0i32;

        for (op, pipeline) in chains {
            let should_run = match op {
                None | Some(ChainOp::Seq) => true,
                Some(ChainOp::And) => last_code == 0,
                Some(ChainOp::Or) => last_code != 0,
            };
            if !should_run {
                continue;
            }
            let (code, out, err) = exec_pipeline(engine, cwd, &pipeline);
            last_code = code;
            append_capped(&mut total_stdout, &out, MAX_SHELL_OUTPUT);
            append_capped(&mut total_stderr, &err, MAX_SHELL_OUTPUT);
        }

        let truncated = total_stdout.len() >= MAX_SHELL_OUTPUT || total_stderr.len() >= MAX_SHELL_OUTPUT;
        json!({
            "command": input,
            "exitCode": last_code,
            "stdout": total_stdout,
            "stderr": total_stderr,
            "truncated": truncated,
            "timedOut": false,
            "elapsedMs": start.elapsed().as_millis() as u64,
        })
    }
}

fn append_capped(dst: &mut String, src: &str, cap: usize) {
    if dst.len() >= cap {
        return;
    }
    let avail = cap - dst.len();
    if src.len() <= avail {
        dst.push_str(src);
    } else {
        let mut cut = avail;
        while cut > 0 && !src.is_char_boundary(cut) {
            cut -= 1;
        }
        dst.push_str(&src[..cut]);
    }
}

fn tokenize_shell(input: &str) -> Result<Vec<Token>, String> {
    if input.contains('\0') {
        return Err("NUL byte in command".to_owned());
    }
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        while i < chars.len() && chars[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        match chars[i] {
            ';' => {
                tokens.push(Token::Semi);
                i += 1;
            }
            '|' => {
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    tokens.push(Token::OrIf);
                    i += 2;
                } else {
                    tokens.push(Token::Pipe);
                    i += 1;
                }
            }
            '&' => {
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    tokens.push(Token::AndIf);
                    i += 2;
                } else {
                    return Err("background '&' is unsupported".to_owned());
                }
            }
            '>' => {
                if i + 1 < chars.len() && chars[i + 1] == '>' {
                    tokens.push(Token::RedirAppend);
                    i += 2;
                } else {
                    tokens.push(Token::RedirTrunc);
                    i += 1;
                }
            }
            '<' => return Err("input redirection '<' is unsupported".to_owned()),
            _ => {
                let mut word = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_ascii_whitespace() || matches!(c, ';' | '|' | '&' | '>' | '<') {
                        break;
                    }
                    if c == '\'' {
                        i += 1;
                        let mut closed = false;
                        while i < chars.len() {
                            if chars[i] == '\'' {
                                closed = true;
                                i += 1;
                                break;
                            }
                            word.push(chars[i]);
                            i += 1;
                        }
                        if !closed {
                            return Err("unterminated single quote".to_owned());
                        }
                    } else if c == '"' {
                        i += 1;
                        let mut closed = false;
                        while i < chars.len() {
                            if chars[i] == '"' {
                                closed = true;
                                i += 1;
                                break;
                            }
                            if chars[i] == '\\' && i + 1 < chars.len() {
                                i += 1;
                                match chars[i] {
                                    'n' => word.push('\n'),
                                    't' => word.push('\t'),
                                    other => word.push(other),
                                }
                            } else {
                                word.push(chars[i]);
                            }
                            i += 1;
                        }
                        if !closed {
                            return Err("unterminated double quote".to_owned());
                        }
                    } else if c == '\\' {
                        i += 1;
                        if i < chars.len() {
                            word.push(chars[i]);
                            i += 1;
                        }
                    } else {
                        word.push(c);
                        i += 1;
                    }
                }
                tokens.push(Token::Word(word));
            }
        }
    }
    Ok(tokens)
}

fn parse_chains(tokens: &[Token]) -> Result<Vec<(Option<ChainOp>, Pipeline)>, String> {
    let mut chains = Vec::new();
    let mut pending_op: Option<ChainOp> = None;
    let mut cur_stages: Vec<SimpleCmd> = Vec::new();
    let mut cur_args: Vec<String> = Vec::new();
    let mut cur_redir: Option<(String, bool)> = None;

    let flush_stage = |args: &mut Vec<String>,
                       redir: &mut Option<(String, bool)>,
                       stages: &mut Vec<SimpleCmd>|
     -> Result<(), String> {
        if args.is_empty() {
            return Err("empty command in pipeline".to_owned());
        }
        stages.push(SimpleCmd {
            args: std::mem::take(args),
            redir: redir.take(),
        });
        Ok(())
    };

    let mut i = 0usize;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Word(w) => cur_args.push(w.clone()),
            Token::RedirTrunc | Token::RedirAppend => {
                let append = matches!(tokens[i], Token::RedirAppend);
                i += 1;
                let Some(Token::Word(target)) = tokens.get(i) else {
                    return Err("expected filename after redirection".to_owned());
                };
                cur_redir = Some((target.clone(), append));
            }
            Token::Pipe => {
                flush_stage(&mut cur_args, &mut cur_redir, &mut cur_stages)?;
            }
            Token::Semi | Token::AndIf | Token::OrIf => {
                flush_stage(&mut cur_args, &mut cur_redir, &mut cur_stages)?;
                chains.push((
                    pending_op,
                    Pipeline {
                        stages: std::mem::take(&mut cur_stages),
                    },
                ));
                pending_op = Some(match tokens[i] {
                    Token::Semi => ChainOp::Seq,
                    Token::AndIf => ChainOp::And,
                    Token::OrIf => ChainOp::Or,
                    _ => unreachable!(),
                });
            }
        }
        i += 1;
    }

    if !cur_args.is_empty() || !cur_stages.is_empty() {
        flush_stage(&mut cur_args, &mut cur_redir, &mut cur_stages)?;
        chains.push((
            pending_op,
            Pipeline {
                stages: cur_stages,
            },
        ));
    } else if pending_op.is_some() && !matches!(pending_op, Some(ChainOp::Seq)) {
        return Err("dangling operator".to_owned());
    }

    Ok(chains)
}

fn exec_pipeline(engine: &WorkspaceEngine, cwd: &mut String, pipeline: &Pipeline) -> (i32, String, String) {
    let mut stdin_buf = String::new();
    let mut all_stderr = String::new();
    let mut last_code = 0i32;

    for (idx, cmd) in pipeline.stages.iter().enumerate() {
        let is_last = idx + 1 == pipeline.stages.len();
        let (code, out, err) = exec_builtin(engine, cwd, &cmd.args, &stdin_buf);
        last_code = code;
        all_stderr.push_str(&err);

        if let Some((redir_target, append)) = &cmd.redir {
            match resolve_shell_rel(cwd, redir_target)
                .and_then(|rel| engine.write_file(&rel, &out, *append))
            {
                Ok(_) => {
                    stdin_buf.clear();
                }
                Err(e) => {
                    last_code = 1;
                    all_stderr.push_str(&format!("{redir_target}: {e}\n"));
                    stdin_buf.clear();
                }
            }
        } else if is_last {
            return (last_code, out, all_stderr);
        } else {
            stdin_buf = out;
        }
    }
    (last_code, String::new(), all_stderr)
}

fn resolve_shell_rel(cwd: &str, raw: &str) -> Result<String, String> {
    if raw.contains('\0') || raw.contains('\\') || raw.contains(':') {
        return Err("forbidden path character".to_owned());
    }
    let mut parts: Vec<String> = if raw.starts_with('/') {
        let stripped = raw.strip_prefix("/workspace").unwrap_or("");
        if raw != "/workspace" && !raw.starts_with("/workspace/") {
            return Err("path outside /workspace".to_owned());
        }
        stripped
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    } else if cwd.is_empty() {
        Vec::new()
    } else {
        cwd.split('/').map(str::to_owned).collect()
    };

    if !raw.starts_with('/') {
        for seg in raw.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    if parts.pop().is_none() {
                        return Err("cannot escape /workspace".to_owned());
                    }
                }
                other => parts.push(other.to_owned()),
            }
        }
    }
    Ok(parts.join("/"))
}

fn exec_builtin(
    engine: &WorkspaceEngine,
    cwd: &mut String,
    args: &[String],
    stdin: &str,
) -> (i32, String, String) {
    let cmd = args[0].as_str();
    let rest = &args[1..];
    match cmd {
        "pwd" => {
            let p = if cwd.is_empty() {
                "/workspace".to_owned()
            } else {
                format!("/workspace/{cwd}")
            };
            (0, format!("{p}\n"), String::new())
        }
        "cd" => {
            let target = rest.first().map(String::as_str).unwrap_or("");
            if target.is_empty() {
                cwd.clear();
                return (0, String::new(), String::new());
            }
            match resolve_shell_rel(cwd, target).and_then(|rel| {
                let p = engine.resolve_jailed_path(&rel, true)?;
                let m = fs::symlink_metadata(&p).map_err(|_| "no such directory".to_owned())?;
                if m.file_type().is_symlink() || !m.is_dir() {
                    return Err("not a directory".to_owned());
                }
                Ok(rel)
            }) {
                Ok(rel) => {
                    *cwd = rel;
                    (0, String::new(), String::new())
                }
                Err(e) => (1, String::new(), format!("cd: {target}: {e}\n")),
            }
        }
        "echo" => {
            let (no_nl, items) = if rest.first().map(String::as_str) == Some("-n") {
                (true, &rest[1..])
            } else {
                (false, rest)
            };
            let mut out = items.join(" ");
            if !no_nl {
                out.push('\n');
            }
            (0, out, String::new())
        }
        "uname" => {
            if rest.iter().any(|a| a == "-a") {
                (0, "OpenBot-PS5 FreeBSD 11.0 amd64\n".to_owned(), String::new())
            } else {
                (0, "OpenBot-PS5\n".to_owned(), String::new())
            }
        }
        "date" => (0, format!("{}\n", now_iso()), String::new()),
        "ls" => cmd_ls(engine, cwd, rest),
        "cat" => cmd_cat(engine, cwd, rest, stdin),
        "head" => cmd_head_tail(engine, cwd, rest, stdin, true),
        "tail" => cmd_head_tail(engine, cwd, rest, stdin, false),
        "wc" => cmd_wc(engine, cwd, rest, stdin),
        "grep" => cmd_grep(engine, cwd, rest, stdin),
        "mkdir" => cmd_mkdir(engine, cwd, rest),
        "touch" => cmd_touch(engine, cwd, rest),
        "rm" => cmd_rm(engine, cwd, rest),
        "cp" => cmd_cp(engine, cwd, rest),
        "mv" => cmd_mv(engine, cwd, rest),
        "find" => cmd_find(engine, cwd, rest),
        "help" => (
            0,
            "Built-ins: pwd cd ls cat head tail wc grep mkdir rm cp mv echo touch find uname date\n"
                .to_owned(),
            String::new(),
        ),
        _ => (
            127,
            String::new(),
            format!("{cmd}: command not supported in virtual shell\n"),
        ),
    }
}

fn read_shell_input(
    engine: &WorkspaceEngine,
    cwd: &str,
    files: &[String],
    stdin: &str,
) -> Result<String, String> {
    if files.is_empty() {
        return Ok(stdin.to_owned());
    }
    let mut combined = String::new();
    for f in files {
        let rel = resolve_shell_rel(cwd, f)?;
        let val = engine.read_file(&rel)?;
        if let Some(t) = val.get("text").and_then(Value::as_str) {
            combined.push_str(t);
        }
    }
    Ok(combined)
}

fn cmd_ls(engine: &WorkspaceEngine, cwd: &str, rest: &[String]) -> (i32, String, String) {
    let mut long = false;
    let mut all = false;
    let mut targets = Vec::new();
    for arg in rest {
        if arg.starts_with('-') && arg.len() > 1 {
            for ch in arg[1..].chars() {
                match ch {
                    'l' => long = true,
                    'a' => all = true,
                    _ => return (2, String::new(), format!("ls: unsupported option -{ch}\n")),
                }
            }
        } else {
            targets.push(arg.as_str());
        }
    }
    if targets.is_empty() {
        targets.push(".");
    }
    let mut out = String::new();
    let mut err = String::new();
    let mut code = 0;

    for target in targets {
        let rel = match resolve_shell_rel(cwd, target) {
            Ok(r) => r,
            Err(e) => {
                code = 1;
                err.push_str(&format!("ls: {target}: {e}\n"));
                continue;
            }
        };
        let path = match engine.resolve_jailed_path(&rel, true) {
            Ok(p) => p,
            Err(e) => {
                code = 1;
                err.push_str(&format!("ls: {target}: {e}\n"));
                continue;
            }
        };
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) if !m.file_type().is_symlink() => m,
            _ => {
                code = 1;
                err.push_str(&format!("ls: {target}: No such file or directory\n"));
                continue;
            }
        };
        if meta.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(target);
            if long {
                out.push_str(&format!("-rw-r--r-- {:>8} {name}\n", meta.len()));
            } else {
                out.push_str(&format!("{name}\n"));
            }
            continue;
        }
        let Ok(rd) = fs::read_dir(&path) else {
            code = 1;
            err.push_str(&format!("ls: {target}: cannot read directory\n"));
            continue;
        };
        let mut items = Vec::new();
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !all && name.starts_with('.') {
                continue;
            }
            if let Ok(m) = fs::symlink_metadata(entry.path()) {
                if !m.file_type().is_symlink() {
                    items.push((name, m));
                }
            }
        }
        items.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, m) in items {
            if long {
                let kind = if m.is_dir() { 'd' } else { '-' };
                let perm = if m.is_dir() { "rwxr-xr-x" } else { "rw-r--r--" };
                out.push_str(&format!("{kind}{perm} {:>8} {name}\n", m.len()));
            } else {
                out.push_str(&format!("{name}\n"));
            }
        }
    }
    (code, out, err)
}

fn cmd_cat(
    engine: &WorkspaceEngine,
    cwd: &str,
    rest: &[String],
    stdin: &str,
) -> (i32, String, String) {
    match read_shell_input(engine, cwd, rest, stdin) {
        Ok(text) => (0, text, String::new()),
        Err(e) => (1, String::new(), format!("cat: {e}\n")),
    }
}

fn cmd_head_tail(
    engine: &WorkspaceEngine,
    cwd: &str,
    rest: &[String],
    stdin: &str,
    is_head: bool,
) -> (i32, String, String) {
    let mut n = 10usize;
    let mut files = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "-n" {
            i += 1;
            let Some(val) = rest.get(i).and_then(|s| s.parse::<usize>().ok()) else {
                return (2, String::new(), "invalid -n count\n".to_owned());
            };
            n = val.min(10_000);
        } else if let Some(v) = rest[i].strip_prefix("-n") {
            let Ok(val) = v.parse::<usize>() else {
                return (2, String::new(), "invalid -n count\n".to_owned());
            };
            n = val.min(10_000);
        } else {
            files.push(rest[i].clone());
        }
        i += 1;
    }
    let text = match read_shell_input(engine, cwd, &files, stdin) {
        Ok(t) => t,
        Err(e) => return (1, String::new(), format!("{e}\n")),
    };
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let slice = if is_head {
        &lines[..n.min(lines.len())]
    } else {
        let start = lines.len().saturating_sub(n);
        &lines[start..]
    };
    (0, slice.concat(), String::new())
}

fn cmd_wc(
    engine: &WorkspaceEngine,
    cwd: &str,
    rest: &[String],
    stdin: &str,
) -> (i32, String, String) {
    let mut show_l = false;
    let mut show_w = false;
    let mut show_c = false;
    let mut files = Vec::new();
    for arg in rest {
        if arg.starts_with('-') && arg.len() > 1 {
            for ch in arg[1..].chars() {
                match ch {
                    'l' => show_l = true,
                    'w' => show_w = true,
                    'c' => show_c = true,
                    _ => return (2, String::new(), format!("wc: unsupported flag -{ch}\n")),
                }
            }
        } else {
            files.push(arg.clone());
        }
    }
    if !show_l && !show_w && !show_c {
        show_l = true;
        show_w = true;
        show_c = true;
    }
    let text = match read_shell_input(engine, cwd, &files, stdin) {
        Ok(t) => t,
        Err(e) => return (1, String::new(), format!("wc: {e}\n")),
    };
    let lines = text.bytes().filter(|b| *b == b'\n').count();
    let words = text.split_whitespace().count();
    let bytes = text.len();
    let mut parts = Vec::new();
    if show_l {
        parts.push(lines.to_string());
    }
    if show_w {
        parts.push(words.to_string());
    }
    if show_c {
        parts.push(bytes.to_string());
    }
    (0, format!("{}\n", parts.join(" ")), String::new())
}

fn cmd_grep(
    engine: &WorkspaceEngine,
    cwd: &str,
    rest: &[String],
    stdin: &str,
) -> (i32, String, String) {
    let mut ignore_case = false;
    let mut line_num = false;
    let mut invert = false;
    let mut pos = Vec::new();
    for arg in rest {
        if arg.starts_with('-') && arg.len() > 1 {
            for ch in arg[1..].chars() {
                match ch {
                    'i' => ignore_case = true,
                    'n' => line_num = true,
                    'v' => invert = true,
                    _ => return (2, String::new(), format!("grep: unsupported flag -{ch}\n")),
                }
            }
        } else {
            pos.push(arg.clone());
        }
    }
    let Some(pattern) = pos.first() else {
        return (2, String::new(), "grep: missing pattern\n".to_owned());
    };
    let files = &pos[1..];
    let text = match read_shell_input(engine, cwd, files, stdin) {
        Ok(t) => t,
        Err(e) => return (2, String::new(), format!("grep: {e}\n")),
    };
    let needle = if ignore_case {
        pattern.to_lowercase()
    } else {
        pattern.clone()
    };
    let mut out = String::new();
    let mut matched = false;
    for (idx, line) in text.lines().enumerate() {
        let contains = if ignore_case {
            line.to_lowercase().contains(&needle)
        } else {
            line.contains(&needle)
        };
        if contains ^ invert {
            matched = true;
            if line_num {
                out.push_str(&format!("{}:{line}\n", idx + 1));
            } else {
                out.push_str(&format!("{line}\n"));
            }
        }
    }
    (if matched { 0 } else { 1 }, out, String::new())
}

fn cmd_mkdir(engine: &WorkspaceEngine, cwd: &str, rest: &[String]) -> (i32, String, String) {
    let mut parents = false;
    let mut dirs = Vec::new();
    for arg in rest {
        if arg == "-p" {
            parents = true;
        } else {
            dirs.push(arg.as_str());
        }
    }
    if dirs.is_empty() {
        return (1, String::new(), "mkdir: missing operand\n".to_owned());
    }
    for d in dirs {
        let Ok(rel) = resolve_shell_rel(cwd, d) else {
            return (1, String::new(), format!("mkdir: {d}: invalid path\n"));
        };
        if rel.is_empty() {
            if parents {
                continue;
            }
            return (1, String::new(), "mkdir: cannot create root\n".to_owned());
        }
        let Ok(path) = engine.resolve_jailed_path(&rel, false) else {
            return (1, String::new(), format!("mkdir: {d}: forbidden path\n"));
        };
        if parents {
            if let Err(e) = engine.create_jailed_dirs(&path) {
                return (1, String::new(), format!("mkdir: {d}: {e}\n"));
            }
        } else if let Err(e) = fs::create_dir(&path) {
            return (1, String::new(), format!("mkdir: {d}: {e}\n"));
        }
    }
    (0, String::new(), String::new())
}

fn cmd_touch(engine: &WorkspaceEngine, cwd: &str, rest: &[String]) -> (i32, String, String) {
    if rest.is_empty() {
        return (1, String::new(), "touch: missing file operand\n".to_owned());
    }
    for f in rest {
        let Ok(rel) = resolve_shell_rel(cwd, f) else {
            return (1, String::new(), format!("touch: {f}: invalid path\n"));
        };
        let Ok(path) = engine.resolve_jailed_path(&rel, false) else {
            return (1, String::new(), format!("touch: {f}: forbidden path\n"));
        };
        if fs::symlink_metadata(&path).is_err() {
            if let Err(e) = engine.write_file(&rel, "", false) {
                return (1, String::new(), format!("touch: {f}: {e}\n"));
            }
        }
    }
    (0, String::new(), String::new())
}

fn cmd_rm(engine: &WorkspaceEngine, cwd: &str, rest: &[String]) -> (i32, String, String) {
    let mut recursive = false;
    let mut force = false;
    let mut targets = Vec::new();
    for arg in rest {
        if arg.starts_with('-') && arg.len() > 1 {
            for ch in arg[1..].chars() {
                match ch {
                    'r' | 'R' => recursive = true,
                    'f' => force = true,
                    _ => return (2, String::new(), format!("rm: unsupported option -{ch}\n")),
                }
            }
        } else {
            targets.push(arg.as_str());
        }
    }
    if targets.is_empty() && !force {
        return (1, String::new(), "rm: missing operand\n".to_owned());
    }
    for t in targets {
        let Ok(rel) = resolve_shell_rel(cwd, t) else {
            return (1, String::new(), format!("rm: {t}: invalid path\n"));
        };
        if rel.is_empty() {
            return (1, String::new(), "rm: refusing to remove workspace root\n".to_owned());
        }
        let Ok(path) = engine.resolve_jailed_path(&rel, false) else {
            return (1, String::new(), format!("rm: {t}: forbidden path\n"));
        };
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) if force => continue,
            Err(_) => return (1, String::new(), format!("rm: {t}: No such file or directory\n")),
        };
        if meta.file_type().is_symlink() {
            return (1, String::new(), format!("rm: {t}: symlink forbidden\n"));
        }
        let res = if meta.is_dir() {
            if !recursive {
                return (1, String::new(), format!("rm: {t}: is a directory\n"));
            }
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        if let Err(e) = res {
            return (1, String::new(), format!("rm: {t}: {e}\n"));
        }
    }
    (0, String::new(), String::new())
}

fn cmd_cp(engine: &WorkspaceEngine, cwd: &str, rest: &[String]) -> (i32, String, String) {
    let args: Vec<&str> = rest.iter().filter(|a| !a.starts_with('-')).map(String::as_str).collect();
    if args.len() != 2 {
        return (1, String::new(), "cp: expected <src> <dst>\n".to_owned());
    }
    let Ok(src_rel) = resolve_shell_rel(cwd, args[0]) else {
        return (1, String::new(), "cp: invalid source\n".to_owned());
    };
    let Ok(dst_rel) = resolve_shell_rel(cwd, args[1]) else {
        return (1, String::new(), "cp: invalid destination\n".to_owned());
    };
    let val = match engine.read_file(&src_rel) {
        Ok(v) => v,
        Err(e) => return (1, String::new(), format!("cp: {e}\n")),
    };
    let text = val.get("text").and_then(Value::as_str).unwrap_or("");
    match engine.write_file(&dst_rel, text, false) {
        Ok(_) => (0, String::new(), String::new()),
        Err(e) => (1, String::new(), format!("cp: {e}\n")),
    }
}

fn cmd_mv(engine: &WorkspaceEngine, cwd: &str, rest: &[String]) -> (i32, String, String) {
    let args: Vec<&str> = rest.iter().filter(|a| !a.starts_with('-')).map(String::as_str).collect();
    if args.len() != 2 {
        return (1, String::new(), "mv: expected <src> <dst>\n".to_owned());
    }
    let Ok(src_rel) = resolve_shell_rel(cwd, args[0]) else {
        return (1, String::new(), "mv: invalid source\n".to_owned());
    };
    let Ok(dst_rel) = resolve_shell_rel(cwd, args[1]) else {
        return (1, String::new(), "mv: invalid destination\n".to_owned());
    };
    let Ok(src) = engine.resolve_jailed_path(&src_rel, false) else {
        return (1, String::new(), "mv: forbidden source\n".to_owned());
    };
    let Ok(dst) = engine.resolve_jailed_path(&dst_rel, false) else {
        return (1, String::new(), "mv: forbidden destination\n".to_owned());
    };
    if fs::symlink_metadata(&src).map(|m| m.file_type().is_symlink()).unwrap_or(true) {
        return (1, String::new(), "mv: source missing or symlink\n".to_owned());
    }
    if let Some(parent) = dst.parent() {
        if let Err(e) = engine.create_jailed_dirs(parent) {
            return (1, String::new(), format!("mv: {e}\n"));
        }
    }
    match fs::rename(&src, &dst) {
        Ok(_) => (0, String::new(), String::new()),
        Err(e) => (1, String::new(), format!("mv: {e}\n")),
    }
}

fn cmd_find(engine: &WorkspaceEngine, cwd: &str, rest: &[String]) -> (i32, String, String) {
    let mut start_arg = ".";
    let mut name_glob: Option<&str> = None;
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "-name" {
            i += 1;
            let Some(pat) = rest.get(i) else {
                return (2, String::new(), "find: missing -name pattern\n".to_owned());
            };
            name_glob = Some(pat.as_str());
        } else if !rest[i].starts_with('-') {
            start_arg = rest[i].as_str();
        }
        i += 1;
    }
    let Ok(rel) = resolve_shell_rel(cwd, start_arg) else {
        return (1, String::new(), "find: invalid start path\n".to_owned());
    };
    let Ok(root) = engine.resolve_jailed_path(&rel, true) else {
        return (1, String::new(), "find: forbidden path\n".to_owned());
    };
    let mut out = String::new();
    let mut stack = vec![root];
    let mut count = 0usize;
    while let Some(path) = stack.pop() {
        if count >= MAX_FILE_COUNT {
            break;
        }
        let Ok(m) = fs::symlink_metadata(&path) else { continue };
        if m.file_type().is_symlink() {
            continue;
        }
        count += 1;
        let disp = path
            .strip_prefix(engine.root())
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let matches = name_glob.is_none_or(|g| glob_match(g, name));
        if matches {
            if disp.is_empty() {
                out.push_str(".\n");
            } else {
                out.push_str(&format!("{disp}\n"));
            }
        }
        if m.is_dir() {
            if let Ok(rd) = fs::read_dir(&path) {
                let mut children: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|x| x.path())).collect();
                children.sort();
                children.reverse();
                stack.extend(children);
            }
        }
    }
    (0, out, String::new())
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = value.chars().collect();
    let (mut i, mut j, mut star, mut restart) = (0, 0, None, 0);
    while j < s.len() {
        if i < p.len() && (p[i] == '?' || p[i] == s[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star = Some(i);
            i += 1;
            restart = j;
        } else if let Some(k) = star {
            restart += 1;
            j = restart;
            i = k + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

// ---------------------------------------------------------------------------
// SSRF-Hardened Web Fetch + HTML Text Extractor
// ---------------------------------------------------------------------------

pub(crate) struct FetchResult {
    pub(crate) url: String,
    pub(crate) status: u16,
    pub(crate) title: String,
    pub(crate) text: String,
    pub(crate) html: String,
    pub(crate) bridge_png: Option<Vec<u8>>,
    pub(crate) truncated: bool,
}

pub(crate) fn is_forbidden_ipv4(ip: Ipv4Addr, local_ips: &[Ipv4Addr]) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // CGNAT 100.64.0.0/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // TEST-NET-1
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // Benchmarking 198.18.0.0/15
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // TEST-NET-3
        || o[0] >= 240 // Reserved 240.0.0.0/4
        || local_ips.contains(&ip)
}

pub(crate) fn is_forbidden_ip(ip: IpAddr, local_ips: &[Ipv4Addr]) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4, local_ips),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_forbidden_ipv4(mapped, local_ips);
            }
            let seg = v6.segments();
            // IPv4-compatible IPv6 ::w.x.y.z
            if seg[0..6] == [0; 6] {
                let compat = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    seg[6] as u8,
                    (seg[7] >> 8) as u8,
                    seg[7] as u8,
                );
                if v6.is_unspecified() || v6.is_loopback() || is_forbidden_ipv4(compat, local_ips) {
                    return true;
                }
            }
            // 6to4 (2002::/16)
            if seg[0] == 0x2002 {
                let embedded = Ipv4Addr::new(
                    (seg[1] >> 8) as u8,
                    seg[1] as u8,
                    (seg[2] >> 8) as u8,
                    seg[2] as u8,
                );
                if is_forbidden_ipv4(embedded, local_ips) {
                    return true;
                }
            }
            // Teredo (2001::/32), NAT64 (64:ff9b::/96 & 64:ff9b:1::/48), Discard (100::/64), Doc (2001:db8::/32)
            let is_ula = (seg[0] & 0xfe00) == 0xfc00;
            let is_link_local = (seg[0] & 0xffc0) == 0xfe80;
            let is_site_local = (seg[0] & 0xffc0) == 0xfec0;
            let is_teredo = seg[0] == 0x2001 && seg[1] == 0x0000;
            let is_nat64 = (seg[0] == 0x0064 && seg[1] == 0xff9b)
                && (seg[2..6] == [0; 4] || seg[2] == 0x0001);
            let is_discard = seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0;
            let is_doc = seg[0] == 0x2001 && seg[1] == 0x0db8;
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || is_ula
                || is_link_local
                || is_site_local
                || is_teredo
                || is_nat64
                || is_discard
                || is_doc
        }
    }
}

fn has_explicit_scheme_without_slashes(s: &str) -> bool {
    if s.starts_with('[') {
        return false;
    }
    let authority_end = s.find(['/', '?', '#']).unwrap_or(s.len());
    let head = &s[..authority_end];
    if let Some((before, after)) = head.split_once(':') {
        !before.is_empty() && (after.is_empty() || !after.bytes().all(|b| b.is_ascii_digit()))
    } else {
        false
    }
}

const MAX_DOH_RESPONSE_BYTES: usize = 64 * 1024;
const DOH_ENDPOINTS: &[&str] = &[
    "https://1.1.1.1/dns-query",
    "https://dns.google/resolve",
    "https://8.8.8.8/resolve",
];

fn allow_all_web_pages_from_env() -> bool {
    std::env::var("OPENBOT_ALLOW_ALL_WEB_PAGES")
        .map(|v| {
            let trimmed = v.trim();
            trimmed == "1"
                || trimmed.eq_ignore_ascii_case("true")
                || trimmed.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

pub(crate) fn is_local_hostname(host: &str) -> bool {
    let lower = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
}

pub(crate) fn is_unspecified_or_sinkhole_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified())
        }
    }
}

fn validate_fetch_url(raw: &str) -> Result<reqwest::Url, String> {
    validate_fetch_url_with_policy(raw, false)
}

fn validate_fetch_url_with_policy(raw: &str, allow_private: bool) -> Result<reqwest::Url, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") {
        return Err("invalid URL".to_owned());
    }
    let authority_end = trimmed.find(['/', '?', '#']).unwrap_or(trimmed.len());
    let head = &trimmed[..authority_end];
    let candidate = if head.contains("://") || has_explicit_scheme_without_slashes(trimmed) {
        trimmed.to_owned()
    } else {
        let host_part = head.split(':').next().unwrap_or("");
        let is_ipv6_bracket = head.starts_with('[') && head.contains(']');
        let is_localhost = is_local_hostname(host_part);
        if !allow_private && !is_ipv6_bracket && !is_localhost && !host_part.contains('.') {
            return Err("invalid URL".to_owned());
        }
        if allow_private && host_part.is_empty() && !is_ipv6_bracket {
            return Err("invalid URL".to_owned());
        }
        format!("https://{trimmed}")
    };

    let url = reqwest::Url::parse(&candidate).map_err(|_| "invalid URL".to_owned())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("only http and https URLs are allowed".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URLs with embedded credentials are forbidden".to_owned());
    }
    let host = url.host_str().ok_or_else(|| "URL missing host".to_owned())?;
    if !allow_private && is_local_hostname(host) {
        return Err("local hostnames are forbidden".to_owned());
    }
    Ok(url)
}

pub(crate) fn select_allowed_socket_addrs(
    host: &str,
    addrs: Vec<SocketAddr>,
    local_ips: &[Ipv4Addr],
) -> Result<Vec<SocketAddr>, String> {
    select_socket_addrs_with_policy(host, addrs, local_ips, false)
}

pub(crate) fn select_socket_addrs_with_policy(
    host: &str,
    addrs: Vec<SocketAddr>,
    local_ips: &[Ipv4Addr],
    allow_private: bool,
) -> Result<Vec<SocketAddr>, String> {
    if addrs.is_empty() {
        return Err(format!("DNS resolution for host '{host}' returned no addresses"));
    }
    let mut allowed_v4 = Vec::new();
    let mut allowed_v6 = Vec::new();
    let mut blocked = Vec::new();
    for addr in addrs {
        let forbidden = if allow_private {
            is_unspecified_or_sinkhole_ip(addr.ip())
        } else {
            is_forbidden_ip(addr.ip(), local_ips)
        };
        if forbidden {
            blocked.push(addr.ip());
        } else if addr.is_ipv4() {
            allowed_v4.push(addr);
        } else {
            allowed_v6.push(addr);
        }
    }
    allowed_v4.extend(allowed_v6);
    if allowed_v4.is_empty() {
        let blocked_list = blocked
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if allow_private {
            return Err(format!(
                "resolved IP address(es) [{blocked_list}] for host '{host}' are unroutable"
            ));
        }
        return Err(format!(
            "resolved IP address(es) [{blocked_list}] for host '{host}' are forbidden by SSRF policy"
        ));
    }
    Ok(allowed_v4)
}

pub(crate) fn should_fallback_to_doh(
    host: &str,
    os_result: &Result<Vec<SocketAddr>, String>,
) -> bool {
    let clean_host = host.trim().trim_matches(['[', ']']).trim_end_matches('.');
    if clean_host.is_empty()
        || clean_host.parse::<IpAddr>().is_ok()
        || is_local_hostname(clean_host)
        || !clean_host.contains('.')
    {
        return false;
    }
    match os_result {
        Err(_) => true,
        Ok(addrs) => {
            addrs.is_empty()
                || addrs
                    .iter()
                    .all(|addr| is_unspecified_or_sinkhole_ip(addr.ip()))
        }
    }
}

pub(crate) fn parse_doh_answer_ips(body: &[u8], port: u16) -> Result<Vec<SocketAddr>, String> {
    let doc: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid DoH JSON: {e}"))?;
    if let Some(status) = doc.get("Status").and_then(Value::as_u64) {
        if status != 0 {
            return Err(format!("DoH query returned DNS status {status}"));
        }
    }
    let mut addrs = Vec::new();
    if let Some(answers) = doc.get("Answer").and_then(Value::as_array) {
        for ans in answers {
            if let Some(rtype) = ans.get("type").and_then(Value::as_u64) {
                if rtype != 1 && rtype != 28 {
                    continue;
                }
            }
            let Some(data) = ans.get("data").and_then(Value::as_str) else {
                continue;
            };
            if let Ok(ip) = data.trim().parse::<IpAddr>() {
                let sa = SocketAddr::new(ip, port);
                if !addrs.contains(&sa) {
                    addrs.push(sa);
                }
            }
        }
    }
    Ok(addrs)
}

async fn query_doh_endpoint(
    client: &reqwest::Client,
    endpoint: &str,
    host: &str,
    record_type: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, String> {
    let clean_host = host.trim().trim_matches(['[', ']']).trim_end_matches('.');
    let url = reqwest::Url::parse_with_params(
        endpoint,
        &[("name", clean_host), ("type", record_type)],
    )
    .map_err(|e| format!("invalid DoH endpoint URL: {e}"))?;

    let mut resp = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .header(reqwest::header::USER_AGENT, "OpenBot-PS5/1.0")
        .send()
        .await
        .map_err(|e| format!("DoH request failed ({endpoint}): {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("DoH HTTP {} from {endpoint}", resp.status().as_u16()));
    }

    let mut bytes = Vec::with_capacity(2048);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("DoH body read failed ({endpoint}): {e}"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_DOH_RESPONSE_BYTES {
            return Err(format!("DoH response exceeded {MAX_DOH_RESPONSE_BYTES} bytes"));
        }
        bytes.extend_from_slice(&chunk);
    }
    parse_doh_answer_ips(&bytes, port)
}

pub(crate) async fn resolve_via_doh_endpoints(
    endpoints: &[&str],
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(0)
        .redirect(Policy::none())
        .no_proxy()
        .build()
        .map_err(|e| format!("DoH client error: {e}"))?;

    let mut last_err: Option<String> = None;
    for record_type in ["A", "AAAA"] {
        for endpoint in endpoints {
            match query_doh_endpoint(&client, endpoint, host, record_type, port).await {
                Ok(addrs) => {
                    let usable: Vec<SocketAddr> = addrs
                        .into_iter()
                        .filter(|a| !is_unspecified_or_sinkhole_ip(a.ip()))
                        .collect();
                    if !usable.is_empty() {
                        return Ok(usable);
                    }
                    last_err = Some(format!(
                        "DoH {endpoint} returned no usable {record_type} addresses for '{host}'"
                    ));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| format!("DoH resolution failed for host '{host}'")))
}

async fn resolve_host_addrs_with_fallback<F, Fut>(
    host: &str,
    os_result: Result<Vec<SocketAddr>, String>,
    local_ips: &[Ipv4Addr],
    allow_private: bool,
    doh_lookup: F,
) -> Result<Vec<SocketAddr>, String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<SocketAddr>, String>>,
{
    let candidate_addrs = if should_fallback_to_doh(host, &os_result) {
        match doh_lookup().await {
            Ok(doh_addrs) if !doh_addrs.is_empty() => doh_addrs,
            Ok(_) => match os_result {
                Ok(os_addrs) if !os_addrs.is_empty() => os_addrs,
                Ok(_) => {
                    return Err(format!(
                        "DNS resolution for host '{host}' returned no addresses"
                    ));
                }
                Err(e) => return Err(e),
            },
            Err(doh_err) => match os_result {
                Ok(os_addrs) if !os_addrs.is_empty() => os_addrs,
                Ok(_) => {
                    return Err(format!(
                        "DNS resolution for host '{host}' returned no addresses (DoH fallback failed: {doh_err})"
                    ));
                }
                Err(os_err) => {
                    return Err(format!("{os_err} (DoH fallback failed: {doh_err})"));
                }
            },
        }
    } else {
        os_result?
    };
    select_socket_addrs_with_policy(host, candidate_addrs, local_ips, allow_private)
}

async fn web_fetch_ssrf_safe(raw_url: &str, dns_jobs: Arc<Semaphore>) -> Result<FetchResult, String> {
    web_fetch_ssrf_safe_with_policy(raw_url, dns_jobs, allow_all_web_pages_from_env()).await
}

async fn resolve_validated_addrs(
    url: &reqwest::Url,
    dns_jobs: &Arc<Semaphore>,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "missing host".to_owned())?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "unknown port".to_owned())?;

    let permit = dns_jobs
        .clone()
        .try_acquire_owned()
        .map_err(|_| "too many concurrent DNS lookups".to_owned())?;
    let resolve_host = host.clone();
    enum LookupOutcome {
        Literal(Vec<SocketAddr>),
        NeedsResolution {
            local_ips: Vec<Ipv4Addr>,
            os_result: Result<Vec<SocketAddr>, String>,
        },
    }
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let local_ips = if allow_private {
                Vec::new()
            } else {
                origin::system_ipv4().map_err(|_| {
                    "local interface enumeration unavailable; failing closed".to_owned()
                })?
            };

            if let Ok(ip) = resolve_host.parse::<IpAddr>() {
                let forbidden = if allow_private {
                    is_unspecified_or_sinkhole_ip(ip)
                } else {
                    is_forbidden_ip(ip, &local_ips)
                };
                if forbidden {
                    return Err(format!(
                        "target IP address {ip} for host '{resolve_host}' is forbidden by SSRF policy"
                    ));
                }
                return Ok(LookupOutcome::Literal(vec![SocketAddr::new(ip, port)]));
            }

            let os_result = (resolve_host.as_str(), port)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
                .map_err(|e| format!("DNS resolution failed for host '{resolve_host}': {e}"));
            Ok(LookupOutcome::NeedsResolution {
                local_ips,
                os_result,
            })
        }),
    )
    .await
    .map_err(|_| "DNS resolution timed out".to_owned())?
    .map_err(|_| "DNS resolution task failed".to_owned())??;

    match outcome {
        LookupOutcome::Literal(addrs) => Ok(addrs),
        LookupOutcome::NeedsResolution {
            local_ips,
            os_result,
        } => {
            let doh_host = host.clone();
            resolve_host_addrs_with_fallback(
                &host,
                os_result,
                &local_ips,
                allow_private,
                move || async move {
                    resolve_via_doh_endpoints(DOH_ENDPOINTS, &doh_host, port).await
                },
            )
            .await
        }
    }
}

pub(crate) async fn web_fetch_ssrf_safe_with_policy(
    raw_url: &str,
    dns_jobs: Arc<Semaphore>,
    allow_private: bool,
) -> Result<FetchResult, String> {
    let mut url = validate_fetch_url_with_policy(raw_url, allow_private)?;
    let mut resp_opt = None;
    for _hop in 0..=5usize {
        let host = url
            .host_str()
            .ok_or_else(|| "missing host".to_owned())?
            .trim_matches(['[', ']'])
            .to_owned();
        let pinned_addrs = resolve_validated_addrs(&url, &dns_jobs, allow_private).await?;

        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(8)
            .tcp_nodelay(true)
            .redirect(Policy::none())
            .no_proxy();
        if host.parse::<IpAddr>().is_err() {
            builder = builder.resolve_to_addrs(&host, &pinned_addrs);
        }
        let client = builder
            .build()
            .map_err(|e| format!("HTTP client error: {e}"))?;

        let resp = client
            .get(url.clone())
            .header(reqwest::header::USER_AGENT, CHROME_USER_AGENT)
            .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .send()
            .await
            .map_err(|e| format!("fetch failed: {e}"))?;

        if resp.status().is_redirection() {
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("redirect missing Location (HTTP {})", resp.status().as_u16()))?;
            let next = url
                .join(loc)
                .map_err(|_| "invalid redirect URL".to_owned())?;
            url = validate_fetch_url_with_policy(next.as_str(), allow_private)?;
            continue;
        }
        resp_opt = Some(resp);
        break;
    }
    let mut resp = resp_opt.ok_or_else(|| "too many redirects".to_owned())?;
    let status = resp.status().as_u16();

    let is_html = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            let mime = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            mime.is_empty() || mime == "text/html" || mime == "application/xhtml+xml"
        })
        .unwrap_or(true);

    let mut raw = Vec::with_capacity(16 * 1024);
    let mut truncated = false;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("body read failed: {e}"))?
    {
        if raw.len().saturating_add(chunk.len()) > MAX_FETCH_BYTES {
            let take = MAX_FETCH_BYTES.saturating_sub(raw.len());
            raw.extend_from_slice(&chunk[..take]);
            truncated = true;
            break;
        }
        raw.extend_from_slice(&chunk);
    }

    let final_url = resp.url().to_string();
    drop(resp);
    let result = process_fetched_bytes(
        final_url,
        url.host_str().unwrap_or(""),
        status,
        is_html,
        &raw,
        truncated,
    );
    drop(raw);
    Ok(result)
}

fn clip_str_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => s[..idx].to_owned(),
        None => s.to_owned(),
    }
}

fn clip_str_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn bounded_web_fetch_tool_output(fetched: &FetchResult) -> Value {
    let safe_url = clip_str_chars(&fetched.url, 512);
    let safe_title = clip_str_chars(&fetched.title, 256);
    let total_text_chars = fetched.text.chars().count();
    let mut text_limit = total_text_chars.min(2600);
    loop {
        let model_text = clip_str_chars(&fetched.text, text_limit);
        let model_trunc = fetched.truncated || text_limit < total_text_chars;
        let payload = json!({
            "ok": true,
            "url": safe_url,
            "status": fetched.status,
            "title": safe_title,
            "text": model_text,
            "truncated": model_trunc,
        });
        let encoded_chars = serde_json::to_string(&payload)
            .map(|s| s.chars().count())
            .unwrap_or(0);
        if encoded_chars <= MAX_TOOL_OUTPUT_CHARS || text_limit == 0 {
            return payload;
        }
        let excess = encoded_chars - MAX_TOOL_OUTPUT_CHARS;
        text_limit = text_limit.saturating_sub(excess.max(32));
    }
}

fn process_fetched_bytes(
    final_url: String,
    fallback_host: &str,
    status: u16,
    is_html: bool,
    raw: &[u8],
    mut truncated: bool,
) -> FetchResult {
    let capped_url = clip_str_chars(&final_url, 1024);
    let body_str = String::from_utf8_lossy(raw);
    let (raw_title, text, visual_html) = if is_html {
        let (t, txt) = extract_html_title_and_text(&body_str);
        let preview = build_visual_html_preview(&capped_url, &body_str);
        (t, txt, preview)
    } else {
        let host_title = fallback_host.to_owned();
        let plain_text = clip_str_chars(&body_str, MAX_PAGE_TEXT_CHARS);
        if body_str.chars().count() > MAX_PAGE_TEXT_CHARS {
            truncated = true;
        }
        let escaped_src = clip_str_chars(&plain_text, 6 * 1024);
        let escaped = escape_html(&escaped_src);
        let prefix = "<!doctype html><html><body style=\"font-family:ui-monospace,monospace;white-space:pre-wrap;padding:16px;background:#0f172a;color:#e2e8f0\">";
        let suffix = "</body></html>";
        let max_inner = MAX_PREVIEW_HTML_BYTES.saturating_sub(prefix.len() + suffix.len());
        let inner = clip_str_bytes(&escaped, max_inner);
        let preview = format!("{prefix}{inner}{suffix}");
        (host_title, plain_text, preview)
    };
    let title = clip_str_chars(&raw_title, 256);
    let final_text = if text.chars().count() > MAX_PAGE_TEXT_CHARS {
        truncated = true;
        clip_str_chars(&text, MAX_PAGE_TEXT_CHARS)
    } else {
        text
    };

    FetchResult {
        url: capped_url,
        status,
        title,
        text: final_text,
        html: visual_html,
        bridge_png: None,
        truncated,
    }
}

#[allow(dead_code)]
async fn web_fetch_or_bridge(
    raw_url: &str,
    bot_id: &str,
    dns_jobs: Arc<Semaphore>,
) -> Result<FetchResult, String> {
    web_fetch_or_bridge_with_policy(raw_url, bot_id, dns_jobs, false).await
}

async fn web_fetch_or_bridge_with_policy(
    raw_url: &str,
    bot_id: &str,
    dns_jobs: Arc<Semaphore>,
    allow_all_web_pages: bool,
) -> Result<FetchResult, String> {
    if let Ok(bridge_base) = std::env::var("OPENBOT_BROWSER_BRIDGE_URL") {
        let trimmed = bridge_base.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            let client = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(25))
                .no_proxy()
                .build()
                .map_err(|e| format!("bridge client error: {e}"))?;
            if let Ok(mut resp) = client
                .post(format!("{trimmed}/navigate"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(json!({ "botId": bot_id, "url": raw_url }).to_string())
                .send()
                .await
            {
                if resp.status().is_success() {
                    let mut bytes = Vec::with_capacity(16 * 1024);
                    let mut within_limit = true;
                    while let Ok(Some(chunk)) = resp.chunk().await {
                        if bytes.len().saturating_add(chunk.len()) > MAX_BRIDGE_RESPONSE_BYTES {
                            within_limit = false;
                            break;
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    if within_limit {
                        if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                            let url = clip_str_chars(
                                val.get("url").and_then(Value::as_str).unwrap_or(raw_url),
                                1024,
                            );
                            let title = clip_str_chars(
                                val.get("title").and_then(Value::as_str).unwrap_or(""),
                                256,
                            );
                            let raw_text = val.get("text").and_then(Value::as_str).unwrap_or("");
                            let truncated = raw_text.chars().count() > MAX_PAGE_TEXT_CHARS;
                            let text = clip_str_chars(raw_text, MAX_PAGE_TEXT_CHARS);
                            let raw_html = val.get("html").and_then(Value::as_str).unwrap_or("");
                            let html = if raw_html.is_empty() {
                                String::new()
                            } else {
                                build_visual_html_preview(&url, raw_html)
                            };
                            let bridge_png = val
                                .get("screenshotBase64")
                                .and_then(Value::as_str)
                                .and_then(|b64| B64.decode(b64).ok());
                            return Ok(FetchResult {
                                url,
                                status: 200,
                                title,
                                text,
                                html,
                                bridge_png,
                                truncated,
                            });
                        }
                    }
                }
            }
        }
    }
    web_fetch_ssrf_safe_with_policy(
        raw_url,
        dns_jobs,
        allow_all_web_pages || allow_all_web_pages_from_env(),
    )
    .await
}

fn find_ascii_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first_low = needle[0].to_ascii_lowercase();
    let first_up = needle[0].to_ascii_uppercase();
    let limit = haystack.len() - needle.len() + 1;
    let mut i = 0;
    while i < limit {
        let b = haystack[i];
        if (b == first_low || b == first_up) && haystack[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn match_skipped_block_tag(rest: &[u8]) -> Option<(&'static [u8], usize)> {
    const TAGS: &[(&[u8], &[u8])] = &[
        (b"<script", b"</script"),
        (b"<style", b"</style"),
        (b"<noscript", b"</noscript"),
    ];
    for &(open, close) in TAGS {
        if starts_with_ascii_ci(rest, open)
            && matches!(
                rest.get(open.len()).copied(),
                None | Some(b'>' | b' ' | b'\t' | b'\r' | b'\n' | b'/')
            )
        {
            return Some((close, open.len()));
        }
    }
    None
}

fn extract_attr_ci(tag: &str, attr_name: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let needle = attr_name.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        if i > 0
            && bytes[i - 1].is_ascii_whitespace()
            && starts_with_ascii_ci(&bytes[i..], needle)
        {
            let mut j = i + needle.len();
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
                    let quote = bytes[j];
                    let start = j + 1;
                    if let Some(rel_end) = tag[start..].find(quote as char) {
                        return Some(collapse_ws(&decode_entities(&tag[start..start + rel_end])));
                    }
                } else {
                    let start = j;
                    while j < bytes.len() && !bytes[j].is_ascii_whitespace() && bytes[j] != b'>' {
                        j += 1;
                    }
                    if j > start {
                        return Some(collapse_ws(&decode_entities(&tag[start..j])));
                    }
                }
            }
        }
        i += 1;
    }
    None
}

#[derive(Default)]
struct HtmlMetadata {
    og_title: String,
    description: String,
    canonical: String,
    links: Vec<(String, String)>,
}

fn extract_html_metadata(raw_html: &str, cleaned_html: &str) -> HtmlMetadata {
    let mut meta = HtmlMetadata::default();
    let raw_bytes = raw_html.as_bytes();
    let mut i = 0usize;
    while i < raw_bytes.len() {
        if raw_bytes[i] == b'<' {
            if let Some((closing, skip_len)) = match_skipped_block_tag(&raw_bytes[i..]) {
                let mut j = i + skip_len;
                while j < raw_bytes.len() {
                    if raw_bytes[j] == b'<' && starts_with_ascii_ci(&raw_bytes[j..], closing) {
                        while j < raw_bytes.len() && raw_bytes[j] != b'>' {
                            j += 1;
                        }
                        if j < raw_bytes.len() {
                            j += 1;
                        }
                        break;
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            if let Some(rel_gt) = raw_bytes[i..].iter().position(|&b| b == b'>') {
                let tag = &raw_html[i..i + rel_gt + 1];
                let tb = tag.as_bytes();
                if starts_with_ascii_ci(tb, b"<meta")
                    && matches!(tb.get(5).copied(), Some(b' ' | b'\t' | b'\r' | b'\n'))
                {
                    let key = extract_attr_ci(tag, "name")
                        .or_else(|| extract_attr_ci(tag, "property"))
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if let Some(content) = extract_attr_ci(tag, "content") {
                        if !content.is_empty() {
                            match key.as_str() {
                                "og:title" | "twitter:title" if meta.og_title.is_empty() => {
                                    meta.og_title = clip_str_chars(&content, 256);
                                }
                                "description" | "og:description" | "twitter:description"
                                    if meta.description.is_empty() =>
                                {
                                    meta.description = clip_str_chars(&content, 600);
                                }
                                _ => {}
                            }
                        }
                    }
                } else if starts_with_ascii_ci(tb, b"<link")
                    && matches!(tb.get(5).copied(), Some(b' ' | b'\t' | b'\r' | b'\n'))
                    && meta.canonical.is_empty()
                {
                    let rel = extract_attr_ci(tag, "rel")
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if rel.split_whitespace().any(|r| r == "canonical") {
                        if let Some(href) = extract_attr_ci(tag, "href") {
                            if !href.is_empty() {
                                meta.canonical = clip_str_chars(&href, 512);
                            }
                        }
                    }
                }
                i += rel_gt + 1;
                continue;
            }
        }
        i += 1;
    }

    // Collect up to 6 unique safe links from cleaned_html for SPA fallback cards.
    let cb = cleaned_html.as_bytes();
    let mut k = 0usize;
    while k < cb.len() && meta.links.len() < 6 {
        if cb[k] == b'<'
            && starts_with_ascii_ci(&cb[k..], b"<a")
            && matches!(cb.get(k + 2).copied(), Some(b' ' | b'\t' | b'\r' | b'\n'))
        {
            if let Some(rel_gt) = cb[k..].iter().position(|&b| b == b'>') {
                let open_tag = &cleaned_html[k..k + rel_gt + 1];
                let after_open = k + rel_gt + 1;
                if let Some(href) = extract_attr_ci(open_tag, "href") {
                    let href_trim = href.trim();
                    let lower_href = href_trim.to_ascii_lowercase();
                    let safe_href = !href_trim.is_empty()
                        && !lower_href.starts_with("javascript:")
                        && !lower_href.starts_with("data:")
                        && !lower_href.starts_with("vbscript:")
                        && !href_trim.starts_with('#');
                    let label = if let Some(rel_close) = find_ascii_ci(&cb[after_open..], b"</a>") {
                        let inner = &cleaned_html[after_open..after_open + rel_close];
                        let (_, txt) = extract_html_title_and_text(inner);
                        clip_str_chars(&collapse_ws(&txt), 80)
                    } else {
                        String::new()
                    };
                    if safe_href
                        && !label.is_empty()
                        && !meta.links.iter().any(|(h, _)| h == href_trim)
                    {
                        meta.links
                            .push((clip_str_chars(href_trim, 512), label));
                    }
                }
                k = after_open;
                continue;
            }
        }
        k += 1;
    }
    meta
}

fn extract_visible_text_ignoring_svg(html_fragment: &str) -> String {
    let bytes = html_fragment.as_bytes();
    let mut out = String::with_capacity(html_fragment.len().min(1024));
    let mut i = 0usize;
    let mut skip_until: Option<&'static [u8]> = None;
    while i < bytes.len() && out.len() < 1024 {
        if let Some(end_tag) = skip_until {
            if bytes[i] == b'<' && starts_with_ascii_ci(&bytes[i..], end_tag) {
                while i < bytes.len() && bytes[i] != b'>' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                skip_until = None;
                continue;
            }
            i += 1;
            continue;
        }
        if bytes[i] == b'<' {
            let rest = &bytes[i..];
            if let Some((close, _)) = match_skipped_block_tag(rest) {
                skip_until = Some(close);
            } else if starts_with_ascii_ci(rest, b"<svg")
                && matches!(rest.get(4).copied(), None | Some(b'>' | b' ' | b'\t' | b'\r' | b'\n'))
            {
                skip_until = Some(b"</svg");
            }
            if !out.ends_with(' ') && !out.is_empty() {
                out.push(' ');
            }
            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
        } else {
            let next_tag = bytes[i..]
                .iter()
                .position(|&b| b == b'<')
                .map(|p| i + p)
                .unwrap_or(bytes.len());
            let chunk = String::from_utf8_lossy(&bytes[i..next_tag]);
            out.push_str(&decode_entities(&chunk));
            i = next_tag;
        }
    }
    collapse_ws(&out)
}

fn is_empty_or_spa_shell(cleaned: &str) -> bool {
    let cleaned_bytes = cleaned.as_bytes();
    let visible = if let Some(body_pos) = find_ascii_ci(cleaned_bytes, b"<body") {
        extract_visible_text_ignoring_svg(&cleaned[body_pos..])
    } else if find_ascii_ci(cleaned_bytes, b"<head").is_some() {
        if let Some(head_end) = find_ascii_ci(cleaned_bytes, b"</head>") {
            extract_visible_text_ignoring_svg(&cleaned[head_end + 7..])
        } else {
            String::new()
        }
    } else {
        extract_visible_text_ignoring_svg(cleaned)
    };

    let visible_len = visible.trim().chars().count();
    if visible_len == 0 {
        return true;
    }

    let spa_markers: &[&[u8]] = &[
        b"<ytd-app",
        b"id=\"root\"",
        b"id='root'",
        b"id=\"app\"",
        b"id='app'",
        b"id=\"__next\"",
        b"id=\"__nuxt\"",
        b"<app-root",
    ];
    let has_spa_marker = spa_markers
        .iter()
        .any(|m| find_ascii_ci(cleaned_bytes, m).is_some());
    has_spa_marker && visible_len < 240
}

fn build_spa_fallback_card_html(
    base_url: &str,
    base_tag: &str,
    title: &str,
    reader_text: &str,
    meta: &HtmlMetadata,
) -> String {
    let display_title = if !title.trim().is_empty() {
        title.trim()
    } else if !meta.og_title.trim().is_empty() {
        meta.og_title.trim()
    } else {
        base_url
    };
    let safe_title = escape_html(&clip_str_chars(display_title, 256));
    let safe_url = escape_html(&clip_str_chars(base_url, 1024));
    let desc_block = if !meta.description.is_empty() {
        format!(
            "<div class=\"section\"><div class=\"label\">Description</div><p class=\"meta-text\">{}</p></div>",
            escape_html(&clip_str_chars(&meta.description, 600))
        )
    } else {
        String::new()
    };
    let canonical_block = if !meta.canonical.is_empty() && meta.canonical != base_url {
        let safe_can = escape_html(&clip_str_chars(&meta.canonical, 512));
        format!(
            "<div class=\"meta-row\"><span class=\"label\">Canonical</span><a class=\"chip-link\" href=\"{safe_can}\" target=\"_blank\" rel=\"noopener noreferrer\">{safe_can}</a></div>"
        )
    } else {
        String::new()
    };
    let links_block = if !meta.links.is_empty() {
        let mut items = String::new();
        for (href, label) in &meta.links {
            items.push_str(&format!(
                "<a class=\"chip-link\" href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{}</a>",
                escape_html(href),
                escape_html(label)
            ));
        }
        format!("<div class=\"section\"><div class=\"label\">Links</div><div class=\"chips\">{items}</div></div>")
    } else {
        String::new()
    };

    let text_source = if !reader_text.trim().is_empty() {
        reader_text.trim()
    } else if !meta.description.is_empty() {
        meta.description.trim()
    } else {
        "No static text was rendered in the initial HTML (this site renders its content dynamically via JavaScript)."
    };

    let render_card = |clipped_reader: &str| {
        let safe_reader = escape_html(clipped_reader);
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\">{base_tag}<style>\
body{{margin:0;padding:20px;font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.5}}\
.card{{max-width:760px;margin:0 auto;background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px}}\
.badge{{display:inline-block;font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#38bdf8;background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.3);border-radius:999px;padding:2px 10px;margin-bottom:10px}}\
h1{{margin:0 0 12px;font-size:20px;line-height:1.3;color:#f8fafc;word-break:break-word}}\
.url-box{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:8px;margin-bottom:14px}}\
.url-link{{color:#60a5fa;text-decoration:none;font-size:13px;word-break:break-all}}\
.url-link:hover{{text-decoration:underline}}\
.section{{margin-top:14px;padding-top:14px;border-top:1px solid #334155}}\
.label{{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin-bottom:6px}}\
.meta-row{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px}}\
.meta-text{{margin:0;font-size:14px;color:#cbd5e1}}\
.reader{{margin:0;white-space:pre-wrap;font-size:13px;color:#e2e8f0;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px;max-height:420px;overflow:auto}}\
.chips{{display:flex;flex-wrap:wrap;gap:8px}}\
.chip-link{{display:inline-block;padding:4px 10px;border-radius:6px;background:#0f172a;border:1px solid #475569;color:#93c5fd;font-size:12px;text-decoration:none}}\
.chip-link:hover{{border-color:#60a5fa;color:#bfdbfe}}\
</style></head><body><main class=\"card\">\
<span class=\"badge\">Dynamic App Preview</span>\
<h1>{safe_title}</h1>\
<div class=\"url-box\"><span class=\"label\" style=\"margin:0\">URL</span><a class=\"url-link\" href=\"{safe_url}\" target=\"_blank\" rel=\"noopener noreferrer\">{safe_url}</a></div>\
{canonical_block}{desc_block}\
<div class=\"section\"><div class=\"label\">Extracted Reader Text</div><pre class=\"reader\">{safe_reader}</pre></div>\
{links_block}\
</main></body></html>"
        )
    };

    let mut limit = text_source.chars().count().min(MAX_PAGE_TEXT_CHARS);
    loop {
        let candidate = render_card(&clip_str_chars(text_source, limit));
        if candidate.len() <= MAX_PREVIEW_HTML_BYTES || limit == 0 {
            if candidate.len() <= MAX_PREVIEW_HTML_BYTES {
                return candidate;
            }
            return clip_str_bytes(&candidate, MAX_PREVIEW_HTML_BYTES).to_owned();
        }
        let excess = candidate.len() - MAX_PREVIEW_HTML_BYTES;
        limit = limit.saturating_sub(excess.max(64));
    }
}

fn build_visual_html_preview(base_url: &str, raw_html: &str) -> String {
    // Strip <script>...</script>, <style>...</style>, and <noscript>...</noscript> blocks
    // before enforcing MAX_PREVIEW_HTML_BYTES so <head> scripts/styles don't starve <body>.
    let safe_base = escape_html(&clip_str_chars(base_url, 1024));
    let base_tag = format!(
        "<base href=\"{safe_base}\" target=\"_blank\"><style>html,body{{margin:8px;font-family:system-ui,-apple-system,sans-serif}}img,svg{{max-width:100%;height:auto}}</style>"
    );
    let budget = MAX_PREVIEW_HTML_BYTES.saturating_sub(base_tag.len() + 32);
    let mut cleaned = String::with_capacity(raw_html.len().min(budget));
    let bytes = raw_html.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && cleaned.len() < budget {
        if bytes[i] == b'<' {
            let rest = &bytes[i..];
            if let Some((closing, skip_len)) = match_skipped_block_tag(rest) {
                let mut j = i + skip_len;
                while j < bytes.len() {
                    if bytes[j] == b'<' && starts_with_ascii_ci(&bytes[j..], closing) {
                        while j < bytes.len() && bytes[j] != b'>' {
                            j += 1;
                        }
                        if j < bytes.len() {
                            j += 1;
                        }
                        break;
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            let next_gt = bytes[i..].iter().position(|&b| b == b'>');
            let seg_end = match next_gt {
                Some(rel) => i + rel + 1,
                None => break,
            };
            let rem = budget.saturating_sub(cleaned.len());
            if seg_end - i > rem {
                break;
            }
            cleaned.push_str(&raw_html[i..seg_end]);
            i = seg_end;
        } else {
            let next_lt = bytes[i..]
                .iter()
                .position(|&b| b == b'<')
                .map(|p| i + p)
                .unwrap_or(bytes.len());
            let rem = budget.saturating_sub(cleaned.len());
            let slice = clip_str_bytes(&raw_html[i..next_lt], rem);
            cleaned.push_str(slice);
            if slice.len() < next_lt - i {
                break;
            }
            i = next_lt;
        }
    }

    if is_empty_or_spa_shell(&cleaned) {
        let (title, reader_text) = extract_html_title_and_text(raw_html);
        let meta = extract_html_metadata(raw_html, &cleaned);
        return build_spa_fallback_card_html(base_url, &base_tag, &title, &reader_text, &meta);
    }

    let cleaned_bytes = cleaned.as_bytes();
    if let Some(pos) = find_ascii_ci(cleaned_bytes, b"<head>") {
        let mut out = String::with_capacity(cleaned.len() + base_tag.len());
        out.push_str(&cleaned[..pos + 6]);
        out.push_str(&base_tag);
        out.push_str(&cleaned[pos + 6..]);
        out
    } else if let Some(pos) = find_ascii_ci(cleaned_bytes, b"<head ") {
        if let Some(rel_end) = cleaned[pos..].find('>') {
            let split = pos + rel_end + 1;
            let mut out = String::with_capacity(cleaned.len() + base_tag.len());
            out.push_str(&cleaned[..split]);
            out.push_str(&base_tag);
            out.push_str(&cleaned[split..]);
            out
        } else {
            format!("{base_tag}{cleaned}")
        }
    } else {
        format!("<head>{base_tag}</head>{cleaned}")
    }
}

fn extract_html_title_and_text(html: &str) -> (String, String) {
    let bytes = html.as_bytes();
    let mut title = if let (Some(ts), Some(te)) = (
        find_ascii_ci(bytes, b"<title"),
        find_ascii_ci(bytes, b"</title>"),
    ) {
        if let Some(gt) = html[ts..].find('>') {
            let start = ts + gt + 1;
            if start <= te {
                clip_str_chars(&collapse_ws(&decode_entities(&html[start..te])), 256)
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let mut out = String::with_capacity(html.len().min(MAX_PAGE_TEXT_CHARS));
    let mut i = 0usize;
    let mut skip_until: Option<&'static [u8]> = None;
    let max_raw_text_bytes = MAX_PAGE_TEXT_CHARS.saturating_mul(2);

    while i < bytes.len() && out.len() < max_raw_text_bytes {
        if let Some(end_tag) = skip_until {
            if bytes[i] == b'<' && starts_with_ascii_ci(&bytes[i..], end_tag) {
                while i < bytes.len() && bytes[i] != b'>' {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
                skip_until = None;
                continue;
            }
            i += 1;
            continue;
        }

        if bytes[i] == b'<' {
            let rest = &bytes[i..];
            if let Some((close, _)) = match_skipped_block_tag(rest) {
                skip_until = Some(close);
            }
            if is_block_tag(rest) && !out.ends_with('\n') && !out.is_empty() {
                out.push('\n');
            } else if !out.ends_with([' ', '\n']) && !out.is_empty() {
                out.push(' ');
            }
            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
        } else {
            let next_tag = bytes[i..]
                .iter()
                .position(|b| *b == b'<')
                .map(|p| i + p)
                .unwrap_or(bytes.len());
            let chunk = String::from_utf8_lossy(&bytes[i..next_tag]);
            out.push_str(&decode_entities(&chunk));
            i = next_tag;
        }
    }

    let mut reader = clip_str_chars(&collapse_multiline(&out), MAX_PAGE_TEXT_CHARS);
    if title.is_empty() || reader.is_empty() {
        let meta = extract_html_metadata(html, "");
        if title.is_empty() && !meta.og_title.is_empty() {
            title = meta.og_title;
        }
        if reader.is_empty() && !meta.description.is_empty() {
            reader = clip_str_chars(&meta.description, MAX_PAGE_TEXT_CHARS);
        }
    }
    (title, reader)
}

fn starts_with_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

fn is_block_tag(tag: &[u8]) -> bool {
    const BLOCKS: &[&[u8]] = &[
        b"<p", b"</p", b"<div", b"</div", b"<br", b"<li", b"</li", b"<tr", b"</tr", b"<h1", b"</h1",
        b"<h2", b"</h2", b"<h3", b"</h3", b"<h4", b"</h4", b"<section", b"<article",
    ];
    BLOCKS.iter().any(|b| starts_with_ascii_ci(tag, b))
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';').filter(|&p| p <= 12) {
            let entity = &after[..semi];
            let decoded_char = if let Some(hex) = entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else if let Some(dec) = entity.strip_prefix('#') {
                dec.parse::<u32>().ok().and_then(char::from_u32)
            } else {
                match entity {
                    "nbsp" => Some(' '),
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "copy" => Some('©'),
                    "reg" => Some('®'),
                    "trade" => Some('™'),
                    "ndash" => Some('–'),
                    "mdash" => Some('—'),
                    "hellip" => Some('…'),
                    "laquo" => Some('«'),
                    "raquo" => Some('»'),
                    "lsquo" => Some('‘'),
                    "rsquo" => Some('’'),
                    "ldquo" => Some('“'),
                    "rdquo" => Some('”'),
                    "bull" => Some('•'),
                    "middot" => Some('·'),
                    "euro" => Some('€'),
                    "pound" => Some('£'),
                    _ => None,
                }
            };
            if let Some(ch) = decoded_char {
                out.push(ch);
                rest = &after[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    out
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn collapse_multiline(s: &str) -> String {
    let mut lines = Vec::new();
    for line in s.lines() {
        let c = collapse_ws(line);
        if !c.is_empty() {
            lines.push(c);
        }
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Screen Bitmap Renderer + Pure-Rust PNG & Baseline JPEG Encoders
// ---------------------------------------------------------------------------

// Minimal 5x7 uppercase/lowercase/digits/punctuation bitmap font (printable ASCII 0x20..=0x7E)
const FONT_5X7: &[[u8; 5]] = &[
    [0x00, 0x00, 0x00, 0x00, 0x00], // ' '
    [0x00, 0x00, 0x5F, 0x00, 0x00], // '!'
    [0x00, 0x07, 0x00, 0x07, 0x00], // '"'
    [0x14, 0x7F, 0x14, 0x7F, 0x14], // '#'
    [0x24, 0x2A, 0x7F, 0x2A, 0x12], // '$'
    [0x23, 0x13, 0x08, 0x64, 0x62], // '%'
    [0x36, 0x49, 0x55, 0x22, 0x50], // '&'
    [0x00, 0x05, 0x03, 0x00, 0x00], // '''
    [0x00, 0x1C, 0x22, 0x41, 0x00], // '('
    [0x00, 0x41, 0x22, 0x1C, 0x00], // ')'
    [0x14, 0x08, 0x3E, 0x08, 0x14], // '*'
    [0x08, 0x08, 0x3E, 0x08, 0x08], // '+'
    [0x00, 0x50, 0x30, 0x00, 0x00], // ','
    [0x08, 0x08, 0x08, 0x08, 0x08], // '-'
    [0x00, 0x60, 0x60, 0x00, 0x00], // '.'
    [0x20, 0x10, 0x08, 0x04, 0x02], // '/'
    [0x3E, 0x51, 0x49, 0x45, 0x3E], // '0'
    [0x00, 0x42, 0x7F, 0x40, 0x00], // '1'
    [0x42, 0x61, 0x51, 0x49, 0x46], // '2'
    [0x21, 0x41, 0x45, 0x4B, 0x31], // '3'
    [0x18, 0x14, 0x12, 0x7F, 0x10], // '4'
    [0x27, 0x45, 0x45, 0x45, 0x39], // '5'
    [0x3C, 0x4A, 0x49, 0x49, 0x30], // '6'
    [0x01, 0x71, 0x09, 0x05, 0x03], // '7'
    [0x36, 0x49, 0x49, 0x49, 0x36], // '8'
    [0x06, 0x49, 0x49, 0x29, 0x1E], // '9'
    [0x00, 0x36, 0x36, 0x00, 0x00], // ':'
    [0x00, 0x56, 0x36, 0x00, 0x00], // ';'
    [0x08, 0x14, 0x22, 0x41, 0x00], // '<'
    [0x14, 0x14, 0x14, 0x14, 0x14], // '='
    [0x00, 0x41, 0x22, 0x14, 0x08], // '>'
    [0x02, 0x01, 0x51, 0x09, 0x06], // '?'
    [0x32, 0x49, 0x79, 0x41, 0x3E], // '@'
    [0x7E, 0x11, 0x11, 0x11, 0x7E], // 'A'
    [0x7F, 0x49, 0x49, 0x49, 0x36], // 'B'
    [0x3E, 0x41, 0x41, 0x41, 0x22], // 'C'
    [0x7F, 0x41, 0x41, 0x22, 0x1C], // 'D'
    [0x7F, 0x49, 0x49, 0x49, 0x41], // 'E'
    [0x7F, 0x09, 0x09, 0x09, 0x01], // 'F'
    [0x3E, 0x41, 0x49, 0x49, 0x7A], // 'G'
    [0x7F, 0x08, 0x08, 0x08, 0x7F], // 'H'
    [0x00, 0x41, 0x7F, 0x41, 0x00], // 'I'
    [0x20, 0x40, 0x41, 0x3F, 0x01], // 'J'
    [0x7F, 0x08, 0x14, 0x22, 0x41], // 'K'
    [0x7F, 0x40, 0x40, 0x40, 0x40], // 'L'
    [0x7F, 0x02, 0x0C, 0x02, 0x7F], // 'M'
    [0x7F, 0x04, 0x08, 0x10, 0x7F], // 'N'
    [0x3E, 0x41, 0x41, 0x41, 0x3E], // 'O'
    [0x7F, 0x09, 0x09, 0x09, 0x06], // 'P'
    [0x3E, 0x41, 0x51, 0x21, 0x5E], // 'Q'
    [0x7F, 0x09, 0x19, 0x29, 0x46], // 'R'
    [0x46, 0x49, 0x49, 0x49, 0x31], // 'S'
    [0x01, 0x01, 0x7F, 0x01, 0x01], // 'T'
    [0x3F, 0x40, 0x40, 0x40, 0x3F], // 'U'
    [0x1F, 0x20, 0x40, 0x20, 0x1F], // 'V'
    [0x3F, 0x40, 0x38, 0x40, 0x3F], // 'W'
    [0x63, 0x14, 0x08, 0x14, 0x63], // 'X'
    [0x07, 0x08, 0x70, 0x08, 0x07], // 'Y'
    [0x61, 0x51, 0x49, 0x45, 0x43], // 'Z'
    [0x00, 0x7F, 0x41, 0x41, 0x00], // '['
    [0x02, 0x04, 0x08, 0x10, 0x20], // '\'
    [0x00, 0x41, 0x41, 0x7F, 0x00], // ']'
    [0x04, 0x02, 0x01, 0x02, 0x04], // '^'
    [0x40, 0x40, 0x40, 0x40, 0x40], // '_'
    [0x00, 0x01, 0x02, 0x04, 0x00], // '`'
    [0x20, 0x54, 0x54, 0x54, 0x78], // 'a'
    [0x7F, 0x48, 0x44, 0x44, 0x38], // 'b'
    [0x38, 0x44, 0x44, 0x44, 0x20], // 'c'
    [0x38, 0x44, 0x44, 0x48, 0x7F], // 'd'
    [0x38, 0x54, 0x54, 0x54, 0x18], // 'e'
    [0x08, 0x7E, 0x09, 0x01, 0x02], // 'f'
    [0x0C, 0x52, 0x52, 0x52, 0x3E], // 'g'
    [0x7F, 0x08, 0x04, 0x04, 0x78], // 'h'
    [0x00, 0x44, 0x7D, 0x40, 0x00], // 'i'
    [0x20, 0x40, 0x44, 0x3D, 0x00], // 'j'
    [0x7F, 0x10, 0x28, 0x44, 0x00], // 'k'
    [0x00, 0x41, 0x7F, 0x40, 0x00], // 'l'
    [0x7C, 0x04, 0x18, 0x04, 0x78], // 'm'
    [0x7C, 0x08, 0x04, 0x04, 0x78], // 'n'
    [0x38, 0x44, 0x44, 0x44, 0x38], // 'o'
    [0x7C, 0x14, 0x14, 0x14, 0x08], // 'p'
    [0x08, 0x14, 0x14, 0x18, 0x7C], // 'q'
    [0x7C, 0x08, 0x04, 0x04, 0x08], // 'r'
    [0x48, 0x54, 0x54, 0x54, 0x20], // 's'
    [0x04, 0x3F, 0x44, 0x40, 0x20], // 't'
    [0x3C, 0x40, 0x40, 0x20, 0x7C], // 'u'
    [0x1C, 0x20, 0x40, 0x20, 0x1C], // 'v'
    [0x3C, 0x40, 0x30, 0x40, 0x3C], // 'w'
    [0x44, 0x28, 0x10, 0x28, 0x44], // 'x'
    [0x0C, 0x50, 0x50, 0x50, 0x3C], // 'y'
    [0x44, 0x64, 0x54, 0x4C, 0x44], // 'z'
    [0x00, 0x08, 0x36, 0x41, 0x00], // '{'
    [0x00, 0x00, 0x7F, 0x00, 0x00], // '|'
    [0x00, 0x41, 0x36, 0x08, 0x00], // '}'
    [0x10, 0x08, 0x08, 0x10, 0x08], // '~'
];

fn render_screen_rgb(snap: &ScreenSnapshot) -> Vec<u8> {
    let w = SCREEN_WIDTH as usize;
    let h = SCREEN_HEIGHT as usize;
    let mut rgb = vec![0u8; w * h * 3];

    // Background #0f172a
    fill_rect(&mut rgb, w, h, 0, 0, w, h, [15, 23, 42]);
    // Header bar #1e293b
    fill_rect(&mut rgb, w, h, 0, 0, w, 42, [30, 41, 59]);
    let accent = match snap.holder {
        ControlHolder::Bot => [56, 189, 248],
        ControlHolder::Human => [245, 158, 11],
    };
    fill_rect(&mut rgb, w, h, 0, 40, w, 2, accent);

    draw_text(&mut rgb, w, h, 14, 14, &format!("OPENBOT-PS5  BOT: {}", clip(&snap.bot_id, 24)), [241, 245, 249]);
    let holder_label = match snap.holder {
        ControlHolder::Bot => "HOLDER: BOT",
        ControlHolder::Human => "HOLDER: HUMAN",
    };
    draw_text(&mut rgb, w, h, 460, 14, holder_label, accent);

    // URL + Title panel
    fill_rect(&mut rgb, w, h, 12, 52, w - 24, 152, [22, 33, 56]);
    draw_text(&mut rgb, w, h, 20, 62, &format!("URL: {}", clip(&snap.current_url, 86)), [148, 163, 184]);
    draw_text(&mut rgb, w, h, 20, 78, &format!("TITLE: {}", clip(&snap.page_title, 84)), [226, 232, 240]);
    fill_rect(&mut rgb, w, h, 20, 92, w - 40, 1, [51, 65, 85]);

    for (idx, line) in snap.page_text.lines().take(8).enumerate() {
        draw_text(&mut rgb, w, h, 20, 100 + idx * 12, &clip(line, 96), [203, 213, 225]);
    }

    // Terminal / Activity panel
    fill_rect(&mut rgb, w, h, 12, 214, w - 24, 174, [11, 17, 32]);
    draw_text(&mut rgb, w, h, 20, 222, "TERMINAL / ACTIVITY", [56, 189, 248]);
    let start_idx = snap.terminal_lines.len().saturating_sub(11);
    for (i, line) in snap.terminal_lines[start_idx..].iter().enumerate() {
        draw_text(&mut rgb, w, h, 20, 238 + i * 12, &clip(line, 96), [134, 239, 172]);
    }
    if !snap.last_input.is_empty() {
        draw_text(
            &mut rgb,
            w,
            h,
            20,
            374,
            &format!("INPUT: {}", clip(&snap.last_input, 80)),
            [251, 191, 36],
        );
    }

    // Subtle cursor crosshair when human holds control
    if snap.holder == ControlHolder::Human {
        let cx = (snap.cursor_x as usize).min(w - 6).max(5);
        let cy = (snap.cursor_y as usize).min(h - 6).max(5);
        fill_rect(&mut rgb, w, h, cx - 4, cy, 9, 1, [245, 158, 11]);
        fill_rect(&mut rgb, w, h, cx, cy - 4, 1, 9, [245, 158, 11]);
    }
    rgb
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn fill_rect(rgb: &mut [u8], w: usize, h: usize, x: usize, y: usize, rw: usize, rh: usize, c: [u8; 3]) {
    let x_end = (x + rw).min(w);
    let y_end = (y + rh).min(h);
    for py in y..y_end {
        for px in x..x_end {
            let off = (py * w + px) * 3;
            rgb[off] = c[0];
            rgb[off + 1] = c[1];
            rgb[off + 2] = c[2];
        }
    }
}

fn ascii_fallback(ch: char) -> char {
    match ch {
        'ą' | 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
        'Ą' | 'À' | 'Á' | 'Â' | 'Ã' | 'Ä' | 'Å' => 'A',
        'ć' | 'ç' => 'c',
        'Ć' | 'Ç' => 'C',
        'ę' | 'è' | 'é' | 'ê' | 'ë' => 'e',
        'Ę' | 'È' | 'É' | 'Ê' | 'Ë' => 'E',
        'ì' | 'í' | 'î' | 'ï' => 'i',
        'Ì' | 'Í' | 'Î' | 'Ï' => 'I',
        'ł' => 'l',
        'Ł' => 'L',
        'ń' | 'ñ' => 'n',
        'Ń' | 'Ñ' => 'N',
        'ó' | 'ò' | 'ô' | 'õ' | 'ö' => 'o',
        'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'O',
        'ś' | 'š' => 's',
        'Ś' | 'Š' => 'S',
        'ù' | 'ú' | 'û' | 'ü' => 'u',
        'Ù' | 'Ú' | 'Û' | 'Ü' => 'U',
        'ż' | 'ź' | 'ž' => 'z',
        'Ż' | 'Ź' | 'Ž' => 'Z',
        '–' | '—' => '-',
        '‘' | '’' => '\'',
        '“' | '”' => '"',
        '©' => 'c',
        '®' => 'r',
        '•' | '·' => '*',
        _ => ch,
    }
}

fn draw_text(rgb: &mut [u8], w: usize, h: usize, mut x: usize, y: usize, text: &str, c: [u8; 3]) {
    for raw_ch in text.chars() {
        let ch = ascii_fallback(raw_ch);
        if x + 6 > w {
            break;
        }
        let code = ch as u32;
        let glyph_idx = if (0x20..=0x7E).contains(&code) {
            (code - 0x20) as usize
        } else {
            ('?' as u32 - 0x20) as usize
        };
        let glyph = FONT_5X7[glyph_idx];
        for (col, &bits) in glyph.iter().enumerate() {
            for row in 0..7 {
                if (bits >> row) & 1 != 0 && y + row < h {
                    let off = ((y + row) * w + (x + col)) * 3;
                    rgb[off] = c[0];
                    rgb[off + 1] = c[1];
                    rgb[off + 2] = c[2];
                }
            }
        }
        x += 6;
    }
}

/// Pure-Rust PNG encoder using stored DEFLATE (`BTYPE=00`) + CRC32 + Adler32.
pub(crate) fn encode_png_rgb(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
    let w = width as usize;
    let h = height as usize;
    let mut raw = Vec::with_capacity(h * (1 + w * 3));
    for y in 0..h {
        raw.push(0); // filter type 0 (None)
        raw.extend_from_slice(&rgb[y * w * 3..(y + 1) * w * 3]);
    }

    let mut zlib = Vec::with_capacity(raw.len() + 128);
    zlib.push(0x78);
    zlib.push(0x01);
    let chunks = raw.chunks(65535);
    let total_chunks = chunks.len().max(1);
    if raw.is_empty() {
        zlib.extend_from_slice(&[1, 0, 0, 0xFF, 0xFF]);
    } else {
        for (idx, chunk) in raw.chunks(65535).enumerate() {
            let bfinal = u8::from(idx + 1 == total_chunks);
            let len = chunk.len() as u16;
            let nlen = !len;
            zlib.push(bfinal);
            zlib.extend_from_slice(&len.to_le_bytes());
            zlib.extend_from_slice(&nlen.to_le_bytes());
            zlib.extend_from_slice(chunk);
        }
    }
    zlib.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut png = Vec::with_capacity(zlib.len() + 64);
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8; // bit depth
    ihdr[9] = 2; // RGB
    push_png_chunk(&mut png, b"IHDR", &ihdr);
    push_png_chunk(&mut png, b"IDAT", &zlib);
    push_png_chunk(&mut png, b"IEND", &[]);
    png
}

fn push_png_chunk(out: &mut Vec<u8>, tag: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32_png(tag, data).to_be_bytes());
}

fn crc32_png(tag: &[u8; 4], data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in tag.iter().chain(data.iter()) {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut s1 = 1u32;
    let mut s2 = 0u32;
    for chunk in data.chunks(5552) {
        for &b in chunk {
            s1 += b as u32;
            s2 += s1;
        }
        s1 %= MOD;
        s2 %= MOD;
    }
    (s2 << 16) | s1
}

/// Pure-Rust baseline color JPEG (`SOF0`, YCbCr 4:4:4) encoder.
pub(crate) fn encode_jpeg_rgb(width: u16, height: u16, rgb: &[u8]) -> Vec<u8> {
    const ZIGZAG: [usize; 64] = [
         0,  1,  8, 16,  9,  2,  3, 10,
        17, 24, 32, 25, 18, 11,  4,  5,
        12, 19, 26, 33, 40, 48, 41, 34,
        27, 20, 13,  6,  7, 14, 21, 28,
        35, 42, 49, 56, 57, 50, 43, 36,
        29, 22, 15, 23, 30, 37, 44, 51,
        58, 59, 52, 45, 38, 31, 39, 46,
        53, 60, 61, 54, 47, 55, 62, 63,
    ];
    // Scaled standard Annex K quantization tables (quality ~80)
    const Q_LUMA: [u8; 64] = [
         6,  4,  4,  6, 10, 16, 20, 24,
         5,  5,  6,  8, 10, 23, 24, 22,
         6,  5,  6, 10, 16, 23, 28, 22,
         6,  7,  9, 12, 20, 35, 32, 25,
         7,  9, 15, 22, 27, 44, 41, 31,
        10, 14, 22, 26, 32, 42, 45, 37,
        20, 26, 31, 35, 41, 48, 48, 40,
        29, 37, 38, 39, 45, 40, 41, 40,
    ];
    const Q_CHROMA: [u8; 64] = [
         7,  7, 10, 19, 40, 40, 40, 40,
         7,  8, 10, 26, 40, 40, 40, 40,
        10, 10, 22, 40, 40, 40, 40, 40,
        19, 26, 40, 40, 40, 40, 40, 40,
        40, 40, 40, 40, 40, 40, 40, 40,
        40, 40, 40, 40, 40, 40, 40, 40,
        40, 40, 40, 40, 40, 40, 40, 40,
        40, 40, 40, 40, 40, 40, 40, 40,
    ];

    const DC_LUM_BITS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
    const DC_LUM_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    const DC_CHR_BITS: [u8; 16] = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
    const DC_CHR_VALS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    const AC_LUM_BITS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125];
    const AC_LUM_VALS: [u8; 162] = [
        0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
        0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
        0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
        0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
        0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
        0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
        0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0xf9, 0xfa,
    ];
    const AC_CHR_BITS: [u8; 16] = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119];
    const AC_CHR_VALS: [u8; 162] = [
        0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
        0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
        0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
        0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
        0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
        0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0xf9, 0xfa,
    ];

    let mut out = Vec::with_capacity(64 * 1024);
    // SOI + APP0 (JFIF 1.1)
    out.extend_from_slice(&[
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00,
    ]);
    // DQT 0 & 1 (zig-zag ordered)
    for (id, q) in [(0u8, &Q_LUMA), (1u8, &Q_CHROMA)] {
        out.extend_from_slice(&[0xFF, 0xDB, 0x00, 67, id]);
        for &idx in &ZIGZAG {
            out.push(q[idx]);
        }
    }
    // SOF0 (8-bit, 3 components, 4:4:4 H1V1)
    out.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 17, 8,
        (height >> 8) as u8, height as u8,
        (width >> 8) as u8, width as u8,
        3,
        1, 0x11, 0,
        2, 0x11, 1,
        3, 0x11, 1,
    ]);
    // DHTs
    write_dht(&mut out, 0x00, &DC_LUM_BITS, &DC_LUM_VALS);
    write_dht(&mut out, 0x10, &AC_LUM_BITS, &AC_LUM_VALS);
    write_dht(&mut out, 0x01, &DC_CHR_BITS, &DC_CHR_VALS);
    write_dht(&mut out, 0x11, &AC_CHR_BITS, &AC_CHR_VALS);
    // SOS
    out.extend_from_slice(&[0xFF, 0xDA, 0x00, 12, 3, 1, 0x00, 2, 0x11, 3, 0x11, 0x00, 63, 0x00]);

    let dc_lum_lut = build_huffman_lut(&DC_LUM_BITS, &DC_LUM_VALS);
    let ac_lum_lut = build_huffman_lut(&AC_LUM_BITS, &AC_LUM_VALS);
    let dc_chr_lut = build_huffman_lut(&DC_CHR_BITS, &DC_CHR_VALS);
    let ac_chr_lut = build_huffman_lut(&AC_CHR_BITS, &AC_CHR_VALS);

    let basis = dct_basis();
    let w = width as usize;
    let h = height as usize;
    let mut bw = JpegBitWriter::new(&mut out);
    let (mut prev_y, mut prev_cb, mut prev_cr) = (0i32, 0i32, 0i32);

    for by in (0..h).step_by(8) {
        for bx in (0..w).step_by(8) {
            let mut y_blk = [0f32; 64];
            let mut cb_blk = [0f32; 64];
            let mut cr_blk = [0f32; 64];
            for dy in 0..8 {
                let sy = (by + dy).min(h - 1);
                for dx in 0..8 {
                    let sx = (bx + dx).min(w - 1);
                    let off = (sy * w + sx) * 3;
                    let r = rgb[off] as f32;
                    let g = rgb[off + 1] as f32;
                    let b = rgb[off + 2] as f32;
                    let idx = dy * 8 + dx;
                    y_blk[idx] = 0.299 * r + 0.587 * g + 0.114 * b - 128.0;
                    cb_blk[idx] = -0.168_736 * r - 0.331_264 * g + 0.5 * b;
                    cr_blk[idx] = 0.5 * r - 0.418_688 * g - 0.081_312 * b;
                }
            }
            prev_y = encode_block(&mut bw, &y_blk, &basis, &Q_LUMA, &ZIGZAG, prev_y, &dc_lum_lut, &ac_lum_lut);
            prev_cb = encode_block(&mut bw, &cb_blk, &basis, &Q_CHROMA, &ZIGZAG, prev_cb, &dc_chr_lut, &ac_chr_lut);
            prev_cr = encode_block(&mut bw, &cr_blk, &basis, &Q_CHROMA, &ZIGZAG, prev_cr, &dc_chr_lut, &ac_chr_lut);
        }
    }
    bw.flush();
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

fn write_dht(out: &mut Vec<u8>, tc_th: u8, bits: &[u8; 16], vals: &[u8]) {
    let len = (2 + 1 + 16 + vals.len()) as u16;
    out.extend_from_slice(&[0xFF, 0xC4]);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(tc_th);
    out.extend_from_slice(bits);
    out.extend_from_slice(vals);
}

fn build_huffman_lut(bits: &[u8; 16], vals: &[u8]) -> [(u16, u8); 256] {
    let mut lut = [(0u16, 0u8); 256];
    let mut code = 0u16;
    let mut idx = 0usize;
    for (i, &count) in bits.iter().enumerate() {
        let len = (i + 1) as u8;
        for _ in 0..count {
            lut[vals[idx] as usize] = (code, len);
            code += 1;
            idx += 1;
        }
        code <<= 1;
    }
    lut
}

fn dct_basis() -> [f32; 64] {
    let mut m = [0f32; 64];
    for u in 0..8 {
        let cu = if u == 0 {
            std::f32::consts::FRAC_1_SQRT_2
        } else {
            1.0
        };
        for x in 0..8 {
            let angle = ((2 * x + 1) * u) as f32 * std::f32::consts::PI / 16.0;
            m[u * 8 + x] = 0.5 * cu * angle.cos();
        }
    }
    m
}

fn fdct_8x8(block: &[f32; 64], basis: &[f32; 64]) -> [f32; 64] {
    let mut tmp = [0f32; 64];
    for row in 0..8 {
        for u in 0..8 {
            let mut sum = 0.0f32;
            for x in 0..8 {
                sum += block[row * 8 + x] * basis[u * 8 + x];
            }
            tmp[row * 8 + u] = sum;
        }
    }
    let mut out = [0f32; 64];
    for col in 0..8 {
        for v in 0..8 {
            let mut sum = 0.0f32;
            for y in 0..8 {
                sum += tmp[y * 8 + col] * basis[v * 8 + y];
            }
            out[v * 8 + col] = sum;
        }
    }
    out
}

fn encode_block(
    bw: &mut JpegBitWriter<'_>,
    block: &[f32; 64],
    basis: &[f32; 64],
    q: &[u8; 64],
    zigzag: &[usize; 64],
    prev_dc: i32,
    dc_lut: &[(u16, u8); 256],
    ac_lut: &[(u16, u8); 256],
) -> i32 {
    let dct = fdct_8x8(block, basis);
    let mut zz = [0i32; 64];
    for k in 0..64 {
        let idx = zigzag[k];
        zz[k] = (dct[idx] / q[idx] as f32).round() as i32;
    }

    let dc = zz[0];
    let diff = dc - prev_dc;
    let (vli_bits, vli_len) = encode_vli(diff);
    let (h_code, h_len) = dc_lut[vli_len as usize];
    bw.write_bits(h_code, h_len);
    if vli_len > 0 {
        bw.write_bits(vli_bits, vli_len);
    }

    let mut zero_run = 0u8;
    for &coeff in &zz[1..] {
        if coeff == 0 {
            zero_run += 1;
        } else {
            while zero_run >= 16 {
                let (zc, zl) = ac_lut[0xF0];
                bw.write_bits(zc, zl);
                zero_run -= 16;
            }
            let (cbits, clen) = encode_vli(coeff);
            let sym = (zero_run << 4) | clen;
            let (hc, hl) = ac_lut[sym as usize];
            bw.write_bits(hc, hl);
            bw.write_bits(cbits, clen);
            zero_run = 0;
        }
    }
    if zero_run > 0 {
        let (ec, el) = ac_lut[0x00];
        bw.write_bits(ec, el);
    }
    dc
}

fn encode_vli(val: i32) -> (u16, u8) {
    if val == 0 {
        return (0, 0);
    }
    let abs = val.unsigned_abs().min(0x7FFF) as u16;
    let len = (16 - abs.leading_zeros()) as u8;
    let bits = if val > 0 {
        abs
    } else {
        abs ^ ((1u16 << len) - 1)
    };
    (bits, len)
}

struct JpegBitWriter<'a> {
    out: &'a mut Vec<u8>,
    buf: u32,
    count: u8,
}

impl<'a> JpegBitWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            out,
            buf: 0,
            count: 0,
        }
    }

    fn write_bits(&mut self, bits: u16, len: u8) {
        self.buf = (self.buf << len) | (bits as u32 & ((1u32 << len) - 1));
        self.count += len;
        while self.count >= 8 {
            self.count -= 8;
            let byte = ((self.buf >> self.count) & 0xFF) as u8;
            self.out.push(byte);
            if byte == 0xFF {
                self.out.push(0x00);
            }
        }
    }

    fn flush(self) {
        if self.count > 0 {
            let pad = 8 - self.count;
            let byte = (((self.buf << pad) | ((1u32 << pad) - 1)) & 0xFF) as u8;
            self.out.push(byte);
            if byte == 0xFF {
                self.out.push(0x00);
            }
        }
    }
}

/// Formats a JPEG frame JSON string with `"type":"frame"` GUARANTEED as the first key.
fn format_ws_frame_json(b64: &str, width: u32, height: u32) -> String {
    format!(
        r#"{{"type":"frame","data":"{b64}","width":{width},"height":{height}}}"#
    )
}

// ---------------------------------------------------------------------------
// REST Router & Handlers
// ---------------------------------------------------------------------------

pub fn router(state: VirtualComputerState) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}",
            get(get_computer),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/wake",
            post(wake_computer),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/control",
            get(get_control),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/control/request",
            post(request_control),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/control/take",
            post(take_control),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/control/release",
            post(release_control),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/control/cancel",
            post(cancel_control),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/screenshot",
            get(get_screenshot),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/page",
            get(get_page_json),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/page-html",
            get(get_page_html),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/proxy",
            get(proxy_entry_redirect),
        )
        .route(
            "/browse/{botId}/{token}/{scheme}/{host}",
            any(proxy_web_root),
        )
        .route(
            "/browse/{botId}/{token}/{scheme}/{host}/",
            any(proxy_web_root),
        )
        .route(
            "/browse/{botId}/{token}/{scheme}/{host}/{*rest}",
            any(proxy_web_rest),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/files/list",
            post(rest_files_list),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/files/read",
            post(rest_files_read),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/files/write",
            post(rest_files_write),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/exec",
            post(rest_exec),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/navigate",
            post(rest_navigate),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/read",
            get(rest_read_page).post(rest_read_page),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/snapshot",
            post(rest_snapshot),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/scroll",
            post(rest_scroll),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/click",
            post(rest_ui_noop),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/type",
            post(rest_ui_noop),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/key",
            post(rest_ui_noop),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/screen",
            get(ws_screen),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{botId}/terminal",
            get(ws_terminal),
        )
        .layer(DefaultBodyLimit::max(512 * 1024))
        .with_state(state)
}

fn problem(status: StatusCode, code: &str, detail: &str) -> Response {
    let category = match status {
        StatusCode::UNAUTHORIZED => "unauthenticated",
        StatusCode::FORBIDDEN => "permission",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::SERVICE_UNAVAILABLE => "dependency",
        _ => "invalid_request",
    };
    let mut r = (
        status,
        Json(json!({
            "type": format!("https://open.bot/errors/{}", code.to_ascii_lowercase().replace('_', "-")),
            "title": detail,
            "status": status.as_u16(),
            "detail": detail,
            "code": code,
            "category": category,
            "retryable": status == StatusCode::SERVICE_UNAVAILABLE,
            "requestId": "unavailable",
            "traceId": "unavailable",
        })),
    )
        .into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}

fn json_ok(status: StatusCode, body: String) -> Response {
    let mut r = (status, body).into_response();
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}

fn format_url_authority(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn build_proxy_url(bot_id: &str, token: &str, raw_url: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    let parsed = reqwest::Url::parse(raw_url.trim()).ok()?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = format_url_authority(&parsed)?;
    let path = parsed.path();
    let query = parsed
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let frag = parsed
        .fragment()
        .map(|f| format!("#{f}"))
        .unwrap_or_default();
    Some(format!(
        "/browse/{bot_id}/{token}/{scheme}/{authority}{path}{query}{frag}"
    ))
}

fn rewrite_proxy_url(raw: &str, base: &reqwest::Url, proxy_prefix: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with("/browse/") {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("javascript:")
        || lower.starts_with("data:")
        || lower.starts_with("blob:")
        || lower.starts_with("mailto:")
        || lower.starts_with("tel:")
        || lower.starts_with("about:")
    {
        return None;
    }
    let resolved = base.join(t).ok()?;
    let scheme = resolved.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = format_url_authority(&resolved)?;
    let query = resolved
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let frag = resolved
        .fragment()
        .map(|f| format!("#{f}"))
        .unwrap_or_default();
    Some(format!(
        "{proxy_prefix}/{scheme}/{authority}{}{query}{frag}",
        resolved.path()
    ))
}

fn rewrite_srcset_value(raw: &str, base: &reqwest::Url, proxy_prefix: &str) -> String {
    let mut parts = Vec::new();
    for item in raw.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut ws_split = trimmed.splitn(2, char::is_whitespace);
        let url_part = ws_split.next().unwrap_or("");
        let desc_part = ws_split.next().map(str::trim).unwrap_or("");
        let rewritten = rewrite_proxy_url(url_part, base, proxy_prefix)
            .unwrap_or_else(|| url_part.to_owned());
        if desc_part.is_empty() {
            parts.push(rewritten);
        } else {
            parts.push(format!("{rewritten} {desc_part}"));
        }
    }
    parts.join(", ")
}

fn rewrite_css_urls(css: &str, base: &reqwest::Url, proxy_prefix: &str) -> String {
    let bytes = css.as_bytes();
    let mut out = String::with_capacity(css.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 4 <= bytes.len() && bytes[i..i + 4].eq_ignore_ascii_case(b"url(") {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            if prev_ok {
                if let Some(close_rel) = bytes[i + 4..].iter().position(|&b| b == b')') {
                    let close_idx = i + 4 + close_rel;
                    let inner = css[i + 4..close_idx].trim();
                    let unquoted = inner
                        .strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .or_else(|| inner.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                        .unwrap_or(inner)
                        .trim();
                    if let Some(rewritten) = rewrite_proxy_url(unquoted, base, proxy_prefix) {
                        out.push_str("url(\"");
                        out.push_str(&rewritten);
                        out.push_str("\")");
                    } else {
                        out.push_str(&css[i..=close_idx]);
                    }
                    i = close_idx + 1;
                    continue;
                }
            }
        }
        if let Some(ch) = css[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn escape_attr_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

fn parse_html_tag_attrs(attr_str: &str) -> Vec<(String, Option<String>)> {
    let mut attrs = Vec::new();
    let bytes = attr_str.as_bytes();
    let len = bytes.len();
    let mut pos = 0usize;
    while pos < len {
        while pos < len && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= len {
            break;
        }
        let name_start = pos;
        while pos < len && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'=' {
            pos += 1;
        }
        let name = attr_str[name_start..pos].to_ascii_lowercase();
        while pos < len && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let val = if pos < len && bytes[pos] == b'=' {
            pos += 1;
            while pos < len && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos >= len {
                Some(String::new())
            } else if bytes[pos] == b'"' || bytes[pos] == b'\'' {
                let q = bytes[pos];
                pos += 1;
                let v_start = pos;
                while pos < len && bytes[pos] != q {
                    pos += 1;
                }
                let raw = decode_entities(&attr_str[v_start..pos]);
                if pos < len {
                    pos += 1;
                }
                Some(raw)
            } else {
                let v_start = pos;
                while pos < len && !bytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
                Some(decode_entities(&attr_str[v_start..pos]))
            }
        } else {
            None
        };
        if !name.is_empty() && name != "/" {
            attrs.push((name, val));
        }
    }
    attrs
}

fn build_proxy_shim_script(proxy_prefix: &str, base: &reqwest::Url, bot_id: &str) -> String {
    let scheme = base.scheme();
    let authority = format_url_authority(base).unwrap_or_default();
    let real_url = base.as_str();
    let js_lit = |v: &str| {
        serde_json::to_string(v)
            .unwrap_or_else(|_| "\"\"".to_owned())
            .replace("</", "<\\/")
    };
    let p_lit = js_lit(proxy_prefix);
    let s_lit = js_lit(scheme);
    let h_lit = js_lit(&authority);
    let r_lit = js_lit(real_url);
    let b_lit = js_lit(bot_id);
    format!(
        "<script data-openbot-proxy=\"1\">(function(){{\
var P={p_lit},S={s_lit},H={h_lit},curReal={r_lit},BID={b_lit};\
try{{if(typeof crypto!==\"undefined\"&&!crypto.randomUUID){{var _ru=function(){{var a=new Uint8Array(16);if(crypto.getRandomValues)crypto.getRandomValues(a);else{{for(var i=0;i<16;i++)a[i]=(Math.random()*256)|0;}}a[6]=(a[6]&15)|64;a[8]=(a[8]&63)|128;var h=\"\";for(var i=0;i<16;i++){{h+=(a[i]<16?\"0\":\"\")+a[i].toString(16);if(i===3||i===5||i===7||i===9)h+=\"-\";}}return h;}};try{{Object.defineProperty(crypto,\"randomUUID\",{{configurable:true,value:_ru}});}}catch(_c1){{try{{Object.defineProperty(Crypto.prototype,\"randomUUID\",{{configurable:true,value:_ru}});}}catch(_c2){{}}}}}}}}catch(_c0){{}}\
try{{void document.cookie;}}catch(_){{\
var _ck=Object.create(null);\
function _getC(){{return Object.keys(_ck).map(function(k){{return k+\"=\"+_ck[k];}}).join(\"; \");}}\
function _setC(v){{var s=String(v||\"\").split(\";\")[0],i=s.indexOf(\"=\");if(i>0){{var k=s.slice(0,i).trim(),val=s.slice(i+1).trim();if(/max-age\\s*=\\s*0/i.test(String(v)))delete _ck[k];else _ck[k]=val;}}}}\
try{{Object.defineProperty(document,\"cookie\",{{configurable:true,get:_getC,set:_setC}});}}catch(_2){{}}\
try{{Object.defineProperty(Document.prototype,\"cookie\",{{configurable:true,get:_getC,set:_setC}});}}catch(_3){{}}\
}}\
function _mkStore(){{var d=Object.create(null);return{{get length(){{return Object.keys(d).length;}},clear:function(){{d=Object.create(null);}},getItem:function(k){{k=String(k);return Object.prototype.hasOwnProperty.call(d,k)?d[k]:null;}},key:function(i){{return Object.keys(d)[i]||null;}},removeItem:function(k){{delete d[String(k)];}},setItem:function(k,v){{d[String(k)]=String(v);}}}};}}\
[\"localStorage\",\"sessionStorage\"].forEach(function(sn){{try{{var st=window[sn];if(st)st.getItem(\"__ob_t\");}}catch(_){{try{{Object.defineProperty(window,sn,{{configurable:true,value:_mkStore()}});}}catch(_2){{}}}}}});\
function toReal(u){{if(!u||typeof u!==\"string\")return curReal;\
if(u.indexOf(P+\"/\")===0){{var r=u.slice(P.length+1),i=r.indexOf(\"/\");if(i>0)return r.slice(0,i)+\"://\"+r.slice(i+1);}}\
try{{if(location.origin&&u.indexOf(location.origin+P+\"/\")===0){{var r2=u.slice((location.origin+P).length+1),j=r2.indexOf(\"/\");if(j>0)return r2.slice(0,j)+\"://\"+r2.slice(j+1);}}\
return new URL(u,curReal).href;}}catch(_){{return curReal;}}}}\
function toProxy(u){{if(typeof u!==\"string\")return u;var t=u.trim();\
if(!t||t[0]===\"#\"||/^(?:data:|blob:|javascript:|mailto:|tel:|about:)/i.test(t)||t.indexOf(P+\"/\")===0)return u;\
try{{if(location.origin&&t.indexOf(location.origin+P+\"/\")===0)return t.slice(location.origin.length);\
var a=new URL(t,curReal);if(a.protocol!==\"http:\"&&a.protocol!==\"https:\")return u;\
return P+\"/\"+a.protocol.slice(0,-1)+\"/\"+a.host+a.pathname+a.search+a.hash;}}catch(_){{return u;}}}}\
function notify(u){{if(u)curReal=toReal(u);\
try{{window.parent.postMessage({{type:\"openbot:browser-nav\",botId:BID,url:curReal,title:document.title||\"\"}},\"*\");}}catch(_){{}}}}\
var of=window.fetch;if(of){{window.fetch=function(inp,ini){{\
var oini=ini?Object.assign({{}},ini):undefined;\
if(oini&&oini.credentials===\"include\")oini.credentials=\"omit\";\
if(typeof inp===\"string\")return of.call(this,toProxy(inp),oini);\
if(inp&&typeof inp===\"object\"&&inp.url){{var px=toProxy(inp.url);if(px!==inp.url||inp.credentials===\"include\"){{try{{var ri={{method:inp.method,headers:inp.headers,mode:inp.mode===\"navigate\"?\"cors\":inp.mode,credentials:\"omit\",redirect:inp.redirect,referrerPolicy:inp.referrerPolicy}};if(inp.body&&inp.method!==\"GET\"&&inp.method!==\"HEAD\"){{ri.body=inp.body;ri.duplex=\"half\";}}inp=new Request(px,ri);}}catch(_){{}}}}}}\
return of.call(this,inp,oini);}};}}\
try{{Object.defineProperty(XMLHttpRequest.prototype,\"withCredentials\",{{configurable:true,get:function(){{return false;}},set:function(){{}}}});}}catch(_){{}}\
var ox=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){{\
var a=Array.prototype.slice.call(arguments);if(typeof u===\"string\")a[1]=toProxy(u);return ox.apply(this,a);}};\
if(navigator.sendBeacon){{var ob=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){{return ob(toProxy(u),d);}};}}\
var oo=window.open;window.open=function(u,tg,ft){{var px=typeof u===\"string\"?toProxy(u):u;if(!tg||tg===\"_top\"||tg===\"_parent\"||tg===\"_blank\")tg=\"_self\";return oo?oo.call(this,px,tg,ft):null;}};\
try{{function wh(obj){{if(!obj)return;var ohp=obj.pushState,ohr=obj.replaceState;\
if(typeof ohp===\"function\")obj.pushState=function(s,ti,u){{if(typeof u===\"string\")curReal=toReal(u);try{{return ohp.call(this,s,ti,typeof u===\"string\"?toProxy(u):u);}}catch(_){{notify(curReal);}}}};\
if(typeof ohr===\"function\")obj.replaceState=function(s,ti,u){{if(typeof u===\"string\")curReal=toReal(u);try{{return ohr.call(this,s,ti,typeof u===\"string\"?toProxy(u):u);}}catch(_){{notify(curReal);}}}};}}\
if(typeof History!==\"undefined\")wh(History.prototype);wh(window.history);}}catch(_){{}}\
var osa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(k,v){{\
var kl=String(k).toLowerCase();\
if((kl===\"src\"||kl===\"href\"||kl===\"action\"||kl===\"poster\")&&typeof v===\"string\")v=toProxy(v);\
else if(kl===\"target\"&&(v===\"_top\"||v===\"_parent\"||v===\"_blank\"))v=\"_self\";\
return osa.call(this,k,v);}};\
function wp(Pr,pr){{try{{var d=Pr&&Object.getOwnPropertyDescriptor(Pr,pr);\
if(d&&d.set&&d.get){{Object.defineProperty(Pr,pr,{{configurable:true,enumerable:true,get:function(){{return d.get.call(this);}},set:function(v){{return d.set.call(this,typeof v===\"string\"?toProxy(v):v);}}}});}}}}catch(_){{}}}}\
wp(typeof HTMLScriptElement!==\"undefined\"&&HTMLScriptElement.prototype,\"src\");\
wp(typeof HTMLImageElement!==\"undefined\"&&HTMLImageElement.prototype,\"src\");\
wp(typeof HTMLLinkElement!==\"undefined\"&&HTMLLinkElement.prototype,\"href\");\
wp(typeof HTMLAnchorElement!==\"undefined\"&&HTMLAnchorElement.prototype,\"href\");\
wp(typeof HTMLFormElement!==\"undefined\"&&HTMLFormElement.prototype,\"action\");\
wp(typeof HTMLMediaElement!==\"undefined\"&&HTMLMediaElement.prototype,\"src\");\
wp(typeof HTMLSourceElement!==\"undefined\"&&HTMLSourceElement.prototype,\"src\");\
wp(typeof HTMLIFrameElement!==\"undefined\"&&HTMLIFrameElement.prototype,\"src\");\
try{{var cwd=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,\"contentWindow\");\
if(cwd&&cwd.get){{Object.defineProperty(HTMLIFrameElement.prototype,\"contentWindow\",{{configurable:true,get:function(){{var cw=cwd.get.call(this);if(!cw)return cw;try{{void cw.history;return cw;}}catch(_){{return new Proxy({{}},{{get:function(_t,p){{if(p===\"history\")return window.history;if(p===\"location\")return window.location;if(p===\"top\")return window.top;if(p===\"parent\")return window;if(p===\"self\"||p===\"window\"||p===\"frames\")return cw;if(p===\"postMessage\")return function(m,o,tr){{return cw.postMessage(m,o,tr);}};try{{var v=cw[p];return typeof v===\"function\"?v.bind(cw):v;}}catch(_e){{return window[p];}}}},has:function(_t,p){{return p===\"history\"||p===\"location\"||(p in window);}}}});}}}}}});}}\
var cdd=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,\"contentDocument\");\
if(cdd&&cdd.get){{Object.defineProperty(HTMLIFrameElement.prototype,\"contentDocument\",{{configurable:true,get:function(){{try{{return cdd.get.call(this);}}catch(_){{return null;}}}}}});}}}}catch(_){{}}\
document.addEventListener(\"click\",function(e){{var a=e.target&&e.target.closest?e.target.closest(\"a[href]\"):null;if(!a)return;\
var h=a.getAttribute(\"href\");if(h)a.setAttribute(\"href\",h);var t=a.getAttribute(\"target\");if(t===\"_top\"||t===\"_parent\"||t===\"_blank\")a.setAttribute(\"target\",\"_self\");}},true);\
document.addEventListener(\"submit\",function(e){{var f=e.target;if(!f||f.tagName!==\"FORM\")return;\
var ac=f.getAttribute(\"action\")||curReal;f.setAttribute(\"action\",ac);var t=f.getAttribute(\"target\");if(t===\"_top\"||t===\"_parent\"||t===\"_blank\")f.setAttribute(\"target\",\"_self\");}},true);\
window.addEventListener(\"DOMContentLoaded\",function(){{notify(curReal);}});\
window.addEventListener(\"load\",function(){{notify(curReal);}});\
window.addEventListener(\"popstate\",function(){{notify(location.href);}});\
window.addEventListener(\"hashchange\",function(){{notify(location.href);}});\
}})();</script>"
    )
}

fn find_tag_close_quote_aware(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => {
                if b == b'"' || b == b'\'' {
                    quote = Some(b);
                } else if b == b'>' {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

fn find_ascii_ci_from(hay: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if start >= hay.len() {
        return None;
    }
    find_ascii_ci(&hay[start..], needle).map(|rel| start + rel)
}

fn rewrite_html_for_proxy(
    html: &str,
    initial_base: &reqwest::Url,
    proxy_prefix: &str,
    bot_id: &str,
) -> String {
    let mut base_url = initial_base.clone();
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(html.len() + 4096);
    let mut shim_injected = false;
    let mut pos = 0usize;

    while pos < len {
        let Some(rel_lt) = bytes[pos..].iter().position(|&b| b == b'<') else {
            out.push_str(&html[pos..]);
            break;
        };
        let lt = pos + rel_lt;
        if lt > pos {
            out.push_str(&html[pos..lt]);
        }
        if lt + 1 >= len {
            out.push_str(&html[lt..]);
            break;
        }
        let after = &bytes[lt + 1..];
        if after.starts_with(b"!--") {
            if let Some(end_rel) = html[lt + 4..].find("-->") {
                let end = lt + 4 + end_rel + 3;
                out.push_str(&html[lt..end]);
                pos = end;
            } else {
                out.push_str(&html[lt..]);
                break;
            }
            continue;
        }
        if after[0] == b'!' || after[0] == b'?' {
            if let Some(gt) = find_tag_close_quote_aware(bytes, lt + 1) {
                out.push_str(&html[lt..=gt]);
                pos = gt + 1;
            } else {
                out.push_str(&html[lt..]);
                break;
            }
            continue;
        }
        let Some(gt) = find_tag_close_quote_aware(bytes, lt + 1) else {
            out.push_str(&html[lt..]);
            break;
        };
        let raw_inside = &html[lt + 1..gt];
        let trimmed_inside = raw_inside.trim();
        if trimmed_inside.starts_with('/') {
            out.push_str(&html[lt..=gt]);
            pos = gt + 1;
            continue;
        }
        let self_closing = trimmed_inside.ends_with('/');
        let without_slash = if self_closing {
            trimmed_inside[..trimmed_inside.len() - 1].trim_end()
        } else {
            trimmed_inside
        };
        let name_end = without_slash
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(without_slash.len());
        let tag_name = without_slash[..name_end].to_ascii_lowercase();
        let attr_str = &without_slash[name_end..];

        if tag_name == "base" {
            for (k, v) in parse_html_tag_attrs(attr_str) {
                if k == "href" {
                    if let Some(h) = v {
                        if let Ok(next_base) = base_url.join(h.trim()) {
                            if next_base.scheme() == "http" || next_base.scheme() == "https" {
                                base_url = next_base;
                            }
                        }
                    }
                }
            }
            pos = gt + 1;
            continue;
        }

        let attrs = parse_html_tag_attrs(attr_str);
        if tag_name == "meta" {
            let is_csp_or_xfo = attrs.iter().any(|(k, v)| {
                k == "http-equiv"
                    && v.as_deref().is_some_and(|hv| {
                        let low = hv.trim().to_ascii_lowercase();
                        low == "content-security-policy"
                            || low == "content-security-policy-report-only"
                            || low == "x-frame-options"
                    })
            });
            if is_csp_or_xfo {
                pos = gt + 1;
                continue;
            }
        } else if tag_name == "link" {
            let is_shared_dict = attrs.iter().any(|(k, v)| {
                k == "rel"
                    && v.as_deref().is_some_and(|rv| {
                        rv.split_ascii_whitespace()
                            .any(|tok| tok.eq_ignore_ascii_case("compression-dictionary"))
                    })
            });
            if is_shared_dict {
                pos = gt + 1;
                continue;
            }
        }

        let is_refresh = tag_name == "meta"
            && attrs.iter().any(|(k, v)| {
                k == "http-equiv"
                    && v.as_deref()
                        .is_some_and(|hv| hv.trim().eq_ignore_ascii_case("refresh"))
            });

        out.push('<');
        out.push_str(&tag_name);
        for (k, v_opt) in attrs {
            if k == "integrity" || k == "nonce" || k == "crossorigin" {
                continue;
            }
            match v_opt {
                None => {
                    out.push(' ');
                    out.push_str(&k);
                }
                Some(v) => {
                    let final_v = if is_refresh && k == "content" {
                        if let Some(idx) = v.to_ascii_lowercase().find("url=") {
                            let prefix = &v[..idx + 4];
                            let raw_u = v[idx + 4..].trim().trim_matches(['"', '\'']);
                            rewrite_proxy_url(raw_u, &base_url, proxy_prefix)
                                .map(|ru| format!("{prefix}{ru}"))
                                .unwrap_or(v)
                        } else {
                            v
                        }
                    } else if matches!(
                        k.as_str(),
                        "href"
                            | "src"
                            | "action"
                            | "poster"
                            | "data-src"
                            | "data"
                            | "formaction"
                            | "background"
                    ) {
                        rewrite_proxy_url(&v, &base_url, proxy_prefix).unwrap_or(v)
                    } else if k == "srcset" {
                        rewrite_srcset_value(&v, &base_url, proxy_prefix)
                    } else if k == "target" && matches!(v.trim(), "_top" | "_parent" | "_blank") {
                        "_self".to_owned()
                    } else {
                        v
                    };
                    out.push(' ');
                    out.push_str(&k);
                    out.push_str("=\"");
                    out.push_str(&escape_attr_value(&final_v));
                    out.push('"');
                }
            }
        }
        if self_closing {
            out.push('/');
        }
        out.push('>');
        pos = gt + 1;

        if !shim_injected && tag_name == "head" {
            out.push_str(&build_proxy_shim_script(proxy_prefix, &base_url, bot_id));
            shim_injected = true;
        }

        if tag_name == "script" && !self_closing {
            if let Some(close_start) = find_ascii_ci_from(bytes, b"</script", pos) {
                let close_gt = find_tag_close_quote_aware(bytes, close_start).unwrap_or(len - 1);
                out.push_str(&html[pos..=close_gt]);
                pos = close_gt + 1;
            }
        } else if tag_name == "style" && !self_closing {
            if let Some(close_start) = find_ascii_ci_from(bytes, b"</style", pos) {
                let close_gt = find_tag_close_quote_aware(bytes, close_start).unwrap_or(len - 1);
                let css_inner = &html[pos..close_start];
                out.push_str(&rewrite_css_urls(css_inner, &base_url, proxy_prefix));
                out.push_str(&html[close_start..=close_gt]);
                pos = close_gt + 1;
            }
        }
    }

    if !shim_injected {
        let shim = build_proxy_shim_script(proxy_prefix, &base_url, bot_id);
        return format!("{shim}{out}");
    }
    out
}

#[derive(Deserialize)]
struct ProxyEntryQuery {
    url: Option<String>,
}

async fn proxy_entry_redirect(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    Query(q): Query<ProxyEntryQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, false).await {
        return e;
    }
    let Some(raw_url) = q.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Missing url query parameter.");
    };
    let allow_all = true;
    let parsed = match validate_fetch_url_with_policy(raw_url, allow_all) {
        Ok(u) => u,
        Err(msg) => return problem(StatusCode::BAD_REQUEST, "INVALID_URL", &msg),
    };
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let proxy_token = {
        let Ok(mut guard) = handle.lock() else {
            return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
        };
        guard.allow_all_web_pages = true;
        guard.proxy_token.clone()
    };
    let Some(location) = build_proxy_url(&bot_id, &proxy_token, parsed.as_str()) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_URL", "Unsupported URL.");
    };
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::FOUND;
    if let Ok(hv) = HeaderValue::from_str(&location) {
        r.headers_mut().insert(header::LOCATION, hv);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    r
}

async fn proxy_web_root(
    State(s): State<VirtualComputerState>,
    Path((bot_id, token, scheme, host)): Path<(String, String, String, String)>,
    req: Request,
) -> Response {
    handle_proxy_web(s, bot_id, token, scheme, host, req).await
}

async fn proxy_web_rest(
    State(s): State<VirtualComputerState>,
    Path((bot_id, token, scheme, host, _rest)): Path<(String, String, String, String, String)>,
    req: Request,
) -> Response {
    handle_proxy_web(s, bot_id, token, scheme, host, req).await
}

async fn handle_proxy_web(
    s: VirtualComputerState,
    bot_id: String,
    token: String,
    scheme: String,
    host: String,
    req: Request,
) -> Response {
    let mut r = handle_proxy_web_inner(s, bot_id, token, scheme, host, req).await;
    if !r.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
        r.headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    }
    r
}

async fn handle_proxy_web_inner(
    s: VirtualComputerState,
    bot_id: String,
    token: String,
    scheme: String,
    host: String,
    req: Request,
) -> Response {
    if validate_bot_id(&bot_id).is_err() || (scheme != "http" && scheme != "https") {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid proxy target.");
    }
    let handle = match s.bot_handle(&bot_id) {
        Ok(h) => h,
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable."),
    };
    let (expected_token, allow_private) = {
        let Ok(guard) = handle.lock() else {
            return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
        };
        (
            guard.proxy_token.clone(),
            guard.allow_all_web_pages || allow_all_web_pages_from_env(),
        )
    };
    let token_ok = token.len() == expected_token.len()
        && bool::from(token.as_bytes().ct_eq(expected_token.as_bytes()));
    if !token_ok {
        return problem(StatusCode::FORBIDDEN, "FORBIDDEN", "Invalid proxy token.");
    }

    if req.method() == Method::OPTIONS {
        let req_hdrs = req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .unwrap_or("*");
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NO_CONTENT;
        r.headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        r.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"),
        );
        if let Ok(hv) = HeaderValue::from_str(req_hdrs) {
            r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_HEADERS, hv);
        }
        r.headers_mut()
            .insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
        return r;
    }

    let prefix_head = format!("/browse/{bot_id}/{token}/{scheme}/{host}");
    let uri_path = req.uri().path().to_owned();
    let suffix_path = uri_path
        .strip_prefix(&prefix_head)
        .filter(|s| !s.is_empty())
        .unwrap_or("/");
    let query_part = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target_raw = format!("{scheme}://{host}{suffix_path}{query_part}");
    let url = match validate_fetch_url_with_policy(&target_raw, allow_private) {
        Ok(u) => u,
        Err(msg) => return problem(StatusCode::BAD_REQUEST, "INVALID_URL", &msg),
    };
    let client = match s.pooled_client_for_url(&url, allow_private, true).await {
        Ok(c) => c,
        Err(msg) => return problem(StatusCode::BAD_GATEWAY, "UPSTREAM_RESOLUTION_FAILED", &msg),
    };

    let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return problem(StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED", "Unsupported method."),
    };
    let (ref_scheme, ref_host, ref_path) =
        parse_browse_referer(req.headers(), &bot_id, &token)
            .unwrap_or_else(|| (scheme.clone(), host.clone(), "/".to_owned()));
    let has_incoming_origin = req.headers().contains_key(header::ORIGIN);
    let send_origin = has_incoming_origin
        || matches!(
            method,
            reqwest::Method::POST
                | reqwest::Method::PUT
                | reqwest::Method::PATCH
                | reqwest::Method::DELETE
        );

    let mut forwarded_headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)> =
        Vec::new();
    for (name, val) in req.headers().iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "cookie"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
                | "accept-encoding"
                | "origin"
                | "referer"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "idempotency-key"
        ) || lower.starts_with("sec-")
            || lower.starts_with("proxy-")
            || lower.starts_with("x-forwarded-")
        {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(val.as_bytes()),
        ) {
            forwarded_headers.push((hn, hv));
        }
    }

    let cookie_header = {
        let target_dom = url.host_str().unwrap_or(&host).to_ascii_lowercase();
        handle
            .lock()
            .ok()
            .and_then(|g| build_proxy_cookie_header(&g.cookie_jar, &target_dom))
    };

    let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return problem(StatusCode::PAYLOAD_TOO_LARGE, "BODY_TOO_LARGE", "Request body too large."),
    };

    let mut req_builder = client
        .request(method, url.clone())
        .header(reqwest::header::USER_AGENT, CHROME_USER_AGENT)
        .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(
            reqwest::header::REFERER,
            format!("{ref_scheme}://{ref_host}{ref_path}"),
        );
    if send_origin {
        req_builder = req_builder.header(
            reqwest::header::ORIGIN,
            format!("{ref_scheme}://{ref_host}"),
        );
    }
    if let Some(ck) = cookie_header {
        req_builder = req_builder.header(reqwest::header::COOKIE, ck);
    }
    for (hn, hv) in forwarded_headers {
        req_builder = req_builder.header(hn, hv);
    }
    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes.to_vec());
    }

    let mut resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return problem(
                StatusCode::BAD_GATEWAY,
                "UPSTREAM_FETCH_FAILED",
                &format!("Failed to load page: {e}"),
            );
        }
    };

    let proxy_prefix = format!("/browse/{bot_id}/{token}");
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = resp.headers().clone();

    {
        let target_dom = url.host_str().unwrap_or(&host).to_ascii_lowercase();
        if let Ok(mut guard) = handle.lock() {
            store_proxy_cookies(&mut guard.cookie_jar, &target_dom, &resp_headers);
        }
    }

    if status.is_redirection() {
        if let Some(loc_val) = resp_headers
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(next_url) = url.join(loc_val) {
                if validate_fetch_url_with_policy(next_url.as_str(), allow_private).is_ok() {
                    if let Some(rewritten_loc) = build_proxy_url(&bot_id, &token, next_url.as_str()) {
                        let mut r = Response::new(Body::empty());
                        *r.status_mut() = status;
                        if let Ok(hv) = HeaderValue::from_str(&rewritten_loc) {
                            r.headers_mut().insert(header::LOCATION, hv);
                        }
                        r.headers_mut()
                            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
                        r.headers_mut()
                            .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("*"));
                        r.headers_mut()
                            .insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
                        r.headers_mut().insert(
                            header::CACHE_CONTROL,
                            HeaderValue::from_static("private, no-store"),
                        );
                        return r;
                    }
                }
            }
        }
    }

    let content_type = resp_headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let is_html = mime == "text/html" || mime == "application/xhtml+xml";
    let is_css = mime == "text/css";

    let mut r = if is_html || is_css {
        let mut raw = Vec::with_capacity(16 * 1024);
        while let Ok(Some(chunk)) = resp.chunk().await {
            let avail = MAX_PROXY_BYTES.saturating_sub(raw.len());
            if avail == 0 {
                break;
            }
            let take = chunk.len().min(avail);
            raw.extend_from_slice(&chunk[..take]);
            if take < chunk.len() {
                break;
            }
        }
        let final_body: Vec<u8> = if is_html {
            let text = String::from_utf8_lossy(&raw);
            rewrite_html_for_proxy(&text, &url, &proxy_prefix, &bot_id).into_bytes()
        } else {
            let text = String::from_utf8_lossy(&raw);
            rewrite_css_urls(&text, &url, &proxy_prefix).into_bytes()
        };
        Response::new(Body::from(final_body))
    } else {
        // Stream scripts, media, and large bundles directly without truncation or RAM buffering.
        Response::new(Body::from_stream(resp.bytes_stream()))
    };
    *r.status_mut() = status;

    apply_proxy_response_headers(
        &mut r,
        &resp_headers,
        &proxy_prefix,
        &scheme,
        &host,
        is_html,
        &content_type,
    );
    r
}

fn apply_proxy_response_headers(
    r: &mut Response,
    resp_headers: &reqwest::header::HeaderMap,
    proxy_prefix: &str,
    scheme: &str,
    host: &str,
    is_html: bool,
    content_type: &str,
) {
    if is_html {
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    } else if !content_type.is_empty() {
        if let Ok(hv) = HeaderValue::from_str(content_type) {
            r.headers_mut().insert(header::CONTENT_TYPE, hv);
        }
    }

    let mut exposed_names: Vec<String> = vec![
        "x-sg-cs".to_owned(),
        "x-sorry-redirect".to_owned(),
    ];
    for (name, val) in resp_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "set-cookie"
                | "set-cookie2"
                | "content-security-policy"
                | "content-security-policy-report-only"
                | "x-frame-options"
                | "cross-origin-embedder-policy"
                | "cross-origin-opener-policy"
                | "cross-origin-resource-policy"
                | "link"
                | "use-as-dictionary"
                | "available-dictionary"
                | "dictionary-id"
                | "content-length"
                | "transfer-encoding"
                | "content-encoding"
                | "connection"
                | "keep-alive"
                | "upgrade"
                | "alt-svc"
                | "alt-used"
                | "strict-transport-security"
                | "access-control-allow-origin"
                | "access-control-expose-headers"
        ) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            axum::http::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(val.as_bytes()),
        ) {
            if lower != "content-type" && lower != "cache-control" {
                r.headers_mut().append(hn, hv);
            }
            if !exposed_names.iter().any(|existing| existing == &lower) {
                exposed_names.push(lower);
            }
        }
    }

    let scoped_cookie_path = format!("{proxy_prefix}/{scheme}/{host}/");
    for cookie_hdr in resp_headers.get_all(reqwest::header::SET_COOKIE) {
        if let Ok(raw_cookie) = cookie_hdr.to_str() {
            let name_lower = raw_cookie
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if name_lower == "openbot_session" || name_lower.is_empty() {
                continue;
            }
            let mut kept_parts = Vec::new();
            for (idx, part) in raw_cookie.split(';').enumerate() {
                let pt = part.trim();
                if idx == 0 {
                    kept_parts.push(pt.to_owned());
                    continue;
                }
                let p_low = pt.to_ascii_lowercase();
                if p_low == "secure"
                    || p_low.starts_with("domain=")
                    || p_low.starts_with("path=")
                    || p_low.starts_with("samesite=")
                {
                    continue;
                }
                kept_parts.push(pt.to_owned());
            }
            kept_parts.push(format!("Path={scoped_cookie_path}"));
            if let Ok(hv) = HeaderValue::from_str(&kept_parts.join("; ")) {
                r.headers_mut().append(header::SET_COOKIE, hv);
            }
        }
    }

    r.headers_mut()
        .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN"));
    r.headers_mut()
        .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    if !exposed_names.is_empty() {
        exposed_names.push("*".to_owned());
        if let Ok(hv) = HeaderValue::from_str(&exposed_names.join(", ")) {
            r.headers_mut().insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, hv);
        } else {
            r.headers_mut()
                .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("*"));
        }
    } else {
        r.headers_mut()
            .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("*"));
    }
    r.headers_mut()
        .insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    if is_html {
        r.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }
}

fn parse_browse_referer(
    headers: &HeaderMap,
    expected_bot_id: &str,
    expected_token: &str,
) -> Option<(String, String, String)> {
    let raw_ref = headers.get(header::REFERER)?.to_str().ok()?;
    let needle = format!("/browse/{expected_bot_id}/{expected_token}/");
    let pos = raw_ref.find(&needle)?;
    let rest = &raw_ref[pos + needle.len()..];
    let mut parts = rest.splitn(3, '/');
    let scheme = parts.next()?.trim();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = parts.next()?.trim();
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    let tail = parts
        .next()
        .map(|p| format!("/{p}"))
        .unwrap_or_else(|| "/".to_owned());
    Some((scheme.to_owned(), host.to_owned(), tail))
}

fn cookie_domain_matches(target_host: &str, cookie_domain: &str) -> bool {
    target_host == cookie_domain || target_host.ends_with(&format!(".{cookie_domain}"))
}

fn store_proxy_cookies(
    jar: &mut HashMap<(String, String), String>,
    target_host: &str,
    resp_headers: &reqwest::header::HeaderMap,
) {
    for cookie_hdr in resp_headers.get_all(reqwest::header::SET_COOKIE) {
        let Ok(raw_cookie) = cookie_hdr.to_str() else {
            continue;
        };
        let mut parts = raw_cookie.split(';');
        let Some(kv) = parts.next() else {
            continue;
        };
        let Some((name_raw, val_raw)) = kv.split_once('=') else {
            continue;
        };
        let name = name_raw.trim();
        if name.is_empty() || name.eq_ignore_ascii_case("openbot_session") {
            continue;
        }
        let mut domain = target_host.to_ascii_lowercase();
        let mut expired = false;
        for attr in parts {
            let trimmed = attr.trim();
            let low = trimmed.to_ascii_lowercase();
            if let Some(d) = low.strip_prefix("domain=") {
                let d_clean = d.trim().trim_start_matches('.');
                if !d_clean.is_empty()
                    && d_clean.contains('.')
                    && cookie_domain_matches(target_host, d_clean)
                {
                    domain = d_clean.to_owned();
                }
            } else if let Some(ma) = low.strip_prefix("max-age=") {
                if ma.trim().parse::<i64>().is_ok_and(|n| n <= 0) {
                    expired = true;
                }
            }
        }
        let key = (domain, name.to_owned());
        if expired {
            jar.remove(&key);
        } else {
            if jar.len() >= 256 && !jar.contains_key(&key) {
                if let Some(oldest_k) = jar.keys().next().cloned() {
                    jar.remove(&oldest_k);
                }
            }
            jar.insert(key, val_raw.trim().to_owned());
        }
    }
}

fn build_proxy_cookie_header(
    jar: &HashMap<(String, String), String>,
    target_host: &str,
) -> Option<String> {
    let mut pairs = Vec::new();
    for ((dom, name), val) in jar {
        if cookie_domain_matches(target_host, dom) {
            pairs.push(format!("{name}={val}"));
        }
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.join("; "))
    }
}

async fn authorize_computer(
    state: &VirtualComputerState,
    headers: &HeaderMap,
    org: &str,
    bot_id: &str,
    require_origin: bool,
) -> Result<Identity, Response> {
    if require_origin && !state.inner.auth.valid_origin(headers).await {
        return Err(problem(StatusCode::FORBIDDEN, "FORBIDDEN", "Forbidden."));
    }
    let actor = match local_auth::identity(&state.inner.auth, headers).await {
        Ok(Some(i)) if i.organization == org || i.slug == org => i,
        Ok(Some(_)) => {
            return Err(problem(
                StatusCode::NOT_FOUND,
                "ORGANIZATION_NOT_FOUND",
                "Organization not found.",
            ))
        }
        Ok(None) => {
            return Err(problem(
                StatusCode::UNAUTHORIZED,
                "UNAUTHENTICATED",
                "Sign in required.",
            ))
        }
        Err(_) => {
            return Err(problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Service unavailable.",
            ))
        }
    };
    match state
        .verify_bot_owner(&actor.organization, &actor.id, bot_id)
        .await
    {
        Ok(true) => Ok(actor),
        Ok(false) => Err(problem(
            StatusCode::NOT_FOUND,
            "BOT_NOT_FOUND",
            "There is no such Bot.",
        )),
        Err(_) => Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Service unavailable.",
        )),
    }
}

fn require_idempotency_key(headers: &HeaderMap) -> Result<String, Response> {
    let mut keys = headers.get_all("idempotency-key").iter();
    match (keys.next(), keys.next()) {
        (Some(v), None) => match v.to_str() {
            Ok(s) if !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control) => {
                Ok(s.to_owned())
            }
            _ => Err(problem(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Invalid Idempotency-Key.",
            )),
        },
        _ => Err(problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Idempotency-Key required.",
        )),
    }
}

fn check_idempotency(
    state: &VirtualComputerState,
    actor: &Identity,
    bot_id: &str,
    op: &str,
    key: &str,
    fingerprint: [u8; 32],
) -> Result<Option<Response>, Response> {
    let store = state
        .inner
        .idempotency
        .lock()
        .map_err(|_| problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable."))?;
    if let Some(rec) = store.iter().find(|r| {
        r.actor_id == actor.id
            && r.org_id == actor.organization
            && r.bot_id == bot_id
            && r.op == op
            && r.key == key
    }) {
        if rec.fingerprint != fingerprint {
            return Err(problem(
                StatusCode::CONFLICT,
                "IDEMPOTENCY_KEY_CONFLICT",
                "That Idempotency-Key was used for a different request.",
            ));
        }
        return Ok(Some(json_ok(rec.status, rec.body.clone())));
    }
    Ok(None)
}

fn store_idempotency(
    state: &VirtualComputerState,
    actor: &Identity,
    bot_id: &str,
    op: &str,
    key: String,
    fingerprint: [u8; 32],
    status: StatusCode,
    body: String,
) {
    if let Ok(mut store) = state.inner.idempotency.lock() {
        if store.len() >= MAX_IDEMPOTENCY_ENTRIES {
            store.pop_front();
        }
        store.push_back(IdempotencyRecord {
            actor_id: actor.id.clone(),
            org_id: actor.organization.clone(),
            bot_id: bot_id.to_owned(),
            op: op.to_owned(),
            key,
            fingerprint,
            status,
            body,
        });
    }
}

async fn get_computer(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, false).await {
        return e;
    }
    json_ok(
        StatusCode::OK,
        json!({ "botId": bot_id, "state": "ready", "reason": null }).to_string(),
    )
}

async fn run_rest_tool(
    s: &VirtualComputerState,
    headers: &HeaderMap,
    org: &str,
    bot_id: &str,
    tool_name: &str,
    args: Value,
    check_pending_approval: bool,
    allow_human_control: bool,
) -> Response {
    let actor = match authorize_computer(s, headers, org, bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    if check_pending_approval {
        let org_c = actor.organization.clone();
        let act_c = actor.id.clone();
        let bot_c = bot_id.to_owned();
        let tool_c = tool_name.to_owned();
        let pending = s.inner.auth.db.try_with_connection(|c| {
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM port_approvals WHERE organization_id=?1 AND actor_id=?2 AND bot_id=?3 AND tool_ref=?4 AND status='pending')",
                params![org_c, act_c, bot_c, tool_c],
                |r| r.get(0),
            )?;
            Ok(exists)
        });
        if matches!(pending, Ok(true)) {
            return json_ok(
                StatusCode::OK,
                json!({ "ok": false, "waiting": true, "needsConversation": true }).to_string(),
            );
        }
    }
    let org_for_mode = actor.organization.clone();
    let allow_turbo_web = if matches!(tool_name, "computer_web_fetch" | "computer_navigate") {
        s.inner
            .auth
            .db
            .try_with_connection(|c| {
                let mode: Option<String> = rusqlite::OptionalExtension::optional(c.query_row(
                    "SELECT execution_mode FROM port_approval_settings WHERE organization_id=?1",
                    params![org_for_mode],
                    |r| r.get(0),
                ))?;
                Ok(mode.as_deref() == Some("turbo"))
            })
            .unwrap_or(false)
    } else {
        false
    };
    match s
        .execute_tool_for_owner_with_control(
            &actor.organization,
            &actor.id,
            bot_id,
            tool_name,
            args,
            allow_human_control,
            allow_turbo_web,
        )
        .await
    {
        Ok(mut val) => {
            if let Some(obj) = val.as_object_mut() {
                obj.entry("ok".to_owned()).or_insert_with(|| json!(true));
            }
            json_ok(StatusCode::OK, val.to_string())
        }
        Err(err) => {
            if err.contains("driving this computer") {
                return problem(StatusCode::CONFLICT, "HUMAN_IN_CONTROL", &err);
            }
            json_ok(StatusCode::OK, json!({ "ok": false, "error": err }).to_string())
        }
    }
}

async fn rest_files_list(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    run_rest_tool(&s, &headers, &org, &bot_id, "computer_list_files", body, false, false).await
}

async fn rest_files_read(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    run_rest_tool(&s, &headers, &org, &bot_id, "computer_read_file", body, false, false).await
}

async fn rest_files_write(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    run_rest_tool(&s, &headers, &org, &bot_id, "computer_write_file", body, true, false).await
}

async fn rest_exec(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    run_rest_tool(&s, &headers, &org, &bot_id, "computer_run_command", body, true, false).await
}

async fn rest_navigate(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    run_rest_tool(&s, &headers, &org, &bot_id, "computer_web_fetch", body, false, true).await
}

async fn rest_read_page(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, false).await {
        return e;
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Ok(guard) = handle.lock() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    json_ok(
        StatusCode::OK,
        json!({
            "ok": true,
            "url": guard.current_url,
            "title": guard.page_title,
            "text": guard.page_text,
        })
        .to_string(),
    )
}

async fn rest_snapshot(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, true).await {
        return e;
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Ok(guard) = handle.lock() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    json_ok(
        StatusCode::OK,
        json!({
            "ok": true,
            "snapshotId": format!("snap_{}", guard.screen_revision),
            "url": guard.current_url,
            "title": guard.page_title,
            "text": guard.page_text,
            "elements": [],
        })
        .to_string(),
    )
}

async fn rest_scroll(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, true).await {
        return e;
    }
    json_ok(StatusCode::OK, json!({ "ok": true }).to_string())
}

async fn rest_ui_noop(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, true).await {
        return e;
    }
    json_ok(StatusCode::OK, json!({ "ok": true }).to_string())
}

async fn wake_computer(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let actor = match authorize_computer(&s, &headers, &org, &bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let key = match require_idempotency_key(&headers) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let fp: [u8; 32] = Sha256::digest(format!("wake:{bot_id}").as_bytes()).into();
    match check_idempotency(&s, &actor, &bot_id, "wake", &key, fp) {
        Ok(Some(r)) => return r,
        Ok(None) => {}
        Err(e) => return e,
    }
    if s.workspace_for_verified_bot(&bot_id).is_err() || s.bot_handle(&bot_id).is_err() {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "Unable to start virtual workspace.",
        );
    }
    let body = json!({ "botId": bot_id, "state": "ready" }).to_string();
    store_idempotency(&s, &actor, &bot_id, "wake", key, fp, StatusCode::OK, body.clone());
    json_ok(StatusCode::OK, body)
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlQuery {
    request_id: Option<String>,
}

async fn get_control(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    Query(q): Query<ControlQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, false).await {
        return e;
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Ok(guard) = handle.lock() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    if let Some(req_id) = &q.request_id {
        if guard.active_request.as_ref().is_none_or(|r| &r.id != req_id) {
            return problem(
                StatusCode::NOT_FOUND,
                "CONTROL_REQUEST_NOT_FOUND",
                "There is no such request.",
            );
        }
    }
    json_ok(StatusCode::OK, guard.control_json().to_string())
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlAskBody {
    reason: Option<String>,
    tool_call_id: Option<String>,
    source: Option<String>,
}

async fn request_control(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<ControlAskBody>,
) -> Response {
    let actor = match authorize_computer(&s, &headers, &org, &bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let key = match require_idempotency_key(&headers) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let source = input.source.unwrap_or_else(|| "manual".to_owned());
    if !matches!(source.as_str(), "model" | "manual") {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid control source.");
    }
    let reason = input
        .reason
        .unwrap_or_else(|| "Take control of the computer.".to_owned());
    let fp: [u8; 32] = Sha256::digest(
        format!("req:{bot_id}:{source}:{reason}:{:?}", input.tool_call_id).as_bytes(),
    )
    .into();
    match check_idempotency(&s, &actor, &bot_id, "control_request", &key, fp) {
        Ok(Some(r)) => return r,
        Ok(None) => {}
        Err(e) => return e,
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Ok(mut guard) = handle.lock() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    if guard.holder == ControlHolder::Human
        || guard
            .active_request
            .as_ref()
            .is_some_and(|r| r.status == "waiting" || r.status == "taken")
    {
        return problem(
            StatusCode::CONFLICT,
            "CONTROL_REQUEST_CONFLICT",
            "A control request is already active.",
        );
    }
    let now = now_iso();
    guard.active_request = Some(ControlRequestState {
        id: random_uuid_like(),
        tool_call_id: input.tool_call_id,
        reason,
        source,
        status: "waiting".to_owned(),
        created_at: now.clone(),
        updated_at: now,
    });
    let body = guard.control_json().to_string();
    drop(guard);
    store_idempotency(
        &s,
        &actor,
        &bot_id,
        "control_request",
        key,
        fp,
        StatusCode::OK,
        body.clone(),
    );
    json_ok(StatusCode::OK, body)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlRefBody {
    request_id: String,
}

async fn take_control(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<ControlRefBody>,
) -> Response {
    let actor = match authorize_computer(&s, &headers, &org, &bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let key = match require_idempotency_key(&headers) {
        Ok(k) => k,
        Err(e) => return e,
    };
    if input.request_id.trim().is_empty() || input.request_id.len() > 200 {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid requestId.");
    }
    let fp: [u8; 32] =
        Sha256::digest(format!("take:{bot_id}:{}", input.request_id).as_bytes()).into();
    match check_idempotency(&s, &actor, &bot_id, "control_take", &key, fp) {
        Ok(Some(r)) => return r,
        Ok(None) => {}
        Err(e) => return e,
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Ok(mut guard) = handle.lock() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Some(req) = guard.active_request.as_mut() else {
        return problem(
            StatusCode::NOT_FOUND,
            "CONTROL_REQUEST_NOT_FOUND",
            "There is no such request.",
        );
    };
    if req.id != input.request_id {
        return problem(
            StatusCode::NOT_FOUND,
            "CONTROL_REQUEST_NOT_FOUND",
            "There is no such request.",
        );
    }
    if req.status != "waiting" {
        return problem(
            StatusCode::CONFLICT,
            "CONTROL_REQUEST_CONFLICT",
            "That request has already ended.",
        );
    }
    let now = now_iso();
    req.status = "taken".to_owned();
    req.updated_at = now.clone();
    guard.holder = ControlHolder::Human;
    guard.held_by = Some(actor.id.clone());
    guard.since = now;
    guard.bump_screen();
    let body = guard.control_json().to_string();
    drop(guard);
    store_idempotency(
        &s,
        &actor,
        &bot_id,
        "control_take",
        key,
        fp,
        StatusCode::OK,
        body.clone(),
    );
    json_ok(StatusCode::OK, body)
}

async fn release_control(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<ControlRefBody>,
) -> Response {
    let actor = match authorize_computer(&s, &headers, &org, &bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let key = match require_idempotency_key(&headers) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let fp: [u8; 32] =
        Sha256::digest(format!("release:{bot_id}:{}", input.request_id).as_bytes()).into();
    match check_idempotency(&s, &actor, &bot_id, "control_release", &key, fp) {
        Ok(Some(r)) => return r,
        Ok(None) => {}
        Err(e) => return e,
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Ok(mut guard) = handle.lock() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let held_by_actor = guard.held_by.as_deref() == Some(actor.id.as_str());
    let Some(req) = guard.active_request.as_mut() else {
        return problem(
            StatusCode::NOT_FOUND,
            "CONTROL_REQUEST_NOT_FOUND",
            "There is no such request.",
        );
    };
    if req.id != input.request_id {
        return problem(
            StatusCode::NOT_FOUND,
            "CONTROL_REQUEST_NOT_FOUND",
            "There is no such request.",
        );
    }
    if req.status != "taken" || !held_by_actor {
        return problem(
            StatusCode::CONFLICT,
            "CONTROL_REQUEST_CONFLICT",
            "That control request can't do this now.",
        );
    }
    let now = now_iso();
    req.status = "completed".to_owned();
    req.updated_at = now.clone();
    guard.holder = ControlHolder::Bot;
    guard.held_by = None;
    guard.since = now;
    guard.bump_screen();
    let body = guard.control_json().to_string();
    drop(guard);
    store_idempotency(
        &s,
        &actor,
        &bot_id,
        "control_release",
        key,
        fp,
        StatusCode::OK,
        body.clone(),
    );
    json_ok(StatusCode::OK, body)
}

async fn cancel_control(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<ControlRefBody>,
) -> Response {
    let actor = match authorize_computer(&s, &headers, &org, &bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let key = match require_idempotency_key(&headers) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let fp: [u8; 32] =
        Sha256::digest(format!("cancel:{bot_id}:{}", input.request_id).as_bytes()).into();
    match check_idempotency(&s, &actor, &bot_id, "control_cancel", &key, fp) {
        Ok(Some(r)) => return r,
        Ok(None) => {}
        Err(e) => return e,
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Ok(mut guard) = handle.lock() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let Some(req) = guard.active_request.as_mut() else {
        return problem(
            StatusCode::NOT_FOUND,
            "CONTROL_REQUEST_NOT_FOUND",
            "There is no such request.",
        );
    };
    if req.id != input.request_id {
        return problem(
            StatusCode::NOT_FOUND,
            "CONTROL_REQUEST_NOT_FOUND",
            "There is no such request.",
        );
    }
    if req.status != "waiting" {
        return problem(
            StatusCode::CONFLICT,
            "CONTROL_REQUEST_CONFLICT",
            "That request has already ended.",
        );
    }
    let now = now_iso();
    req.status = "cancelled".to_owned();
    req.updated_at = now;
    let body = guard.control_json().to_string();
    drop(guard);
    store_idempotency(
        &s,
        &actor,
        &bot_id,
        "control_cancel",
        key,
        fp,
        StatusCode::OK,
        body.clone(),
    );
    json_ok(StatusCode::OK, body)
}

async fn get_page_json(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, false).await {
        return e;
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let snap = {
        let Ok(guard) = handle.lock() else {
            return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
        };
        guard.snapshot()
    };
    let proxy_url = build_proxy_url(&snap.bot_id, &snap.proxy_token, &snap.current_url);
    let mode = if snap.bridge_png.is_some() {
        "bridge"
    } else if proxy_url.is_some() || !snap.page_html.is_empty() {
        "html-preview"
    } else {
        "reader"
    };
    let mut payload = json!({
        "ok": true,
        "url": snap.current_url,
        "title": snap.page_title,
        "text": snap.page_text,
        "html": snap.page_html,
        "revision": snap.revision,
        "mode": mode,
    });
    if let Some(pu) = proxy_url {
        payload
            .as_object_mut()
            .unwrap()
            .insert("proxyUrl".to_owned(), Value::String(pu));
    }
    json_ok(StatusCode::OK, payload.to_string())
}

async fn get_page_html(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, false).await {
        return e;
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let snap = {
        let Ok(guard) = handle.lock() else {
            return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
        };
        guard.snapshot()
    };
    let body = if snap.page_html.is_empty() {
        format!(
            "<!doctype html><html><body style=\"font-family:sans-serif;padding:24px\"><h3>{}</h3><p>{}</p></body></html>",
            escape_html(&snap.page_title),
            escape_html(&snap.page_text)
        )
    } else {
        snap.page_html
    };
    let mut r = Response::new(axum::body::Body::from(body));
    *r.status_mut() = StatusCode::OK;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src * data: blob: 'unsafe-inline'; script-src 'none'; object-src 'none'; frame-ancestors 'self'"),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}

async fn get_screenshot(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize_computer(&s, &headers, &org, &bot_id, false).await {
        return e;
    }
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let snap = {
        let Ok(guard) = handle.lock() else {
            return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
        };
        guard.snapshot()
    };
    let url = snap.current_url.clone();
    if let Some(png_bytes) = snap.bridge_png.clone() {
        return json_ok(
            StatusCode::OK,
            json!({
                "base64": B64.encode(png_bytes),
                "width": 1280,
                "height": 800,
                "capturedAt": now_iso(),
                "url": url,
            })
            .to_string(),
        );
    }
    let png = tokio::task::spawn_blocking(move || {
        let rgb = render_screen_rgb(&snap);
        encode_png_rgb(SCREEN_WIDTH, SCREEN_HEIGHT, &rgb)
    })
    .await;
    let Ok(png_bytes) = png else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Render failed.");
    };
    json_ok(
        StatusCode::OK,
        json!({
            "base64": B64.encode(png_bytes),
            "width": SCREEN_WIDTH,
            "height": SCREEN_HEIGHT,
            "capturedAt": now_iso(),
            "url": url,
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Live Screen WebSocket (/screen)
// ---------------------------------------------------------------------------

async fn ws_screen(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let actor = match authorize_computer(&s, &headers, &org, &bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    if s.workspace_for_verified_bot(&bot_id).is_err() {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    }
    let permit = match s.inner.sockets.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Too many open sockets.",
            )
        }
    };
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let viewer_id = s.inner.viewer_seq.fetch_add(1, Ordering::Relaxed);
    {
        let Ok(mut guard) = handle.lock() else {
            return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
        };
        guard.active_screen_viewer = viewer_id;
        guard.screen_notify.notify_waiters();
    }
    ws.max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            serve_screen(socket, s, handle, actor, viewer_id).await
        })
}

async fn send_ws_text(ws: &mut WebSocket, text: String) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(5), ws.send(Message::Text(text.into()))).await,
        Ok(Ok(()))
    )
}

async fn send_ws_binary(ws: &mut WebSocket, data: Vec<u8>) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(5), ws.send(Message::Binary(data.into()))).await,
        Ok(Ok(()))
    )
}

async fn encode_jpeg_frame(snap: ScreenSnapshot) -> Result<String, ()> {
    tokio::task::spawn_blocking(move || {
        let rgb = render_screen_rgb(&snap);
        let jpg = encode_jpeg_rgb(SCREEN_WIDTH as u16, SCREEN_HEIGHT as u16, &rgb);
        let b64 = B64.encode(jpg);
        format_ws_frame_json(&b64, SCREEN_WIDTH, SCREEN_HEIGHT)
    })
    .await
    .map_err(|_| ())
}

async fn serve_screen(
    mut ws: WebSocket,
    _state: VirtualComputerState,
    handle: Arc<Mutex<BotComputer>>,
    actor: Identity,
    viewer_id: u64,
) {
    if !send_ws_text(&mut ws, r#"{"type":"hello","confirmFrames":true}"#.to_owned()).await {
        return;
    }

    let (notify, initial_snap) = {
        let Ok(guard) = handle.lock() else { return };
        (guard.screen_notify.clone(), guard.snapshot())
    };
    let mut last_sent_rev = initial_snap.revision;
    let Ok(initial_frame) = encode_jpeg_frame(initial_snap).await else {
        return;
    };
    if !send_ws_text(&mut ws, initial_frame).await {
        return;
    }
    let mut awaiting_ack = true;
    let mut periodic = tokio::time::interval(Duration::from_secs(2));
    periodic.tick().await;

    loop {
        tokio::select! {
            _ = notify.notified() => {
                let (superseded, snap) = {
                    let Ok(guard) = handle.lock() else { break };
                    (guard.active_screen_viewer != viewer_id, guard.snapshot())
                };
                if superseded {
                    let _ = send_ws_text(
                        &mut ws,
                        json!({"type":"error","error":"This screen is open in another tab."}).to_string(),
                    ).await;
                    break;
                }
                if !awaiting_ack && snap.revision > last_sent_rev {
                    last_sent_rev = snap.revision;
                    if let Ok(frame) = encode_jpeg_frame(snap).await {
                        if !send_ws_text(&mut ws, frame).await {
                            break;
                        }
                        awaiting_ack = true;
                    }
                }
            }
            _ = periodic.tick() => {
                let (superseded, snap) = {
                    let Ok(guard) = handle.lock() else { break };
                    (guard.active_screen_viewer != viewer_id, guard.snapshot())
                };
                if superseded {
                    let _ = send_ws_text(
                        &mut ws,
                        json!({"type":"error","error":"This screen is open in another tab."}).to_string(),
                    ).await;
                    break;
                }
                if !awaiting_ack && snap.revision > last_sent_rev {
                    last_sent_rev = snap.revision;
                    if let Ok(frame) = encode_jpeg_frame(snap).await {
                        if !send_ws_text(&mut ws, frame).await {
                            break;
                        }
                        awaiting_ack = true;
                    }
                }
            }
            msg = ws.recv() => {
                let Some(Ok(msg)) = msg else { break };
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Binary(_) => break,
                };
                let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
                if kind == "frame-received" {
                    awaiting_ack = false;
                    let snap = {
                        let Ok(guard) = handle.lock() else { break };
                        guard.snapshot()
                    };
                    if snap.revision > last_sent_rev {
                        last_sent_rev = snap.revision;
                        if let Ok(frame) = encode_jpeg_frame(snap).await {
                            if !send_ws_text(&mut ws, frame).await {
                                break;
                            }
                            awaiting_ack = true;
                        }
                    }
                    continue;
                }
                if matches!(kind, "mouse" | "wheel" | "key" | "text") {
                    let err_msg = {
                        let Ok(mut guard) = handle.lock() else { break };
                        if guard.holder != ControlHolder::Human || guard.held_by.as_deref() != Some(actor.id.as_str()) {
                            Some("You must take control before sending screen input.")
                        } else {
                            apply_screen_input(&mut guard, kind, &v);
                            None
                        }
                    };
                    if let Some(err) = err_msg {
                        if !send_ws_text(&mut ws, json!({"type":"input-error","error":err}).to_string()).await {
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn apply_screen_input(bot: &mut BotComputer, kind: &str, v: &Value) {
    match kind {
        "mouse" => {
            if let (Some(x), Some(y)) = (v.get("x").and_then(Value::as_f64), v.get("y").and_then(Value::as_f64)) {
                bot.cursor_x = (x.round().max(0.0) as u32).min(SCREEN_WIDTH - 1);
                bot.cursor_y = (y.round().max(0.0) as u32).min(SCREEN_HEIGHT - 1);
            }
            let ev = v.get("event").and_then(Value::as_str).unwrap_or("moved");
            if ev != "moved" {
                bot.last_input = format!("mouse {ev} ({}, {})", bot.cursor_x, bot.cursor_y);
            }
            bot.bump_screen();
        }
        "wheel" => {
            let dy = v.get("deltaY").and_then(Value::as_f64).unwrap_or(0.0);
            bot.last_input = format!("wheel deltaY={dy:.0}");
            bot.bump_screen();
        }
        "key" => {
            let ev = v.get("event").and_then(Value::as_str).unwrap_or("down");
            let key = v.get("key").and_then(Value::as_str).unwrap_or("");
            if ev == "down" && !key.is_empty() {
                bot.last_input = format!("key {key}");
                bot.bump_screen();
            }
        }
        "text" => {
            if let Some(txt) = v.get("text").and_then(Value::as_str) {
                let clipped: String = txt.chars().take(64).collect();
                bot.last_input = format!("text: {clipped}");
                bot.bump_screen();
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Live Terminal WebSocket (/terminal)
// ---------------------------------------------------------------------------

async fn ws_terminal(
    State(s): State<VirtualComputerState>,
    Path((org, bot_id)): Path<(String, String)>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let actor = match authorize_computer(&s, &headers, &org, &bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let Ok(engine) = s.workspace_for_verified_bot(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    let permit = match s.inner.sockets.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "Too many open sockets.",
            )
        }
    };
    let Ok(handle) = s.bot_handle(&bot_id) else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", "Unavailable.");
    };
    ws.max_message_size(128 * 1024)
        .max_frame_size(128 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            serve_terminal(socket, handle, engine, actor).await
        })
}

async fn serve_terminal(
    mut ws: WebSocket,
    handle: Arc<Mutex<BotComputer>>,
    engine: WorkspaceEngine,
    actor: Identity,
) {
    if !send_ws_text(&mut ws, r#"{"type":"snapshot","cols":80,"rows":24}"#.to_owned()).await {
        return;
    }
    let banner = "\x1b[1;36mOpenBot-PS5 Virtual Terminal\x1b[0m (/workspace)\r\n\x1b[32m$\x1b[0m ";
    if !send_ws_binary(&mut ws, banner.as_bytes().to_vec()).await {
        return;
    }
    if !send_ws_text(&mut ws, r#"{"type":"ready"}"#.to_owned()).await {
        return;
    }

    let mut line_buf = String::new();
    let mut last_was_cr = false;
    let mut in_csi = false;
    let mut unacked_bytes: u64 = banner.len() as u64;

    while let Some(Ok(msg)) = ws.recv().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Binary(_) => break,
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match v.get("type").and_then(Value::as_str).unwrap_or("") {
            "resize" => {
                // Dimensions acknowledged for @xterm/xterm FitAddon
            }
            "ack" => {
                let acked = v.get("bytes").and_then(Value::as_u64).unwrap_or(0);
                unacked_bytes = unacked_bytes.saturating_sub(acked);
            }
            "input" => {
                let Some(data) = v.get("data").and_then(Value::as_str) else {
                    continue;
                };
                if data.len() > 65536 {
                    let _ = send_ws_text(
                        &mut ws,
                        json!({"type":"error","error":"Input exceeds maximum length."}).to_string(),
                    )
                    .await;
                    continue;
                }
                let can_drive = {
                    let Ok(guard) = handle.lock() else { break };
                    guard.holder == ControlHolder::Human
                        && guard.held_by.as_deref() == Some(actor.id.as_str())
                };
                if !can_drive {
                    let _ = send_ws_text(
                        &mut ws,
                        json!({"type":"error","error":"Take control of the computer before typing."})
                            .to_string(),
                    )
                    .await;
                    continue;
                }

                let mut out_bytes = Vec::new();
                let mut commands_to_run = Vec::new();
                for ch in data.chars() {
                    if in_csi {
                        if ('@'..='~').contains(&ch) {
                            in_csi = false;
                        }
                        continue;
                    }
                    if ch == '\x1b' {
                        in_csi = true;
                        continue;
                    }
                    if ch == '\n' && last_was_cr {
                        last_was_cr = false;
                        continue;
                    }
                    last_was_cr = ch == '\r';

                    match ch {
                        '\r' | '\n' => {
                            out_bytes.extend_from_slice(b"\r\n");
                            commands_to_run.push(std::mem::take(&mut line_buf));
                        }
                        '\x7f' | '\x08' => {
                            if line_buf.pop().is_some() {
                                out_bytes.extend_from_slice(b"\x08 \x08");
                            }
                        }
                        '\x03' => {
                            line_buf.clear();
                            out_bytes.extend_from_slice(b"^C\r\n\x1b[32m$\x1b[0m ");
                        }
                        c if !c.is_control() => {
                            if line_buf.len() < 4096 {
                                line_buf.push(c);
                                let mut enc = [0u8; 4];
                                out_bytes.extend_from_slice(c.encode_utf8(&mut enc).as_bytes());
                            }
                        }
                        _ => {}
                    }
                }

                for cmd in commands_to_run {
                    if cmd.trim() == "clear" {
                        out_bytes.extend_from_slice(b"\x1b[2J\x1b[H\x1b[32m$\x1b[0m ");
                        continue;
                    }
                    if !cmd.trim().is_empty() {
                        let cwd = {
                            let Ok(guard) = handle.lock() else { break };
                            guard.cwd.clone()
                        };
                        let eng = engine.clone();
                        let cmd_owned = cmd.clone();
                        let res = tokio::task::spawn_blocking(move || {
                            let mut cur_cwd = cwd;
                            let val = VirtualShell::run(&eng, &mut cur_cwd, &cmd_owned);
                            (val, cur_cwd)
                        })
                        .await;
                        if let Ok((val, new_cwd)) = res {
                            let stdout = val.get("stdout").and_then(Value::as_str).unwrap_or("");
                            let stderr = val.get("stderr").and_then(Value::as_str).unwrap_or("");
                            out_bytes.extend_from_slice(stdout.replace('\n', "\r\n").as_bytes());
                            if !stderr.is_empty() {
                                out_bytes.extend_from_slice(b"\x1b[31m");
                                out_bytes.extend_from_slice(stderr.replace('\n', "\r\n").as_bytes());
                                out_bytes.extend_from_slice(b"\x1b[0m");
                            }
                            if let Ok(mut guard) = handle.lock() {
                                guard.cwd = new_cwd;
                                guard.push_terminal_line(&format!("$ {cmd}\n{stdout}{stderr}"));
                            }
                        }
                    }
                    out_bytes.extend_from_slice(b"\x1b[32m$\x1b[0m ");
                }

                if !out_bytes.is_empty() && unacked_bytes < 256 * 1024 {
                    unacked_bytes = unacked_bytes.saturating_add(out_bytes.len() as u64);
                    if !send_ws_binary(&mut ws, out_bytes).await {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Time & Random Helpers (Pure std + getrandom)
// ---------------------------------------------------------------------------

fn random_uuid_like() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let sec = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.000Z")
}

// Howard Hinnant's civil-from-days algorithm (public domain)
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = y + i64::from(m <= 2);
    (year, m, d)
}

// ---------------------------------------------------------------------------
// Unit & Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message as ClientMessage};
    use tower::ServiceExt;

    fn temp_workspace(tag: &str) -> PathBuf {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let dir = std::env::temp_dir().join(format!("openbot-vc-{tag}-{:x}", u64::from_le_bytes(r)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn workspace_jail_rejects_traversal_and_symlinks() {
        let base = temp_workspace("jail");
        let bot_dir = base.join("bot_1");
        let engine = WorkspaceEngine::open_or_create(&base, &bot_dir).unwrap();

        for bad in [
            "",
            ".",
            "..",
            "../secret.txt",
            "a/../b",
            "a/./b",
            "/etc/passwd",
            "a\\b",
            "C:foo",
            "bad\0name",
            "a//b",
        ] {
            assert!(
                engine.resolve_jailed_path(bad, false).is_err(),
                "expected rejection for {bad:?}"
            );
        }

        // Symlink check (Unix or Windows if symlink privilege available)
        let outside = temp_workspace("outside");
        let outside_file = outside.join("secret.txt");
        fs::write(&outside_file, "top-secret").unwrap();
        let link_path = engine.root().join("escape_link");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&outside_file, &link_path).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&outside_file, &link_path).is_ok();
        if linked {
            assert!(engine.read_file("escape_link").is_err());
            assert!(engine.write_file("escape_link", "x", false).is_err());
        }

        let _ = fs::remove_dir_all(outside);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn virtual_shell_supports_mkdir_echo_cat_ls_and_chaining() {
        let base = temp_workspace("shell");
        let bot_dir = base.join("bot_sh");
        let engine = WorkspaceEngine::open_or_create(&base, &bot_dir).unwrap();
        let mut cwd = String::new();

        let res = VirtualShell::run(
            &engine,
            &mut cwd,
            "mkdir -p reports/2026 && echo 'hello ps5' > reports/2026/note.txt && cat reports/2026/note.txt",
        );
        assert_eq!(res["exitCode"], 0);
        assert_eq!(res["stdout"], "hello ps5\n");

        let ls_res = VirtualShell::run(&engine, &mut cwd, "ls reports/2026 | grep note");
        assert_eq!(ls_res["exitCode"], 0);
        assert_eq!(ls_res["stdout"], "note.txt\n");

        let wc_res = VirtualShell::run(&engine, &mut cwd, "wc -w reports/2026/note.txt");
        assert_eq!(wc_res["exitCode"], 0);
        assert_eq!(wc_res["stdout"], "2\n");

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn ssrf_guard_blocks_private_loopback_cgnat_and_ipv4_mapped_v6() {
        let local = vec![Ipv4Addr::new(192, 168, 50, 10)];
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "192.168.50.10",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456:789a::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "2002:7f00:0001::1",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(is_forbidden_ip(parsed, &local), "expected SSRF block for {ip}");
        }

        let public_v4: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(!is_forbidden_ip(public_v4, &local));
        let public_v6: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();
        assert!(!is_forbidden_ip(public_v6, &local));

        assert!(validate_fetch_url("http://localhost/admin").is_err());
        assert!(validate_fetch_url("file:///etc/passwd").is_err());
        assert!(validate_fetch_url("http://user:pass@example.com/").is_err());
    }

    #[tokio::test]
    async fn web_fetch_blocks_loopback_before_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dns_jobs = Arc::new(Semaphore::new(4));
        let err = web_fetch_ssrf_safe(&format!("http://{addr}/secret"), dns_jobs)
            .await
            .err()
            .expect("loopback fetch must fail");
        assert!(err.contains("SSRF"), "unexpected error: {err}");
    }

    #[test]
    fn png_and_jpeg_encoders_emit_valid_magic_and_frame_first_key() {
        let snap = ScreenSnapshot {
            bot_id: "bot_test".to_owned(),
            proxy_token: String::new(),
            holder: ControlHolder::Bot,
            current_url: "https://example.com".to_owned(),
            page_title: "Example".to_owned(),
            page_text: "Hello world".to_owned(),
            page_html: String::new(),
            bridge_png: None,
            last_input: String::new(),
            cursor_x: 320,
            cursor_y: 200,
            terminal_lines: vec!["$ ls".to_owned(), "reports".to_owned()],
            revision: 1,
        };
        let rgb = render_screen_rgb(&snap);
        assert_eq!(rgb.len(), (SCREEN_WIDTH * SCREEN_HEIGHT * 3) as usize);

        let png = encode_png_rgb(SCREEN_WIDTH, SCREEN_HEIGHT, &rgb);
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(&png[12..16], b"IHDR");
        assert!(png.ends_with(b"IEND\xae\x42\x60\x82"));

        let jpg = encode_jpeg_rgb(SCREEN_WIDTH as u16, SCREEN_HEIGHT as u16, &rgb);
        assert!(jpg.starts_with(&[0xFF, 0xD8, 0xFF]));
        assert!(jpg.ends_with(&[0xFF, 0xD9]));

        let b64 = B64.encode(&jpg);
        let frame_json = format_ws_frame_json(&b64, SCREEN_WIDTH, SCREEN_HEIGHT);
        assert!(
            frame_json.starts_with(r#"{"type":"frame""#),
            "FRAME_PREFIX invariant violated"
        );
        let parsed: Value = serde_json::from_str(&frame_json).unwrap();
        assert_eq!(parsed["type"], "frame");
        assert_eq!(parsed["width"], SCREEN_WIDTH);
        assert_eq!(parsed["height"], SCREEN_HEIGHT);
    }

    #[tokio::test]
    async fn rest_control_screenshot_and_websockets_end_to_end() {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).unwrap();
        let db_path = std::env::temp_dir().join(format!("openbot-vc-{:x}.db", u64::from_le_bytes(rnd)));
        let ws_root = temp_workspace("e2e");
        let db = Arc::new(Storage::open(&db_path).unwrap());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = format!("http://{addr}");
        let host = addr.to_string();

        let auth = AuthState::new(
            db.clone(),
            &origin,
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let vc = VirtualComputerState::new(auth.clone(), ws_root.clone());
        let app = local_auth::router(auth).merge(router(vc.clone()));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("origin", &origin)
            .header("host", &host)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(setup).await.unwrap();
        let status = resp.status();
        if status != StatusCode::NO_CONTENT {
            let err_body = to_bytes(resp.into_body(), 4096).await.unwrap();
            panic!("setup failed with {status}: {}", String::from_utf8_lossy(&err_body));
        }
        let cookie = resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        // Unknown bot must NOT create workspace directory
        let missing = Request::builder()
            .uri("/api/v2/organizations/default/computers/missing_bot")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.clone().oneshot(missing).await.unwrap().status(), StatusCode::NOT_FOUND);
        assert!(!ws_root.join("missing_bot").exists());

        let owner_id: String = db
            .try_with_connection(|c| {
                c.execute(
                    "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot_1','default',id,'Bot','','help',0 FROM auth_users LIMIT 1",
                    [],
                )?;
                let uid: String = c.query_row("SELECT id FROM auth_users LIMIT 1", [], |r| r.get(0))?;
                Ok(uid)
            })
            .unwrap();

        // Wake & status
        let wake = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/computers/bot_1/wake")
            .header("origin", &origin)
            .header("host", &host)
            .header("cookie", &cookie)
            .header("idempotency-key", "wake-1")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(wake).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(ws_root.join("bot_1").exists());

        // Control request -> take -> release
        let req_ctrl = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/computers/bot_1/control/request")
            .header("origin", &origin)
            .header("host", &host)
            .header("cookie", &cookie)
            .header("idempotency-key", "req-1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"reason":"manual check","source":"manual"}"#))
            .unwrap();
        let ctrl_body: Value = serde_json::from_slice(
            &to_bytes(app.clone().oneshot(req_ctrl).await.unwrap().into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        let req_id = ctrl_body["request"]["id"].as_str().unwrap().to_owned();

        let take_ctrl = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/computers/bot_1/control/take")
            .header("origin", &origin)
            .header("host", &host)
            .header("cookie", &cookie)
            .header("idempotency-key", "take-1")
            .header("content-type", "application/json")
            .body(Body::from(json!({"requestId": req_id}).to_string()))
            .unwrap();
        let taken: Value = serde_json::from_slice(
            &to_bytes(app.clone().oneshot(take_ctrl).await.unwrap().into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(taken["holder"], "human");

        // Screenshot PNG
        let shot = Request::builder()
            .uri("/api/v2/organizations/default/computers/bot_1/screenshot")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let shot_json: Value = serde_json::from_slice(
            &to_bytes(app.clone().oneshot(shot).await.unwrap().into_body(), 2 * 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let png_bytes = B64.decode(shot_json["base64"].as_str().unwrap()).unwrap();
        assert!(png_bytes.starts_with(b"\x89PNG\r\n\x1a\n"));

        // Serve for WebSocket tests
        let srv_app = app.clone();
        let server = tokio::spawn(async move { axum::serve(listener, srv_app).await.unwrap() });

        // Screen WS
        let mut req = format!("ws://{addr}/api/v2/organizations/default/computers/bot_1/screen")
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("origin", origin.parse().unwrap());
        req.headers_mut().insert("cookie", cookie.parse().unwrap());
        let (mut ws_s, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let hello = ws_s.next().await.unwrap().unwrap();
        let hello_json: Value = serde_json::from_str(hello.to_text().unwrap()).unwrap();
        assert_eq!(hello_json["type"], "hello");
        let frame = ws_s.next().await.unwrap().unwrap();
        let frame_txt = frame.to_text().unwrap();
        assert!(frame_txt.starts_with(r#"{"type":"frame""#));
        let frame_json: Value = serde_json::from_str(frame_txt).unwrap();
        let jpg_bytes = B64.decode(frame_json["data"].as_str().unwrap()).unwrap();
        assert!(jpg_bytes.starts_with(&[0xFF, 0xD8, 0xFF]));
        ws_s.close(None).await.unwrap();

        // Terminal WS
        let mut treq = format!("ws://{addr}/api/v2/organizations/default/computers/bot_1/terminal")
            .into_client_request()
            .unwrap();
        treq.headers_mut()
            .insert("origin", origin.parse().unwrap());
        treq.headers_mut().insert("cookie", cookie.parse().unwrap());
        let (mut ws_t, _) = tokio_tungstenite::connect_async(treq).await.unwrap();
        let snap_msg: Value =
            serde_json::from_str(ws_t.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(snap_msg["type"], "snapshot");
        assert!(matches!(ws_t.next().await.unwrap().unwrap(), ClientMessage::Binary(_)));
        let ready_msg: Value =
            serde_json::from_str(ws_t.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(ready_msg["type"], "ready");
        ws_t.send(ClientMessage::Text(
            json!({"type":"input","data":"echo hi_term\n"}).to_string().into(),
        ))
        .await
        .unwrap();
        let out_msg = ws_t.next().await.unwrap().unwrap();
        let ClientMessage::Binary(bin) = out_msg else {
            panic!("expected binary terminal output");
        };
        assert!(String::from_utf8_lossy(&bin).contains("hi_term"));
        ws_t.close(None).await.unwrap();

        // Release control back to bot
        let rel_ctrl = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/computers/bot_1/control/release")
            .header("origin", &origin)
            .header("host", &host)
            .header("cookie", &cookie)
            .header("idempotency-key", "rel-1")
            .header("content-type", "application/json")
            .body(Body::from(json!({"requestId": req_id}).to_string()))
            .unwrap();
        let released: Value = serde_json::from_slice(
            &to_bytes(app.oneshot(rel_ctrl).await.unwrap().into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(released["holder"], "bot");

        // Verify owner-scoped execute_tool_for_owner rejects wrong owner & accepts right owner
        assert!(vc
            .execute_tool_for_owner("default", "wrong_user", "bot_1", "computer_list_files", json!({}))
            .await
            .is_err());
        assert!(vc
            .execute_tool_for_owner("default", &owner_id, "bot_1", "computer_list_files", json!({}))
            .await
            .is_ok());

        // Exercise execute_tool dispatcher (read/write/list/grep/run_command/web_fetch SSRF)
        let wr = vc
            .execute_tool(
                "bot_1",
                "computer_write_file",
                json!({"path":"docs/readme.md","contents":"hello OpenBot PS5\nline two"}),
            )
            .await
            .unwrap();
        assert_eq!(wr["bytes"], 26);

        let rd = vc
            .execute_tool("bot_1", "computer_read_file", json!({"path":"docs/readme.md"}))
            .await
            .unwrap();
        assert_eq!(rd["text"], "hello OpenBot PS5\nline two");

        let ls = vc
            .execute_tool("bot_1", "computer_list_files", json!({"path":"docs"}))
            .await
            .unwrap();
        assert_eq!(ls["entries"][0]["path"], "docs/readme.md");

        let gr = vc
            .execute_tool(
                "bot_1",
                "computer_grep_search",
                json!({"query":"OpenBot","path":"docs"}),
            )
            .await
            .unwrap();
        assert_eq!(gr["matches"][0]["line"], 1);

        let cmd = vc
            .execute_tool(
                "bot_1",
                "computer_run_command",
                json!({"command":"uname && pwd"}),
            )
            .await
            .unwrap();
        assert_eq!(cmd["exitCode"], 0);
        assert!(cmd["stdout"].as_str().unwrap().contains("OpenBot-PS5"));

        let ssrf_err = vc
            .execute_tool(
                "bot_1",
                "computer_web_fetch",
                json!({"url":"http://127.0.0.1:8080/"}),
            )
            .await
            .unwrap_err();
        assert!(ssrf_err.contains("SSRF"));

        // Ensure HTTP redirects are checked against SSRF rules on every hop (validates URL + IP pinning)
        let redir_err = match web_fetch_ssrf_safe(
            &format!("http://localhost:{}/", addr.port()),
            Arc::new(Semaphore::new(4)),
        )
        .await
        {
            Ok(_) => panic!("expected loopback fetch to be blocked"),
            Err(e) => e,
        };
        assert!(redir_err.contains("SSRF") || redir_err.contains("host"));

        let (title, text) = extract_html_title_and_text(
            "<html><head><title>PS5 &amp; Rust</title><style>body{}</style></head><body><h1>Hi</h1><script>evil()</script><p>Zaloguj si&#281; &copy; 2026 - Prywatno&#347;&#263;</p></body></html>",
        );
        assert_eq!(title, "PS5 & Rust");
        assert!(text.contains("Hi") && text.contains("Zaloguj się") && text.contains("© 2026 - Prywatność") && !text.contains("evil"));
        let preview = build_visual_html_preview(
            "https://example.com/dir/",
            "<html><head><title>Test</title></head><body><script>alert(1)</script><p>Visual</p></body></html>",
        );
        assert!(preview.contains("<base href=\"https://example.com/dir/\""));
        assert!(!preview.contains("alert(1)"));
        assert!(preview.contains("<p>Visual</p>"));

        server.abort();
        drop(db);
        let _ = fs::remove_file(db_path);
        let _ = fs::remove_dir_all(ws_root);
    }

    #[test]
    fn massive_youtube_like_html_fetch_stays_strictly_bounded() {
        // Simulate a massive page like YouTube with 250KB of inline JSON/JS in <head> before <body>
        // plus multi-byte UTF-8 body content exceeding MAX_PAGE_TEXT_CHARS and MAX_PREVIEW_HTML_BYTES.
        let huge_js = "var ytInitialData={\"k\":\"x\"};".repeat(9000); // ~252 KB
        let huge_noscript = "<noscript>Enable JavaScript to run YouTube</noscript>".repeat(200);
        let huge_body = "<p>Watch trending videos — Zażółć gęślą jaźń 🎵</p>".repeat(1200);
        let huge_html = format!(
            "<!doctype html><html><head><title>YouTube — {}</title><script>{}</script>{}</head><body>{}</body></html>",
            "VeryLongTitle".repeat(40),
            huge_js,
            huge_noscript,
            huge_body,
        );
        assert!(huge_html.len() > 300 * 1024);

        let capped_input = &huge_html.as_bytes()[..MAX_FETCH_BYTES.min(huge_html.len())];
        let fetched = process_fetched_bytes(
            format!("https://www.youtube.com/watch?v={}", "a".repeat(800)),
            "www.youtube.com",
            200,
            true,
            capped_input,
            true,
        );
        assert!(fetched.truncated);
        assert!(fetched.title.chars().count() <= 256);
        assert!(fetched.text.chars().count() <= MAX_PAGE_TEXT_CHARS);
        assert!(fetched.html.len() <= MAX_PREVIEW_HTML_BYTES);
        assert!(!fetched.html.contains("ytInitialData"));

        // Ensure multi-byte UTF-8 body + long URL/title still yields bounded preview and <= 3072 char tool output
        let body_heavy_html = format!(
            "<html><head><title>{}</title></head><body>{}</body></html>",
            "Title🔥".repeat(80),
            huge_body
        );
        let fetched_body = process_fetched_bytes(
            format!("https://www.youtube.com/results?search_query={}", "q".repeat(700)),
            "www.youtube.com",
            200,
            true,
            body_heavy_html.as_bytes(),
            false,
        );
        assert!(fetched_body.html.len() <= MAX_PREVIEW_HTML_BYTES);
        assert!(fetched_body.text.chars().count() <= MAX_PAGE_TEXT_CHARS);
        assert!(fetched_body.text.contains("Watch trending videos"));

        let tool_out = bounded_web_fetch_tool_output(&fetched_body);
        let encoded = serde_json::to_string(&tool_out).unwrap();
        assert!(
            encoded.chars().count() <= MAX_TOOL_OUTPUT_CHARS,
            "tool output exceeded {} chars: {}",
            MAX_TOOL_OUTPUT_CHARS,
            encoded.chars().count()
        );
        assert_eq!(tool_out["ok"], true);
        assert_eq!(tool_out["truncated"], true);
    }

    #[test]
    fn validate_fetch_url_normalizes_bare_domains_and_keeps_ssrf_guards() {
        assert_eq!(
            validate_fetch_url("youtube.com").unwrap().as_str(),
            "https://youtube.com/"
        );
        assert_eq!(
            validate_fetch_url("  www.youtube.com/watch?v=dQw4w9WgXcQ  ")
                .unwrap()
                .as_str(),
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        );
        assert_eq!(
            validate_fetch_url("example.com:8443/path?a=b:c")
                .unwrap()
                .as_str(),
            "https://example.com:8443/path?a=b:c"
        );
        assert_eq!(
            validate_fetch_url("http://example.com/test").unwrap().as_str(),
            "http://example.com/test"
        );

        for bad in [
            "",
            "   ",
            "//evil.com",
            "notadomain",
            "localhost",
            "localhost:3000/admin",
            "sub.localhost/test",
            "printer.local",
            "file:///etc/passwd",
            "ftp://example.com/a",
            "javascript:alert(1)",
            "data:text/html,hello",
            "user:pass@example.com",
            "https://user:pass@example.com/",
        ] {
            assert!(
                validate_fetch_url(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn ssrf_dns_selection_prioritizes_public_ipv4_and_reports_offending_ips() {
        let local = vec![Ipv4Addr::new(192, 168, 10, 3)];
        let mixed = vec![
            SocketAddr::new("::".parse().unwrap(), 443),
            SocketAddr::new("fe80::1".parse().unwrap(), 443),
            SocketAddr::new("fd00::1".parse().unwrap(), 443),
            SocketAddr::new("2001:4860:4826:400::".parse().unwrap(), 443),
            SocketAddr::new("142.251.153.4".parse().unwrap(), 443),
        ];
        let allowed = select_allowed_socket_addrs("www.youtube.com", mixed, &local).unwrap();
        assert_eq!(
            allowed,
            vec![
                SocketAddr::new("142.251.153.4".parse().unwrap(), 443),
                SocketAddr::new("2001:4860:4826:400::".parse().unwrap(), 443),
            ]
        );

        let all_bad = vec![
            SocketAddr::new("127.0.0.1".parse().unwrap(), 443),
            SocketAddr::new("::1".parse().unwrap(), 443),
        ];
        let err = select_allowed_socket_addrs("www.youtube.com", all_bad, &local).unwrap_err();
        assert!(err.contains("www.youtube.com"), "missing host in {err}");
        assert!(err.contains("127.0.0.1"), "missing v4 ip in {err}");
        assert!(err.contains("::1"), "missing v6 ip in {err}");
        assert!(err.contains("SSRF"), "missing SSRF in {err}");

        let dns_jobs = Arc::new(Semaphore::new(4));
        let lit_err = web_fetch_ssrf_safe("http://127.0.0.1:8080/", dns_jobs)
            .await
            .err()
            .unwrap();
        assert!(lit_err.contains("127.0.0.1"), "missing literal ip in {lit_err}");
        assert!(lit_err.contains("SSRF"), "missing SSRF in {lit_err}");
    }

    #[test]
    fn spa_youtube_fallback_preview_and_head_stripping() {
        // Large <script>, <style>, and <noscript> in <head> must be stripped before
        // MAX_PREVIEW_HTML_BYTES so <body> is preserved.
        let huge_script = "var ytInitialData={\"k\":\"v\"};".repeat(1200);
        let huge_style = ".ytd-masthead{color:#fff;}".repeat(1200);
        let huge_noscript = "<noscript>Enable JS</noscript>".repeat(300);
        let html_with_body = format!(
            "<!doctype html><html><head><title>Article</title><script>{huge_script}</script><style>{huge_style}</style>{huge_noscript}</head><body><main><p>Real visible article body</p></main></body></html>"
        );
        let body_preview = build_visual_html_preview("https://example.com/post", &html_with_body);
        assert!(body_preview.len() <= MAX_PREVIEW_HTML_BYTES);
        assert!(body_preview.contains("<p>Real visible article body</p>"));
        assert!(!body_preview.contains("ytInitialData"));
        assert!(!body_preview.contains(".ytd-masthead"));

        // YouTube Polymer SPA shell with empty/minimal body synthesizes structured fallback card.
        let yt_shell = r#"<!doctype html><html><head><title>YouTube</title><meta name="description" content="Enjoy the videos and music you love on YouTube."><link rel="canonical" href="https://www.youtube.com/"><script>var ytInitialData={};</script></head><body><ytd-app><ytd-masthead><a href="https://www.youtube.com/feed/trending">Trending</a></ytd-masthead></ytd-app></body></html>"#;
        let fetched_spa = process_fetched_bytes(
            "https://www.youtube.com/".to_owned(),
            "www.youtube.com",
            200,
            true,
            yt_shell.as_bytes(),
            false,
        );
        assert!(fetched_spa.html.len() <= MAX_PREVIEW_HTML_BYTES);
        assert!(fetched_spa.html.contains("Dynamic App Preview"));
        assert!(fetched_spa.html.contains("YouTube"));
        assert!(fetched_spa.html.contains("https://www.youtube.com/"));
        assert!(fetched_spa.html.contains("Extracted Reader Text"));
        assert!(fetched_spa.html.contains("Enjoy the videos and music you love on YouTube."));
        assert!(fetched_spa.html.contains("Trending"));

        // Truncated <head>-only SPA HTML (body never reached) also yields structured fallback card.
        let head_only = r#"<!doctype html><html><head><title>YouTube Music</title><meta property="og:description" content="A new music service with official albums."><script>var big=1;"#;
        let head_preview = build_visual_html_preview("https://music.youtube.com/", head_only);
        assert!(head_preview.len() <= MAX_PREVIEW_HTML_BYTES);
        assert!(head_preview.contains("YouTube Music"));
        assert!(head_preview.contains("https://music.youtube.com/"));
        assert!(head_preview.contains("A new music service with official albums."));
    }

    #[tokio::test]
    async fn human_go_navigate_and_page_html_escaping_work_with_human_in_control() {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).unwrap();
        let db_path = std::env::temp_dir().join(format!("openbot-vc-nav-{:x}.db", u64::from_le_bytes(rnd)));
        let ws_root = temp_workspace("nav");
        let db = Arc::new(Storage::open(&db_path).unwrap());

        let origin = "http://127.0.0.1:3010";
        let host = "127.0.0.1:3010";
        let auth = AuthState::new(
            db.clone(),
            origin,
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let vc = VirtualComputerState::new(auth.clone(), ws_root.clone());
        let app = local_auth::router(auth).merge(router(vc.clone()));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("origin", origin)
            .header("host", host)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#,
            ))
            .unwrap();
        let resp = app.clone().oneshot(setup).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let cookie = resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        db.try_with_connection(|c| {
            c.execute(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot_nav','default',id,'Bot','','help',0 FROM auth_users LIMIT 1",
                [],
            )?;
            Ok(())
        })
        .unwrap();

        // Take control as Human
        let req_ctrl = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/computers/bot_nav/control/request")
            .header("origin", origin)
            .header("host", host)
            .header("cookie", &cookie)
            .header("idempotency-key", "req-nav")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"reason":"manual browse","source":"manual"}"#))
            .unwrap();
        let ctrl_body: Value = serde_json::from_slice(
            &to_bytes(app.clone().oneshot(req_ctrl).await.unwrap().into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        let req_id = ctrl_body["request"]["id"].as_str().unwrap().to_owned();

        let take_ctrl = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/computers/bot_nav/control/take")
            .header("origin", origin)
            .header("host", host)
            .header("cookie", &cookie)
            .header("idempotency-key", "take-nav")
            .header("content-type", "application/json")
            .body(Body::from(json!({"requestId": req_id}).to_string()))
            .unwrap();
        let taken: Value = serde_json::from_slice(
            &to_bytes(app.clone().oneshot(take_ctrl).await.unwrap().into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(taken["holder"], "human");

        // Bot-initiated navigate must still be blocked while Human holds control
        let bot_err = vc
            .execute_tool(
                "bot_nav",
                "computer_web_fetch",
                json!({"url": "https://example.com"}),
            )
            .await
            .unwrap_err();
        assert!(bot_err.contains("driving this computer"));

        // Human-initiated POST .../navigate (modal Go) must NOT be blocked by HUMAN_IN_CONTROL
        let nav_req = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/computers/bot_nav/navigate")
            .header("origin", origin)
            .header("host", host)
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"url":"localhost"}"#))
            .unwrap();
        let nav_resp = app.clone().oneshot(nav_req).await.unwrap();
        assert_eq!(nav_resp.status(), StatusCode::OK);
        let nav_json: Value = serde_json::from_slice(
            &to_bytes(nav_resp.into_body(), 4096).await.unwrap(),
        )
        .unwrap();
        assert_eq!(nav_json["ok"], false);
        assert_eq!(nav_json["error"], "local hostnames are forbidden");

        // Non-navigate REST exec remains blocked by HUMAN_IN_CONTROL
        let exec_req = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/computers/bot_nav/exec")
            .header("origin", origin)
            .header("host", host)
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"command":"pwd"}"#))
            .unwrap();
        let exec_resp = app.clone().oneshot(exec_req).await.unwrap();
        assert_eq!(exec_resp.status(), StatusCode::CONFLICT);

        // Verify get_page_html escapes HTML entities in title & text when page_html is empty
        {
            let handle = vc.bot_handle("bot_nav").unwrap();
            let mut guard = handle.lock().unwrap();
            guard.page_html.clear();
            guard.page_title = "<script>alert(1)</script> & \"Title\"".to_owned();
            guard.page_text = "5 < 10 & 'raw'".to_owned();
        }
        let html_req = Request::builder()
            .uri("/api/v2/organizations/default/computers/bot_nav/page-html")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let html_resp = app.clone().oneshot(html_req).await.unwrap();
        assert_eq!(html_resp.status(), StatusCode::OK);
        let html_body = String::from_utf8(
            to_bytes(html_resp.into_body(), 8192).await.unwrap().to_vec(),
        )
        .unwrap();
        assert!(html_body.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;Title&quot;"));
        assert!(html_body.contains("5 &lt; 10 &amp; &#39;raw&#39;"));
        assert!(!html_body.contains("<script>alert(1)</script>"));

        drop(db);
        let _ = fs::remove_file(db_path);
        let _ = fs::remove_dir_all(ws_root);
    }

    #[test]
    fn doh_json_parser_extracts_a_aaaa_skips_cname_and_rejects_errors() {
        let payload = br#"{
            "Status": 0,
            "Answer": [
                { "name": "www.youtube.com.", "type": 5, "TTL": 300, "data": "youtube-ui.l.google.com." },
                { "name": "youtube-ui.l.google.com.", "type": 1, "TTL": 120, "data": "142.250.185.206" },
                { "name": "youtube-ui.l.google.com.", "type": 1, "TTL": 120, "data": "142.250.185.206" },
                { "name": "youtube-ui.l.google.com.", "type": 28, "TTL": 120, "data": "2607:f8b0:4005:80b::200e" }
            ]
        }"#;
        let parsed = parse_doh_answer_ips(payload, 443).unwrap();
        assert_eq!(
            parsed,
            vec![
                SocketAddr::new("142.250.185.206".parse().unwrap(), 443),
                SocketAddr::new("2607:f8b0:4005:80b::200e".parse().unwrap(), 443),
            ]
        );

        let empty_ok = parse_doh_answer_ips(br#"{"Status":0,"Answer":[]}"#, 443).unwrap();
        assert!(empty_ok.is_empty());

        let nxdomain = parse_doh_answer_ips(br#"{"Status":3,"Answer":[]}"#, 443).unwrap_err();
        assert!(nxdomain.contains("status 3"), "unexpected err: {nxdomain}");

        assert!(parse_doh_answer_ips(b"not json", 443).is_err());
    }

    #[tokio::test]
    async fn doh_fallback_triggers_on_sinkhole_or_os_error_and_respects_ssrf_and_local_hosts() {
        let local = vec![Ipv4Addr::new(192, 168, 10, 3)];

        // Sinkhole (0.0.0.0 / ::) and OS DNS failure on public domains trigger DoH
        assert!(should_fallback_to_doh(
            "youtube.com",
            &Ok(vec![SocketAddr::new("0.0.0.0".parse().unwrap(), 443)])
        ));
        assert!(should_fallback_to_doh(
            "www.youtube.com",
            &Ok(vec![
                SocketAddr::new("0.0.0.0".parse().unwrap(), 443),
                SocketAddr::new("::".parse().unwrap(), 443),
            ])
        ));
        assert!(should_fallback_to_doh(
            "youtu.be",
            &Err("lookup failed".to_owned())
        ));
        assert!(should_fallback_to_doh("m.youtube.com", &Ok(vec![])));

        // Valid public IP or non-unspecified SSRF IP (e.g. 127.0.0.1) does NOT bypass via DoH
        assert!(!should_fallback_to_doh(
            "youtube.com",
            &Ok(vec![SocketAddr::new("142.250.185.206".parse().unwrap(), 443)])
        ));
        assert!(!should_fallback_to_doh(
            "evil.example",
            &Ok(vec![SocketAddr::new("127.0.0.1".parse().unwrap(), 443)])
        ));

        // Local hostnames / single-label LAN names / literal IPs never query public DoH
        assert!(!should_fallback_to_doh("localhost", &Err("err".to_owned())));
        assert!(!should_fallback_to_doh("printer.local", &Ok(vec![SocketAddr::new("0.0.0.0".parse().unwrap(), 80)])));
        assert!(!should_fallback_to_doh("nas", &Err("err".to_owned())));
        assert!(!should_fallback_to_doh("127.0.0.1", &Err("err".to_owned())));

        // Full resolution fallback when OS DNS returns [0.0.0.0] sinkhole for youtube.com
        let resolved_sinkhole = resolve_host_addrs_with_fallback(
            "youtube.com",
            Ok(vec![SocketAddr::new("0.0.0.0".parse().unwrap(), 443)]),
            &local,
            false,
            || async {
                Ok(vec![SocketAddr::new("142.250.185.206".parse().unwrap(), 443)])
            },
        )
        .await
        .unwrap();
        assert_eq!(
            resolved_sinkhole,
            vec![SocketAddr::new("142.250.185.206".parse().unwrap(), 443)]
        );

        // Full resolution fallback when OS DNS fails completely
        let resolved_err = resolve_host_addrs_with_fallback(
            "youtu.be",
            Err("DNS resolution failed for host 'youtu.be'".to_owned()),
            &local,
            false,
            || async {
                Ok(vec![SocketAddr::new("142.250.185.174".parse().unwrap(), 443)])
            },
        )
        .await
        .unwrap();
        assert_eq!(
            resolved_err,
            vec![SocketAddr::new("142.250.185.174".parse().unwrap(), 443)]
        );

        // If OS DNS returns 127.0.0.1, DoH MUST NOT be consulted and SSRF must reject it
        let ssrf_blocked = resolve_host_addrs_with_fallback(
            "evil.example",
            Ok(vec![SocketAddr::new("127.0.0.1".parse().unwrap(), 443)]),
            &local,
            false,
            || async { panic!("DoH fallback must not run for 127.0.0.1 SSRF result") },
        )
        .await
        .unwrap_err();
        assert!(ssrf_blocked.contains("SSRF"), "unexpected error: {ssrf_blocked}");

        // Even if DoH returns a private IP while allow_private == false, SSRF still blocks it
        let doh_private_blocked = resolve_host_addrs_with_fallback(
            "youtube.com",
            Ok(vec![SocketAddr::new("0.0.0.0".parse().unwrap(), 443)]),
            &local,
            false,
            || async {
                Ok(vec![SocketAddr::new("192.168.1.1".parse().unwrap(), 443)])
            },
        )
        .await
        .unwrap_err();
        assert!(
            doh_private_blocked.contains("SSRF"),
            "unexpected error: {doh_private_blocked}"
        );

        // In allow_private mode, 192.168.x.x is allowed and 0.0.0.0 sinkhole still falls back to DoH
        let allowed_lan = resolve_host_addrs_with_fallback(
            "nas.local",
            Ok(vec![SocketAddr::new("192.168.10.50".parse().unwrap(), 80)]),
            &local,
            true,
            || async { panic!("DoH fallback must not run for .local") },
        )
        .await
        .unwrap();
        assert_eq!(
            allowed_lan,
            vec![SocketAddr::new("192.168.10.50".parse().unwrap(), 80)]
        );
    }

    #[tokio::test]
    async fn doh_http_client_queries_endpoints_and_falls_back_to_second_provider() {
        let listener1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener1.local_addr().unwrap();
        let app1 = Router::new().route(
            "/dns-query",
            get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "upstream error") }),
        );
        let srv1 = tokio::spawn(async move { axum::serve(listener1, app1).await.unwrap() });

        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let app2 = Router::new().route(
            "/resolve",
            get(|headers: HeaderMap, Query(params): Query<HashMap<String, String>>| async move {
                let accept = headers
                    .get(header::ACCEPT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                assert_eq!(accept, "application/dns-json");
                assert_eq!(params.get("name").map(String::as_str), Some("youtube.com"));
                assert_eq!(params.get("type").map(String::as_str), Some("A"));
                Json(json!({
                    "Status": 0,
                    "Answer": [
                        { "name": "youtube.com.", "type": 1, "TTL": 120, "data": "142.250.185.206" }
                    ]
                }))
            }),
        );
        let srv2 = tokio::spawn(async move { axum::serve(listener2, app2).await.unwrap() });

        let ep1 = format!("http://{addr1}/dns-query");
        let ep2 = format!("http://{addr2}/resolve");
        let resolved = resolve_via_doh_endpoints(&[&ep1, &ep2], "youtube.com", 443)
            .await
            .unwrap();
        assert_eq!(
            resolved,
            vec![SocketAddr::new("142.250.185.206".parse().unwrap(), 443)]
        );

        srv1.abort();
        srv2.abort();
    }

    #[tokio::test]
    async fn web_fetch_ssrf_safe_with_policy_honors_allow_private_and_public_youtube_urls() {
        assert_eq!(
            validate_fetch_url("youtu.be/dQw4w9WgXcQ").unwrap().as_str(),
            "https://youtu.be/dQw4w9WgXcQ"
        );
        assert_eq!(
            validate_fetch_url("m.youtube.com").unwrap().as_str(),
            "https://m.youtube.com/"
        );
        assert_eq!(
            validate_fetch_url("youtube.com/results?search_query=https://other.com")
                .unwrap()
                .as_str(),
            "https://youtube.com/results?search_query=https://other.com"
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/page",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    "<html><head><title>Permissive OK</title></head><body><p>Hello LAN</p></body></html>",
                )
            }),
        );
        let srv = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dns_jobs = Arc::new(Semaphore::new(4));
        let url = format!("http://{addr}/page");

        let blocked = web_fetch_ssrf_safe_with_policy(&url, dns_jobs.clone(), false)
            .await
            .err()
            .unwrap();
        assert!(blocked.contains("SSRF"), "unexpected error: {blocked}");

        let allowed = web_fetch_ssrf_safe_with_policy(&url, dns_jobs, true)
            .await
            .unwrap();
        assert_eq!(allowed.status, 200);
        assert_eq!(allowed.title, "Permissive OK");
        assert!(allowed.text.contains("Hello LAN"));

        srv.abort();
    }

    #[tokio::test]
    async fn live_web_proxy_rewrites_html_strips_framing_headers_and_protects_session() {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream = Router::new()
            .route(
                "/",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, "/home")
                        .body(Body::empty())
                        .unwrap()
                }),
            )
            .route(
                "/home",
                get(|| async {
                let html = concat!(
                    "<!doctype html><html><head>",
                    "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\">",
                    "<link rel=\"compression-dictionary\" href=\"/shared_dict/test.dict\">",
                    "<style>body{background:url(/bg.png)}</style>",
                    "<link rel=\"modulepreload\" crossorigin=\"use-credentials\" href=\"/assets/m.js\">",
                    "<link rel=\"stylesheet\" href=\"/app.css\" integrity=\"sha256-abc\">",
                    "<script src=\"/app.js\" integrity=\"sha256-xyz\">if(1<2){}</script>",
                    "</head><body>",
                    "<a href=\"/search?q=1\" target=\"_top\">Search</a>",
                    "<a href=\"/next\" target=\"_blank\">Next</a>",
                    "<form action=\"/submit\" method=\"post\"><input name=\"q\"></form>",
                    "<img src=\"//cdn.test/logo.png\" srcset=\"/a.png 1x, /b.png 2x\">",
                    "</body></html>"
                );
                let mut r = Response::new(Body::from(html));
                *r.status_mut() = StatusCode::OK;
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
                r.headers_mut()
                    .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
                r.headers_mut().insert(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("frame-ancestors 'none'"),
                );
                r.headers_mut().append(
                    header::SET_COOKIE,
                    HeaderValue::from_static("openbot_session=hijack; Path=/; Secure"),
                );
                r.headers_mut().append(
                    header::SET_COOKIE,
                    HeaderValue::from_static("pref=dark; Domain=.example.com; Path=/; Secure"),
                );
                r.headers_mut()
                    .insert("x-sg-cs", HeaderValue::from_static("ok-header"));
                r
            }),
        )
        .route(
            "/big.js",
            get(|| async {
                let mut r = Response::new(Body::from(vec![b'a'; 5 * 1024 * 1024]));
                *r.status_mut() = StatusCode::OK;
                r.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/javascript"),
                );
                r
            }),
        )
        .route(
            "/echo-rpc",
            post(|hdrs: HeaderMap| async move {
                let api_key = hdrs
                    .get("x-goog-api-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let cookie_hdr = hdrs
                    .get(header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let origin_hdr = hdrs
                    .get(header::ORIGIN)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let ref_hdr = hdrs
                    .get(header::REFERER)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                Json(json!({
                    "apiKey": api_key,
                    "cookie": cookie_hdr,
                    "origin": origin_hdr,
                    "referer": ref_hdr,
                }))
            }),
        );
        let upstream_srv = tokio::spawn(async move { axum::serve(upstream_listener, upstream).await.unwrap() });

        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).unwrap();
        let db_path = std::env::temp_dir().join(format!("openbot-vc-proxy-{:x}.db", u64::from_le_bytes(rnd)));
        let ws_root = temp_workspace("proxy");
        let db = Arc::new(Storage::open(&db_path).unwrap());

        let origin = "http://127.0.0.1:3010";
        let host = "127.0.0.1:3010";
        let auth = AuthState::new(
            db.clone(),
            origin,
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let vc = VirtualComputerState::new(auth.clone(), ws_root.clone());
        let app = local_auth::router(auth).merge(router(vc.clone()));
        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("origin", origin)
            .header("host", host)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#,
            ))
            .unwrap();
        let setup_resp = app.clone().oneshot(setup).await.unwrap();
        assert_eq!(setup_resp.status(), StatusCode::NO_CONTENT);
        let cookie = setup_resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        {
            let handle = vc.bot_handle("ps5-virtual").unwrap();
            let mut guard = handle.lock().unwrap();
            guard.allow_all_web_pages = true;
            guard.current_url = format!("http://{upstream_addr}/home");
        }

        let page_req = Request::builder()
            .uri("/api/v2/organizations/default/computers/ps5-virtual/page")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let page_resp = app.clone().oneshot(page_req).await.unwrap();
        assert_eq!(page_resp.status(), StatusCode::OK);
        let page_json: Value = serde_json::from_slice(
            &to_bytes(page_resp.into_body(), 16 * 1024).await.unwrap(),
        )
        .unwrap();
        let proxy_url = page_json["proxyUrl"].as_str().unwrap().to_owned();
        assert!(proxy_url.starts_with("/browse/ps5-virtual/"));
        assert!(proxy_url.ends_with(&format!("/http/{upstream_addr}/home")));

        let bad_tok_req = Request::builder()
            .uri(&format!("/browse/ps5-virtual/00000000000000000000000000000000/http/{upstream_addr}/home"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.clone().oneshot(bad_tok_req).await.unwrap().status(), StatusCode::FORBIDDEN);

        let proxied_resp = app
            .clone()
            .oneshot(Request::builder().uri(&proxy_url).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(proxied_resp.status(), StatusCode::OK);
        assert_eq!(
            proxied_resp.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "SAMEORIGIN"
        );
        assert!(proxied_resp.headers().get(header::CONTENT_SECURITY_POLICY).is_none());
        let set_cookies: Vec<String> = proxied_resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        assert!(!set_cookies.iter().any(|c| c.contains("openbot_session")));
        assert!(set_cookies.iter().any(|c| c.contains("pref=dark") && !c.contains("Secure")));

        let expose_hdr = proxied_resp
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        assert!(expose_hdr.contains("x-sg-cs"), "missing x-sg-cs in {expose_hdr}");

        let html = String::from_utf8(
            to_bytes(proxied_resp.into_body(), 64 * 1024).await.unwrap().to_vec(),
        )
        .unwrap();
        assert!(html.contains("data-openbot-proxy=\"1\""));
        assert!(html.contains("randomUUID"));
        assert!(html.contains("localStorage"));
        assert!(html.contains("withCredentials"));
        assert!(html.contains("contentWindow"));
        assert!(!html.contains("/shared_dict/test.dict"));
        assert!(html.contains(&format!("/http/{upstream_addr}/search?q=1\"")));
        assert!(html.contains(&format!("/http/{upstream_addr}/submit\"")));
        assert!(html.contains(&format!("/http/{upstream_addr}/bg.png\"")));
        assert!(html.contains("/http/cdn.test/logo.png\""));
        assert!(html.contains("target=\"_self\""));
        assert!(!html.contains("target=\"_blank\""));
        assert!(!html.contains("crossorigin="));
        assert!(html.contains("History.prototype"));
        assert!(!html.contains("integrity=\"sha256-"));
        assert!(!html.contains("script-src 'none'"));
        assert!(html.contains("if(1<2){}"));

        // Also test proxy_entry_redirect (/proxy?url=...)
        let entry_req = Request::builder()
            .uri(&format!(
                "/api/v2/organizations/default/computers/ps5-virtual/proxy?url=http%3A%2F%2F{upstream_addr}%2Fhome"
            ))
            .header("host", host)
            .header("origin", origin)
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let entry_resp = app.clone().oneshot(entry_req).await.unwrap();
        assert_eq!(entry_resp.status(), StatusCode::FOUND);
        assert_eq!(entry_resp.headers().get(header::LOCATION).unwrap(), proxy_url.as_str());

        // Root proxy path WITH trailing slash (`/browse/.../{host}/`) and without trailing slash (`/browse/.../{host}`)
        let browse_prefix = proxy_url.strip_suffix("/home").unwrap();
        for root_uri in [format!("{browse_prefix}/"), browse_prefix.to_string()] {
            let root_resp = app
                .clone()
                .oneshot(Request::builder().uri(&root_uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(root_resp.status(), StatusCode::FOUND, "root proxy route failed for {root_uri}");
            assert_eq!(root_resp.headers().get(header::LOCATION).unwrap(), proxy_url.as_str());
            assert_eq!(root_resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
        }

        // Verify >4MB JS bundles stream completely without truncation.
        let big_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&format!("{browse_prefix}/big.js"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(big_resp.status(), StatusCode::OK);
        let big_bytes = to_bytes(big_resp.into_body(), 6 * 1024 * 1024).await.unwrap();
        assert_eq!(big_bytes.len(), 5 * 1024 * 1024);

        // Verify custom request headers, mapped Origin/Referer, and server-side cookie jar replay.
        let rpc_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("{browse_prefix}/echo-rpc"))
                    .header("x-goog-api-key", "test-key-123")
                    .header("origin", origin)
                    .header("referer", format!("{origin}{proxy_url}"))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rpc_resp.status(), StatusCode::OK);
        let echo_json: Value = serde_json::from_slice(
            &to_bytes(rpc_resp.into_body(), 16 * 1024).await.unwrap(),
        )
        .unwrap();
        assert_eq!(echo_json["apiKey"], "test-key-123");
        assert!(echo_json["cookie"].as_str().unwrap().contains("pref=dark"));
        assert_eq!(echo_json["origin"], format!("http://{upstream_addr}"));
        assert_eq!(echo_json["referer"], format!("http://{upstream_addr}/home"));

        upstream_srv.abort();
        drop(db);
        let _ = fs::remove_file(db_path);
        let _ = fs::remove_dir_all(ws_root);
    }
}
