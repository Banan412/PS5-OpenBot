//! Local account backend. Not enabled unless explicitly wired and configured.
//! All mutations require the exact configured browser origin and JSON requests.
use crate::storage::Storage;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

const COOKIE: &str = "openbot_session";
const ABSOLUTE_SECONDS: i64 = 8 * 3600;
const IDLE_SECONDS: i64 = 30 * 60;
const SETUP_LIFETIME: Duration = Duration::from_secs(15 * 60);
const ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
const MAX_ATTEMPTS_PER_KEY: usize = 5;
const MAX_GLOBAL_ATTEMPTS: usize = 30;
const MAX_TRACKED_KEYS: usize = 64;

#[derive(Default)]
struct AttemptLimiter {
    global: VecDeque<Instant>,
    per_key: HashMap<[u8; 32], VecDeque<Instant>>,
}

impl AttemptLimiter {
    fn prune_queue(queue: &mut VecDeque<Instant>, now: Instant) {
        while queue
            .front()
            .is_some_and(|t| now.duration_since(*t) >= ATTEMPT_WINDOW)
        {
            queue.pop_front();
        }
    }

    fn take(&mut self, key: [u8; 32], now: Instant) -> bool {
        Self::prune_queue(&mut self.global, now);
        self.per_key.retain(|_, queue| {
            Self::prune_queue(queue, now);
            !queue.is_empty()
        });
        if self.global.len() >= MAX_GLOBAL_ATTEMPTS {
            return false;
        }
        if let Some(queue) = self.per_key.get(&key) {
            if queue.len() >= MAX_ATTEMPTS_PER_KEY {
                return false;
            }
        } else if self.per_key.len() >= MAX_TRACKED_KEYS {
            return false;
        }
        self.global.push_back(now);
        self.per_key.entry(key).or_default().push_back(now);
        true
    }
}

#[derive(Clone, Copy)]
struct SetupConfig {
    token_hash: Option<[u8; 32]>,
    deadline: Option<Instant>,
}

#[derive(Clone)]
pub struct AuthState {
    pub(crate) db: Arc<Storage>,
    origin_policy: crate::origin::OriginPolicy,
    origin_jobs: Arc<Semaphore>,
    secure_cookie: bool,
    setup: Option<SetupConfig>,
    jobs: Arc<Semaphore>,
    pub(crate) db_jobs: Arc<Semaphore>,
    attempts: Arc<Mutex<AttemptLimiter>>,
}

impl AuthState {
    /// `origin` must be the exact externally visible http(s) origin (no trailing slash).
    /// Setup token is operator-provisioned over a private channel, not logged or stored.
    /// Use a newly generated, high-entropy token on each startup. An absent token disables setup.
    pub fn new(
        db: Arc<Storage>,
        origin: &str,
        setup_token: Option<&str>,
    ) -> Result<Self, &'static str> {
        let origin_policy = crate::origin::OriginPolicy::exact(origin)?;
        Self::with_policy(db, origin_policy, setup_token)
    }

    pub(crate) fn new_automatic(
        db: Arc<Storage>,
        bind: std::net::Ipv4Addr,
        port: u16,
        token: Option<&str>,
    ) -> Result<Self, &'static str> {
        let origin_policy = crate::origin::OriginPolicy::automatic_http_v4(bind, port)?;
        Self::with_policy(db, origin_policy, token)
    }

    fn with_policy(
        db: Arc<Storage>,
        origin_policy: crate::origin::OriginPolicy,
        setup_token: Option<&str>,
    ) -> Result<Self, &'static str> {
        if let Some(token) = setup_token {
            if token.len() < 32 || token.len() > 256 {
                return Err("setup token must have 32-256 characters");
            }
        }
        let secure_cookie = origin_policy.is_https();
        Ok(Self {
            db,
            origin_policy,
            origin_jobs: Arc::new(Semaphore::new(4)),
            secure_cookie,
            setup: setup_token.map(|s| SetupConfig {
                token_hash: Some(digest(s.as_bytes())),
                deadline: Some(Instant::now() + SETUP_LIFETIME),
            }),
            jobs: Arc::new(Semaphore::new(1)),
            db_jobs: Arc::new(Semaphore::new(16)),
            attempts: Arc::new(Mutex::new(AttemptLimiter::default())),
        })
    }

    pub(crate) fn with_ps5_open_setup(mut self, require_token: bool) -> Self {
        let token_hash = if require_token {
            self.setup.and_then(|c| c.token_hash)
        } else {
            None
        };
        if !require_token || token_hash.is_some() {
            self.setup = Some(SetupConfig {
                token_hash,
                deadline: None,
            });
        }
        self
    }

    pub(crate) async fn valid_origin(&self, headers: &HeaderMap) -> bool {
        if self.origin_policy.requires_interface_lookup() {
            let Ok(permit) = self.origin_jobs.clone().try_acquire_owned() else {
                return false;
            };
            let policy = self.origin_policy.clone();
            let headers = headers.clone();
            return tokio::task::spawn_blocking(move || {
                let _permit = permit;
                policy.validate(&headers, crate::origin::system_ipv4)
            })
            .await
            .unwrap_or(false);
        }
        self.origin_policy.validate(headers, || Ok(Vec::new()))
    }

    // Bounded global + per-key rate limiter prevents cross-account lockout and bounds memory.
    fn take_attempt(&self, key: [u8; 32]) -> bool {
        let Ok(mut limiter) = self.attempts.lock() else {
            return false;
        };
        limiter.take(key, Instant::now())
    }
}

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route("/api/port/auth/status", get(status))
        .route("/api/port/auth/setup", post(setup))
        .route("/api/port/auth/login", post(login))
        .route("/api/port/auth/logout", post(logout))
        .route("/api/v2/people/me/organizations", get(organizations))
        .route(
            "/api/v2/organizations/{organization}/people/me",
            get(person).patch(crate::compat_extra::update_person_me),
        )
        .layer(DefaultBodyLimit::max(4096))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Setup {
    #[serde(default)]
    setup_token: String,
    email: String,
    name: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    email: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

fn now() -> Result<i64, ()> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())
}
fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
fn attempt_key(scope: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(scope);
    hasher.update([0]);
    hasher.update(value);
    hasher.finalize().into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn random_hex() -> Result<String, ()> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ())?;
    Ok(hex(&bytes))
}
fn kdf() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19 * 1024, 2, 1, None).expect("valid fixed parameters"),
    )
}
fn normalized_email(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() > 254
        || !s.is_ascii()
        || s.bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || s.matches('@').count() != 1
    {
        return None;
    }
    let (local, domain) = s.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(s.to_ascii_lowercase())
}
fn valid_password(s: &str) -> bool {
    (12..=1024).contains(&s.len()) && !s.contains('\0')
}
fn error(code: StatusCode, msg: &'static str) -> Response {
    let mut r = (code, Json(json!({"error":msg}))).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}
fn internal() -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, "service unavailable")
}
fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}
fn set_cookie(token: &str, secure: bool) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ABSOLUTE_SECONDS}{}",
        if secure { "; Secure" } else { "" }
    )
}
fn expired_cookie(secure: bool) -> String {
    format!(
        "{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        if secure { "; Secure" } else { "" }
    )
}
fn token(headers: &HeaderMap) -> Option<String> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE).iter() {
        for pair in header.to_str().ok()?.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key == COOKIE {
                if found.is_some()
                    || value.len() != 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return None;
                }
                found = Some(value.to_string());
            }
        }
    }
    found
}

/// Binds a short-lived socket ticket to the actual browser session without retaining its cookie.
pub(crate) fn session_binding(headers: &HeaderMap) -> Option<[u8; 32]> {
    token(headers).map(|value| digest(value.as_bytes()))
}

async fn status(State(s): State<AuthState>) -> Response {
    let db = s.db.clone();
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return error(StatusCode::TOO_MANY_REQUESTS, "try later");
    };
    let Ok(Ok(setup_required)) = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(|c| {
            Ok(
                c.query_row("SELECT NOT EXISTS(SELECT 1 FROM auth_users)", [], |r| {
                    r.get::<_, bool>(0)
                })?,
            )
        })
    })
    .await
    else {
        return internal();
    };
    let setup_available = setup_required
        && s.setup
            .is_some_and(|cfg| cfg.deadline.is_none_or(|d| Instant::now() < d));
    let setup_code_required = s.setup.is_some_and(|cfg| cfg.token_hash.is_some());
    no_store(
        Json(
            json!({"enabled":true,"setupRequired":setup_required,"setupAvailable":setup_available,"setupCodeRequired":setup_code_required}),
        )
        .into_response(),
    )
}

async fn setup(
    State(s): State<AuthState>,
    headers: HeaderMap,
    Json(input): Json<Setup>,
) -> Response {
    if !s.valid_origin(&headers).await {
        return error(StatusCode::FORBIDDEN, "forbidden");
    }
    if !s.take_attempt(attempt_key(b"setup", b"")) {
        return error(StatusCode::TOO_MANY_REQUESTS, "try later");
    }
    let Some(cfg) = s.setup else {
        return error(StatusCode::FORBIDDEN, "setup unavailable");
    };
    if cfg.deadline.is_some_and(|until| Instant::now() >= until) {
        return error(StatusCode::FORBIDDEN, "setup unavailable");
    }
    if let Some(expected) = cfg.token_hash {
        if !bool::from(expected.ct_eq(&digest(input.setup_token.as_bytes()))) {
            return error(StatusCode::FORBIDDEN, "setup unavailable");
        }
    }
    let Some(email) = normalized_email(&input.email) else {
        return error(StatusCode::BAD_REQUEST, "invalid account details");
    };
    let name = input.name.trim().to_string();
    if name.is_empty()
        || name.len() > 100
        || name.contains('\0')
        || !valid_password(&input.password)
    {
        return error(StatusCode::BAD_REQUEST, "invalid account details");
    }
    let Ok(permit) = s.jobs.clone().try_acquire_owned() else {
        return error(StatusCode::TOO_MANY_REQUESTS, "try later");
    };
    let db = s.db.clone();
    let secure = s.secure_cookie;
    let result = tokio::task::spawn_blocking(move || -> Result<Option<String>, ()> {
        let _permit = permit;
        let mut salt_bytes = [0u8; 16];
        getrandom::getrandom(&mut salt_bytes).map_err(|_| ())?;
        let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| ())?;
        let password_hash = kdf().hash_password(input.password.as_bytes(), &salt).map_err(|_| ())?.to_string();
        if cfg.deadline.is_some_and(|until| Instant::now() >= until) { return Ok(None); }
        let user = random_hex()?; let session = random_hex()?; let now = now()?;
        db.try_with_connection(|conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if cfg.deadline.is_some_and(|until| Instant::now() >= until) { return Ok(None); }
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM auth_users)", [], |r| r.get(0))?;
            if exists { return Ok(None); }
            tx.execute("INSERT INTO auth_users(id,email,display_name,password_hash) VALUES (?1,?2,?3,?4)", params![user,email,name,password_hash])?;
            tx.execute("INSERT INTO auth_organizations(id,slug,name) VALUES ('default','default','OpenBot')", [])?;
            tx.execute("INSERT INTO auth_memberships(user_id,organization_id,role) VALUES (?1,'default','owner')", params![user])?;
            tx.execute("INSERT INTO auth_sessions(token_hash,user_id,created_at,last_seen_at,expires_at) VALUES (?1,?2,?3,?3,?4)", params![digest(session.as_bytes()).as_slice(),user,now,now+ABSOLUTE_SECONDS])?;
            tx.commit()?;
            Ok(Some(session))
        }).map_err(|_| ())
    }).await;
    match result {
        Ok(Ok(Some(session))) => cookie_response(&session, secure),
        Ok(Ok(None)) => error(StatusCode::CONFLICT, "setup unavailable"),
        _ => internal(),
    }
}
fn cookie_response(session: &str, secure: bool) -> Response {
    let mut r = StatusCode::NO_CONTENT.into_response();
    if let Ok(cookie) = HeaderValue::from_str(&set_cookie(session, secure)) {
        r.headers_mut().insert(header::SET_COOKIE, cookie);
    } else {
        return internal();
    }
    no_store(r)
}

async fn login(
    State(s): State<AuthState>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Response {
    if !s.valid_origin(&headers).await {
        return error(StatusCode::FORBIDDEN, "forbidden");
    }
    let normalized = normalized_email(&input.email);
    let rate_key = match normalized.as_deref() {
        Some(email) => attempt_key(b"login", email.as_bytes()),
        None => attempt_key(b"login_invalid", b""),
    };
    if !s.take_attempt(rate_key) {
        return error(StatusCode::TOO_MANY_REQUESTS, "try later");
    }
    let email = normalized.unwrap_or_default();
    if input.password.len() > 1024 {
        return error(StatusCode::UNAUTHORIZED, "invalid credentials");
    }
    let Ok(permit) = s.jobs.clone().try_acquire_owned() else {
        return error(StatusCode::TOO_MANY_REQUESTS, "try later");
    };
    let db = s.db.clone();
    let secure = s.secure_cookie;
    let result=tokio::task::spawn_blocking(move || -> Result<Option<String>, ()> {
        let _permit=permit;
        let account = db.try_with_connection(|c| Ok(c.query_row("SELECT id,password_hash FROM auth_users WHERE email=?1 AND revoked=0", params![email], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?)).map_err(|_| ())?;
        // Always perform a real KDF, including unknown identities, to avoid the obvious timing oracle.
        let dummy = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$MhD5EtW5Irgp6K3pCrXaZ5PymKkn1BZpFZ/Z9OevcYk";
        let hash = account.as_ref().map(|x|x.1.as_str()).unwrap_or(dummy);
        let parsed = PasswordHash::new(hash).map_err(|_| ())?;
        let valid = kdf().verify_password(input.password.as_bytes(), &parsed).is_ok();
        let Some((user,_)) = account else { return Ok(None); };
        if !valid { return Ok(None); }
        let session=random_hex()?; let now=now()?;
        db.try_with_connection(|c| {
            c.execute("DELETE FROM auth_sessions WHERE expires_at<=?1 OR last_seen_at<=?2", params![now, now - IDLE_SECONDS])?;
            c.execute("INSERT INTO auth_sessions(token_hash,user_id,created_at,last_seen_at,expires_at) SELECT ?1,id,?2,?2,?3 FROM auth_users WHERE id=?4 AND revoked=0",params![digest(session.as_bytes()).as_slice(),now,now+ABSOLUTE_SECONDS,user]).and_then(|count| if count==1 { Ok(()) } else { Err(rusqlite::Error::QueryReturnedNoRows) })?;
            Ok(())
        }).map_err(|_| ())?;
        Ok(Some(session))
    }).await;
    match result {
        Ok(Ok(Some(session))) => cookie_response(&session, secure),
        Ok(Ok(None)) => error(StatusCode::UNAUTHORIZED, "invalid credentials"),
        _ => internal(),
    }
}

async fn logout(State(s): State<AuthState>, headers: HeaderMap, Json(_): Json<Empty>) -> Response {
    if !s.valid_origin(&headers).await {
        return error(StatusCode::FORBIDDEN, "forbidden");
    }
    if let Some(t) = token(&headers) {
        let db = s.db.clone();
        let hash = digest(t.as_bytes());
        let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
            return error(StatusCode::TOO_MANY_REQUESTS, "try later");
        };
        if !matches!(
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                db.try_with_connection(|c| {
                    c.execute(
                        "DELETE FROM auth_sessions WHERE token_hash=?1",
                        params![hash.as_slice()],
                    )?;
                    Ok(())
                })
            })
            .await,
            Ok(Ok(()))
        ) {
            return internal();
        }
    }
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&expired_cookie(s.secure_cookie)).expect("constant cookie"),
    );
    no_store(r)
}

#[derive(Clone)]
pub(crate) struct Identity {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) name: String,
    pub(crate) organization: String,
    pub(crate) slug: String,
    pub(crate) org_name: String,
    pub(crate) role: String,
}
fn query_active_identity(
    c: &rusqlite::Connection,
    hash: &[u8; 32],
    now: i64,
) -> rusqlite::Result<Option<Identity>> {
    c.query_row(
        "SELECT u.id,u.email,u.display_name,o.id,o.slug,o.name,m.role \
         FROM auth_sessions s \
         JOIN auth_users u ON u.id=s.user_id \
         JOIN auth_memberships m ON m.user_id=u.id \
         JOIN auth_organizations o ON o.id=m.organization_id \
         WHERE s.token_hash=?1 AND u.revoked=0 AND s.expires_at>?2 AND s.last_seen_at>?3 \
         ORDER BY o.id LIMIT 1",
        params![hash.as_slice(), now, now - IDLE_SECONDS],
        |r| {
            Ok(Identity {
                id: r.get(0)?,
                email: r.get(1)?,
                name: r.get(2)?,
                organization: r.get(3)?,
                slug: r.get(4)?,
                org_name: r.get(5)?,
                role: r.get(6)?,
            })
        },
    )
    .optional()
}

async fn resolve_identity(
    s: &AuthState,
    headers: &HeaderMap,
    refresh_idle: bool,
) -> Result<Option<Identity>, ()> {
    let Some(t) = token(headers) else {
        return Ok(None);
    };
    let hash = digest(t.as_bytes());
    let db = s.db.clone();
    let permit = s.db_jobs.clone().try_acquire_owned().map_err(|_| ())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let now = now()?;
        db.try_with_connection(|c| {
            if refresh_idle {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let user = query_active_identity(&tx, &hash, now)?;
                if user.is_some() {
                    tx.execute(
                        "UPDATE auth_sessions SET last_seen_at=?2 WHERE token_hash=?1",
                        params![hash.as_slice(), now],
                    )?;
                }
                tx.commit()?;
                Ok(user)
            } else {
                Ok(query_active_identity(c, &hash, now)?)
            }
        })
        .map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

pub(crate) async fn identity(s: &AuthState, headers: &HeaderMap) -> Result<Option<Identity>, ()> {
    resolve_identity(s, headers, true).await
}

/// Verifies session validity, revocation, idle expiry, and absolute expiry without
/// extending `last_seen_at` (for background WebSocket/SSE liveness checks).
pub(crate) async fn check_session_without_refresh(
    s: &AuthState,
    headers: &HeaderMap,
) -> Result<Option<Identity>, ()> {
    resolve_identity(s, headers, false).await
}
async fn organizations(State(s): State<AuthState>, headers: HeaderMap) -> Response {
    match identity(&s,&headers).await {
        Ok(Some(i)) => no_store(Json(json!({"organizations":[{"id":i.organization,"slug":i.slug,"name":i.org_name,"role":i.role,"active":true,"personal":true}],"canCreate":false,"nextCursor":null})).into_response()),
        Ok(None) => error(StatusCode::UNAUTHORIZED,"sign in required"), Err(()) => internal()
    }
}
async fn person(
    State(s): State<AuthState>,
    Path(organization): Path<String>,
    headers: HeaderMap,
) -> Response {
    match identity(&s,&headers).await {
        Ok(Some(i)) if organization==i.organization || organization==i.slug => no_store(Json(json!({"person":{"id":i.id,"email":i.email,"name":i.name,"image":null,"role":i.role,"needsName":false,"onboarding":null,"providers":[],"lastSignedInAt":null,"revoked":false,"configuredAdmin":false},"openbotVersion":null})).into_response()),
        Ok(Some(_)) => error(StatusCode::NOT_FOUND,"not found"), Ok(None) => error(StatusCode::UNAUTHORIZED,"sign in required"), Err(())=>internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    fn fixture_state(origin: &str) -> (AuthState, Router, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("openbot-auth-{}.db", random_hex().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        // Isolated tests may run before migration v2 is integrated in storage.
        db.try_with_connection(|c| {
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'auth_users')",
                [],
                |r| r.get(0),
            )?;
            if !exists {
                c.execute_batch(include_str!("../migrations/0002_local_auth.sql"))?;
            }
            Ok(())
        })
        .unwrap();
        let state = AuthState::new(
            db,
            origin,
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let r = router(state.clone());
        (state, r, path)
    }
    fn fixture() -> (Router, std::path::PathBuf) {
        let (_, r, path) = fixture_state("http://example.test:3010");
        (r, path)
    }
    fn request_with_host(path: &str, origin: &str, host: Option<&str>, body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("origin", origin)
            .header("content-type", "application/json");
        if let Some(host) = host {
            builder = builder.header(header::HOST, host);
        }
        builder.body(Body::from(body.to_owned())).unwrap()
    }
    fn request(path: &str, origin: &str, body: &str) -> Request<Body> {
        request_with_host(path, origin, Some("example.test:3010"), body)
    }
    #[tokio::test]
    async fn setup_origin_single_use_session_and_logout() {
        let (r, path) = fixture();
        let bad = r
            .clone()
            .oneshot(request("/api/port/auth/setup", "http://evil.test", r#"{}"#))
            .await
            .unwrap();
        assert!(
            bad.status() == StatusCode::FORBIDDEN
                || bad.status() == StatusCode::UNPROCESSABLE_ENTITY
        );
        let payload = r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"long secure password"}"#;
        let bad = r
            .clone()
            .oneshot(request("/api/port/auth/setup", "http://evil.test", payload))
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::FORBIDDEN);
        let setup = r
            .clone()
            .oneshot(request(
                "/api/port/auth/setup",
                "http://example.test:3010",
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);
        let cookie = setup.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let again = r
            .clone()
            .oneshot(request(
                "/api/port/auth/setup",
                "http://example.test:3010",
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::CONFLICT);
        let orgs = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/people/me/organizations")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(orgs.status(), StatusCode::OK);
        let body = to_bytes(orgs.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["organizations"][0]["role"], "owner");
        let logout = r
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/port/auth/logout")
                    .header("origin", "http://example.test:3010")
                    .header(header::HOST, "example.test:3010")
                    .header("content-type", "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
        let denied = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/people/me/organizations")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let missing = r
            .clone()
            .oneshot(request(
                "/api/port/auth/login",
                "http://example.test:3010",
                r#"{"email":"absent@example.test","password":"long secure password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let wrong = r
            .clone()
            .oneshot(request(
                "/api/port/auth/login",
                "http://example.test:3010",
                r#"{"email":"owner@example.test","password":"incorrect password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let login = r
            .clone()
            .oneshot(request(
                "/api/port/auth/login",
                "http://example.test:3010",
                r#"{"email":"owner@example.test","password":"long secure password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::NO_CONTENT);
        let new_cookie = login.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let wrong_org = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/organizations/other/people/me")
                    .header(header::COOKIE, &new_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_org.status(), StatusCode::NOT_FOUND);
        let me = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/organizations/default/people/me")
                    .header(header::COOKIE, new_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(me.status(), StatusCode::OK);
        drop(r);
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn setup_is_disabled_without_secret() {
        let path = std::env::temp_dir().join(format!("openbot-auth-{}.db", random_hex().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        db.try_with_connection(|c| {
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'auth_users')",
                [],
                |r| r.get(0),
            )?;
            if !exists {
                c.execute_batch(include_str!("../migrations/0002_local_auth.sql"))?;
            }
            Ok(())
        })
        .unwrap();
        let r = router(AuthState::new(db, "http://example.test:3010", None).unwrap());
        let resp = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/port/auth/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let data: serde_json::Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(data["setupAvailable"], false);
        drop(r);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn token_skips_valueless_cookies_around_session_cookie() {
        let valid = "a".repeat(64);
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("flag_before; {COOKIE}={valid}")).unwrap(),
        );
        assert_eq!(token(&h).as_deref(), Some(valid.as_str()));

        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{COOKIE}={valid}; flag_after;")).unwrap(),
        );
        assert_eq!(token(&h).as_deref(), Some(valid.as_str()));

        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("flag_only; ; other=1; {COOKIE}={valid}; tail"))
                .unwrap(),
        );
        assert_eq!(token(&h).as_deref(), Some(valid.as_str()));

        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("flag_only;"));
        assert_eq!(token(&h), None);

        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("flag; {COOKIE}={valid}; {COOKIE}={valid}")).unwrap(),
        );
        assert_eq!(token(&h), None);
    }

    #[tokio::test]
    async fn exact_mode_rejects_missing_and_mismatched_host_and_noncanonical_origins() {
        let path = std::env::temp_dir().join(format!("openbot-auth-{}.db", random_hex().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        assert!(AuthState::new(db.clone(), "https://Bot.Example", None).is_err());
        assert!(AuthState::new(db.clone(), "https://bot.example:443", None).is_err());
        drop(db);
        let _ = std::fs::remove_file(&path);

        let (_, r, path) = fixture_state("https://bot.example");
        let payload = r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"long secure password"}"#;

        let missing_host = r
            .clone()
            .oneshot(request_with_host(
                "/api/port/auth/setup",
                "https://bot.example",
                None,
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(missing_host.status(), StatusCode::FORBIDDEN);

        let mismatched_host = r
            .clone()
            .oneshot(request_with_host(
                "/api/port/auth/setup",
                "https://bot.example",
                Some("evil.example"),
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(mismatched_host.status(), StatusCode::FORBIDDEN);

        let ok = r
            .clone()
            .oneshot(request_with_host(
                "/api/port/auth/setup",
                "https://bot.example",
                Some("bot.example"),
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::NO_CONTENT);

        drop(r);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn check_session_without_refresh_does_not_extend_idle_and_enforces_expiry() {
        let (state, r, path) = fixture_state("http://example.test:3010");
        let payload = r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"long secure password"}"#;
        let setup = r
            .clone()
            .oneshot(request(
                "/api/port/auth/setup",
                "http://example.test:3010",
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);
        let cookie = setup.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        let token_hash = session_binding(&headers).unwrap();

        let current_now = now().unwrap();
        let stale_seen = current_now - 600;
        state
            .db
            .try_with_connection(|c| {
                c.execute(
                    "UPDATE auth_sessions SET last_seen_at=?2 WHERE token_hash=?1",
                    params![token_hash.as_slice(), stale_seen],
                )?;
                Ok(())
            })
            .unwrap();

        // Background check succeeds without refreshing last_seen_at.
        let checked = check_session_without_refresh(&state, &headers)
            .await
            .unwrap();
        assert!(checked.is_some());
        let after_check: i64 = state
            .db
            .try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT last_seen_at FROM auth_sessions WHERE token_hash=?1",
                    params![token_hash.as_slice()],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(after_check, stale_seen);

        // Foreground identity() extends last_seen_at.
        assert!(identity(&state, &headers).await.unwrap().is_some());
        let after_identity: i64 = state
            .db
            .try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT last_seen_at FROM auth_sessions WHERE token_hash=?1",
                    params![token_hash.as_slice()],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert!(after_identity >= current_now);

        // Idle expiry is enforced by check_session_without_refresh.
        state
            .db
            .try_with_connection(|c| {
                c.execute(
                    "UPDATE auth_sessions SET last_seen_at=?2 WHERE token_hash=?1",
                    params![token_hash.as_slice(), current_now - IDLE_SECONDS - 1],
                )?;
                Ok(())
            })
            .unwrap();
        assert!(check_session_without_refresh(&state, &headers)
            .await
            .unwrap()
            .is_none());

        // Absolute expiry is enforced.
        state
            .db
            .try_with_connection(|c| {
                c.execute(
                    "UPDATE auth_sessions SET last_seen_at=?2, expires_at=?3 WHERE token_hash=?1",
                    params![token_hash.as_slice(), current_now, current_now - 1],
                )?;
                Ok(())
            })
            .unwrap();
        assert!(check_session_without_refresh(&state, &headers)
            .await
            .unwrap()
            .is_none());

        // User revocation is enforced.
        state
            .db
            .try_with_connection(|c| {
                c.execute(
                    "UPDATE auth_sessions SET expires_at=?2 WHERE token_hash=?1",
                    params![token_hash.as_slice(), current_now + 3600],
                )?;
                c.execute("UPDATE auth_users SET revoked=1", [])?;
                Ok(())
            })
            .unwrap();
        assert!(check_session_without_refresh(&state, &headers)
            .await
            .unwrap()
            .is_none());

        drop(r);
        drop(state);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn per_key_rate_limit_isolates_accounts() {
        let (_, r, path) = fixture_state("http://example.test:3010");
        let setup_payload = r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"long secure password"}"#;
        let setup = r
            .clone()
            .oneshot(request(
                "/api/port/auth/setup",
                "http://example.test:3010",
                setup_payload,
            ))
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);

        for _ in 0..MAX_ATTEMPTS_PER_KEY {
            let res = r
                .clone()
                .oneshot(request(
                    "/api/port/auth/login",
                    "http://example.test:3010",
                    r#"{"email":"attacker@example.test","password":"wrong password 123"}"#,
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
        let limited = r
            .clone()
            .oneshot(request(
                "/api/port/auth/login",
                "http://example.test:3010",
                r#"{"email":"attacker@example.test","password":"wrong password 123"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        // Legitimate owner login is unaffected by another email's bucket.
        let owner = r
            .clone()
            .oneshot(request(
                "/api/port/auth/login",
                "http://example.test:3010",
                r#"{"email":"owner@example.test","password":"long secure password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(owner.status(), StatusCode::NO_CONTENT);

        drop(r);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn ps5_open_setup_never_expires_and_allows_empty_code() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "openbot-open-setup-{:x}.db",
            u64::from_le_bytes(random)
        ));
        let db = Arc::new(Storage::open(&path).unwrap());
        let state = AuthState::new(db, "http://example.test:3010", None)
            .unwrap()
            .with_ps5_open_setup(false);
        let r = router(state);
        let st = r
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/port/auth/status")
                    .header("host", "example.test:3010")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(st.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(st.into_body(), 1024).await.unwrap()).unwrap();
        assert_eq!(body["setupRequired"], true);
        assert_eq!(body["setupAvailable"], true);
        assert_eq!(body["setupCodeRequired"], false);

        let setup = r
            .clone()
            .oneshot(request(
                "/api/port/auth/setup",
                "http://example.test:3010",
                r#"{"email":"ps5@example.test","name":"PS5 Owner","password":"long secure password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);

        drop(r);
        std::fs::remove_file(path).unwrap();
    }
}
