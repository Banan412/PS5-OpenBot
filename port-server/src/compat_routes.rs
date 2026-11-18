//! OpenAPI-faithful compatibility & UI support routes for components,
//! bot attention, browser status, invitations, and read-only catalog views.
use crate::{
    local_auth::{identity, AuthState, Identity},
    storage::StorageError,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_BODY_BYTES: usize = 128 * 1024;
const MAX_ANNOUNCE_ITEMS: usize = 500;
const IDEMPOTENCY_TTL_SECS: i64 = 86_400;

/// Returns the SQL migration for compatibility tables (`0010_compat.sql`).
pub fn migration_sql() -> &'static str {
    include_str!("../migrations/0010_compat.sql")
}

/// Builds the router for all compatibility and missing frontend REST endpoints.
pub fn router(state: AuthState) -> Router {
    router_with_context(
        state,
        crate::context_manager::ContextManager::offline(
            crate::context_manager::DEFAULT_CONTEXT_LIMIT,
        ),
    )
}

#[derive(Clone)]
struct CompatContextState {
    auth: AuthState,
    context: crate::context_manager::ContextManager,
}

/// Builds the compatibility router wired with a shared `ContextManager`.
pub fn router_with_context(
    state: AuthState,
    context: crate::context_manager::ContextManager,
) -> Router {
    let context_router = Router::new()
        .route(
            "/api/v2/organizations/{organization}/conversations/{id}/context",
            get(get_conversation_context),
        )
        .with_state(CompatContextState {
            auth: state.clone(),
            context,
        });

    Router::new()
        .route(
            "/api/v2/organizations/{organization}/shortened-tool-names",
            get(shortened_tool_names),
        )
        .route(
            "/api/v2/organizations/{organization}/components",
            get(list_components),
        )
        .route(
            "/api/v2/organizations/{organization}/components/announce",
            post(announce_components),
        )
        .route(
            "/api/v2/organizations/{organization}/components/{component_id}",
            get(get_component).delete(delete_component),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/components",
            get(list_bot_components),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/components/{component_id}",
            put(allow_bot_component).delete(withhold_bot_component),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/bot-attention",
            get(bot_attention),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/browser",
            get(person_browser),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{bot_id}/browser",
            get(bot_browser),
        )
        .route("/api/v2/people/me/invitations", get(list_my_invitations))
        .route(
            "/api/v2/organizations/{organization}/invitations",
            get(list_org_invitations),
        )
        .route(
            "/api/v2/organizations/{organization}/app-setup",
            get(get_app_setup),
        )
        .route(
            "/api/v2/organizations/{organization}/skills",
            get(list_skills),
        )
        .route(
            "/api/v2/organizations/{organization}/shared-use-requests",
            get(list_shared_use_requests),
        )
        .route(
            "/api/v2/organizations/{organization}/app-access-requests",
            get(list_app_access_requests),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state.clone())
        .merge(context_router)
        .merge(crate::compat_extra::router(state))
}

pub(crate) fn problem(status: StatusCode, code: &str, detail: &str) -> Response {
    let category = match status {
        StatusCode::UNAUTHORIZED => "unauthenticated",
        StatusCode::FORBIDDEN => "permission",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::SERVICE_UNAVAILABLE => "dependency",
        _ => "validation",
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
            "retryable": false,
            "requestId": "unavailable",
            "traceId": "unavailable"
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

pub(crate) fn internal() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "SERVICE_UNAVAILABLE",
        "Service unavailable.",
    )
}

pub(crate) fn respond_json(status: StatusCode, value: Value) -> Response {
    let mut r = (status, Json(value)).into_response();
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}

pub(crate) fn respond_raw(status: StatusCode, body: String) -> Response {
    let mut r = if status == StatusCode::NO_CONTENT {
        status.into_response()
    } else {
        (status, body).into_response()
    };
    if status != StatusCode::NO_CONTENT {
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}

async fn authorize_any_org(s: &AuthState, h: &HeaderMap) -> Result<Identity, Response> {
    match identity(s, h).await {
        Ok(Some(i)) => Ok(i),
        Ok(None) => Err(problem(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Sign in required.",
        )),
        Err(_) => Err(internal()),
    }
}

pub(crate) async fn authorize(
    s: &AuthState,
    h: &HeaderMap,
    org: &str,
    write: bool,
) -> Result<Identity, Response> {
    if write && !s.valid_origin(h).await {
        return Err(problem(StatusCode::FORBIDDEN, "FORBIDDEN", "Forbidden."));
    }
    match identity(s, h).await {
        Ok(Some(i)) if i.organization == org || i.slug == org => Ok(i),
        Ok(Some(_)) => Err(problem(
            StatusCode::NOT_FOUND,
            "ORGANIZATION_NOT_FOUND",
            "Organization not found.",
        )),
        Ok(None) => Err(problem(
            StatusCode::UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Sign in required.",
        )),
        Err(_) => Err(internal()),
    }
}

pub(crate) fn is_admin(actor: &Identity) -> bool {
    actor.role == "owner" || actor.role == "admin"
}

pub(crate) fn require_person(actor: &Identity, person: &str) -> Result<(), Response> {
    if person == "me" || person == actor.id {
        Ok(())
    } else {
        Err(problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Own resources only.",
        ))
    }
}

pub(crate) fn idempotency_key(h: &HeaderMap) -> Result<String, Response> {
    let mut keys = h.get_all("idempotency-key").iter();
    match (keys.next(), keys.next()) {
        (Some(k), None) => match k.to_str() {
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
            "Idempotency-Key is required.",
        )),
    }
}

pub(crate) fn epoch() -> Result<i64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or(StorageError::InvalidDatabase("clock unavailable"))
}

pub(crate) fn parse_limit(q: &HashMap<String, String>) -> Result<usize, Response> {
    match q.get("limit") {
        None => Ok(50),
        Some(s) => s
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=100).contains(n))
            .ok_or_else(|| problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid limit.")),
    }
}

fn validate_cursor_format(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= 4096
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) fn parse_empty_list_paging(q: &HashMap<String, String>) -> Result<usize, Response> {
    let limit = parse_limit(q)?;
    if q.contains_key("cursor") {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid cursor.",
        ));
    }
    Ok(limit)
}

pub(crate) fn encode_cursor(offset: usize, scope_tag: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{offset}\n{scope_tag}"))
}

pub(crate) fn decode_cursor(q: &HashMap<String, String>, expected_scope_tag: &str) -> Result<usize, Response> {
    let Some(c) = q.get("cursor") else {
        return Ok(0);
    };
    if !validate_cursor_format(c) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid cursor.",
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(c).map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid cursor.",
        )
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid cursor.",
        )
    })?;
    let (offset_str, tag) = text.split_once('\n').ok_or_else(|| {
        problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid cursor.",
        )
    })?;
    if tag != expected_scope_tag {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Cursor does not match query.",
        ));
    }
    offset_str
        .parse::<usize>()
        .ok()
        .filter(|v| *v <= 100_000)
        .ok_or_else(|| {
            problem(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Invalid cursor.",
            )
        })
}

pub(crate) fn valid_non_empty_param(s: &str, max_len: usize) -> bool {
    !s.is_empty()
        && s.chars().count() <= max_len
        && s.chars().any(|c| !c.is_whitespace())
        && !s.chars().any(char::is_control)
}

pub(crate) async fn run_db<T, F>(s: &AuthState, f: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&mut rusqlite::Connection) -> Result<T, StorageError> + Send + 'static,
{
    let permit = s
        .db_jobs
        .clone()
        .try_acquire_owned()
        .map_err(|_| internal())?;
    let db = s.db.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(f)
    })
    .await
    .map_err(|_| internal())?
    .map_err(|_| internal())
}

pub(crate) fn fingerprint(method: &str, resource: &str, body: Option<&Value>) -> Vec<u8> {
    let mut d = Sha256::new();
    d.update(method.as_bytes());
    d.update([0]);
    d.update(resource.as_bytes());
    d.update([0]);
    if let Some(v) = body {
        d.update(v.to_string().as_bytes());
    }
    d.finalize().to_vec()
}

pub(crate) fn replay_idempotency(
    tx: &rusqlite::Connection,
    org: &str,
    actor_id: &str,
    key: &str,
    fp: &[u8],
    now: i64,
) -> Result<Option<(u16, String)>, StorageError> {
    tx.execute(
        "DELETE FROM port_compat_idempotency WHERE created_at < ?1",
        params![now - IDEMPOTENCY_TTL_SECS],
    )?;
    let existing: Option<(Vec<u8>, u16, String)> = tx
        .query_row(
            "SELECT fingerprint, status, body FROM port_compat_idempotency WHERE organization_id=?1 AND actor_id=?2 AND idem_key=?3",
            params![org, actor_id, key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    Ok(existing.map(|(old_fp, status, body)| {
        if old_fp == fp {
            (status, body)
        } else {
            (409, String::new())
        }
    }))
}

pub(crate) fn store_idempotency(
    tx: &rusqlite::Connection,
    org: &str,
    actor_id: &str,
    key: &str,
    fp: &[u8],
    now: i64,
    status: u16,
    body: &str,
) -> Result<(), StorageError> {
    tx.execute(
        "INSERT INTO port_compat_idempotency(organization_id, actor_id, idem_key, fingerprint, created_at, status, body) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![org, actor_id, key, fp, now, status, body],
    )?;
    Ok(())
}

pub(crate) fn format_iso_utc(c: &rusqlite::Connection, ts: Option<i64>) -> rusqlite::Result<Option<String>> {
    match ts {
        Some(n) => c.query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', ?1, 'unixepoch')",
            params![n],
            |r| r.get(0),
        ),
        None => Ok(None),
    }
}

// -----------------------------------------------------------------------------
// 1. GET /api/v2/organizations/{organization}/shortened-tool-names
// -----------------------------------------------------------------------------

async fn shortened_tool_names(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "names": {} }))
}

// -----------------------------------------------------------------------------
// 2. Components endpoints
// -----------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentAnnouncementPayload {
    components: Vec<AnnouncedComponentInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnouncedComponentInput {
    name: String,
    title: String,
    kind: String,
    description: String,
}

struct CleanComponentInput {
    name: String,
    title: String,
    kind: String,
    description: String,
}

fn validate_announcement(body: &Value) -> Result<Vec<CleanComponentInput>, Response> {
    let payload: ComponentAnnouncementPayload =
        serde_json::from_value(body.clone()).map_err(|_| {
            problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Request body must be { components: [{ name, title, kind, description }] }.",
            )
        })?;
    if payload.components.len() > MAX_ANNOUNCE_ITEMS {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Too many announced components.",
        ));
    }
    let mut clean = Vec::with_capacity(payload.components.len());
    for (idx, item) in payload.components.into_iter().enumerate() {
        let name = item.name.trim().to_owned();
        let title = item.title.trim().to_owned();
        let kind = item.kind.trim().to_owned();
        let description = item.description.trim().to_owned();
        if !valid_non_empty_param(&name, 200)
            || !valid_non_empty_param(&title, 200)
            || !valid_non_empty_param(&kind, 100)
            || !valid_non_empty_param(&description, 4000)
        {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                &format!(
                    "Component at index {idx} needs a name, a title, a kind and a description."
                ),
            ));
        }
        if name.starts_with('@') {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                &format!(
                    "Component at index {idx} has a name that starts with @, which a component's name can't."
                ),
            ));
        }
        clean.push(CleanComponentInput {
            name,
            title,
            kind,
            description,
        });
    }
    Ok(clean)
}

fn build_component_json(
    c: &rusqlite::Connection,
    org: &str,
    row: &(
        String,
        String,
        String,
        bool,
        Option<i64>,
        Option<String>,
        String,
        String,
        i64,
    ),
    admin: bool,
) -> Result<Value, StorageError> {
    let (
        name,
        title,
        kind,
        published,
        published_at,
        description,
        draft_desc,
        updated_by,
        updated_at,
    ) = row;
    let published_at_iso = format_iso_utc(c, *published_at)?;
    let updated_at_iso = format_iso_utc(c, Some(*updated_at))?
        .ok_or(StorageError::InvalidDatabase("missing timestamp"))?;

    if !admin {
        return Ok(json!({
            "name": name,
            "title": title,
            "kind": kind,
            "published": published,
            "publishedAt": published_at_iso,
            "description": description,
            "source": Value::Null,
            "draft": Value::Null,
            "hasUnpublishedChanges": Value::Null,
            "withheldFrom": Value::Null,
            "functions": Value::Null,
            "updatedBy": Value::Null,
            "updatedAt": updated_at_iso,
        }));
    }

    let mut stmt = c.prepare(
        "SELECT bot_id FROM port_bot_components WHERE organization_id=?1 AND component_name=?2 AND withheld=1 ORDER BY bot_id",
    )?;
    let withheld_from = stmt
        .query_map(params![org, name], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_unpublished = !*published || description.as_deref() != Some(draft_desc.as_str());

    Ok(json!({
        "name": name,
        "title": title,
        "kind": kind,
        "published": published,
        "publishedAt": published_at_iso,
        "description": description,
        "source": Value::Null,
        "draft": {
            "title": title,
            "description": draft_desc,
            "source": Value::Null,
        },
        "hasUnpublishedChanges": has_unpublished,
        "withheldFrom": withheld_from,
        "functions": [],
        "updatedBy": updated_by,
        "updatedAt": updated_at_iso,
    }))
}

async fn list_components(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let limit = match parse_limit(&q) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let kind = match q.get("kind") {
        None => None,
        Some(k) if valid_non_empty_param(k, 100) => Some(k.clone()),
        Some(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Invalid kind parameter.",
            )
        }
    };
    let scope_tag = format!(
        "components:{}:{}",
        actor.organization,
        kind.as_deref().unwrap_or("")
    );
    let offset = match decode_cursor(&q, &scope_tag) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let admin = is_admin(&actor);
    let org_id = actor.organization;
    let kind_filter = kind;

    match run_db(&s, move |c| {
        let mut stmt = c.prepare(
            "SELECT name, title, kind, published, published_at, description, draft_description, updated_by, updated_at
             FROM port_components
             WHERE organization_id = ?1
               AND (?2 IS NULL OR kind = ?2)
               AND (?3 = 1 OR published = 1)
             ORDER BY kind ASC, title ASC, name ASC
             LIMIT ?4 OFFSET ?5",
        )?;
        let rows = stmt
            .query_map(
                params![
                    org_id,
                    kind_filter,
                    if admin { 1i64 } else { 0i64 },
                    (limit + 1) as i64,
                    offset as i64
                ],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, bool>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, i64>(8)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let has_more = rows.len() > limit;
        let mut items = Vec::with_capacity(rows.len().min(limit));
        for row in rows.into_iter().take(limit) {
            items.push(build_component_json(c, &org_id, &row, admin)?);
        }
        let next_cursor = if has_more {
            Some(encode_cursor(offset + limit, &scope_tag))
        } else {
            None
        };
        Ok(json!({
            "components": items,
            "nextCursor": next_cursor
        }))
    })
    .await
    {
        Ok(val) => respond_json(StatusCode::OK, val),
        Err(e) => e,
    }
}

async fn announce_components(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = match idempotency_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let items = match validate_announcement(&body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let fp = fingerprint("POST", "/components/announce", Some(&body));

    let res = run_db(&s, move |c| {
        let now = epoch()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((status, saved_body)) =
            replay_idempotency(&tx, &actor.organization, &actor.id, &key, &fp, now)?
        {
            return Ok((status, saved_body));
        }

        let mut added = Vec::new();
        let mut seen = HashSet::new();
        for item in items {
            if !seen.insert(item.name.clone()) {
                continue;
            }
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM port_components WHERE organization_id=?1 AND name=?2)",
                params![actor.organization, item.name],
                |r| r.get(0),
            )?;
            if !exists {
                tx.execute(
                    "INSERT INTO port_components(organization_id, name, title, kind, published, published_at, description, draft_description, updated_by, updated_at)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?6, 'the build', ?5)",
                    params![
                        actor.organization,
                        item.name,
                        item.title,
                        item.kind,
                        now,
                        item.description
                    ],
                )?;
                added.push(item.name);
            }
        }

        let response_body = json!({ "added": added }).to_string();
        store_idempotency(
            &tx,
            &actor.organization,
            &actor.id,
            &key,
            &fp,
            now,
            200,
            &response_body,
        )?;
        tx.commit()?;
        Ok((200, response_body))
    })
    .await;

    match res {
        Ok((409, _)) => problem(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_KEY_CONFLICT",
            "That Idempotency-Key was used for a different request.",
        ),
        Ok((status, body_str)) => respond_raw(
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            body_str,
        ),
        Err(e) => e,
    }
}

async fn get_component(
    State(s): State<AuthState>,
    Path((org, component_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !valid_non_empty_param(&component_id, 200) {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid component id.",
        );
    }
    let admin = is_admin(&actor);
    let org_id = actor.organization;

    match run_db(&s, move |c| {
        let row = c
            .query_row(
                "SELECT name, title, kind, published, published_at, description, draft_description, updated_by, updated_at
                 FROM port_components
                 WHERE organization_id=?1 AND name=?2 AND (?3 = 1 OR published = 1)",
                params![org_id, component_id, if admin { 1i64 } else { 0i64 }],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, bool>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()?;
        match row {
            Some(r) => Ok(Some(build_component_json(c, &org_id, &r, admin)?)),
            None => Ok(None),
        }
    })
    .await
    {
        Ok(Some(v)) => respond_json(StatusCode::OK, v),
        Ok(None) => problem(
            StatusCode::NOT_FOUND,
            "COMPONENT_NOT_FOUND",
            "Component not found.",
        ),
        Err(e) => e,
    }
}

async fn delete_component(
    State(s): State<AuthState>,
    Path((org, component_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = match idempotency_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    if !valid_non_empty_param(&component_id, 200) {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid component id.",
        );
    }
    if !is_admin(&actor) {
        return problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Only an admin can delete a component.",
        );
    }
    let fp = fingerprint("DELETE", &format!("/components/{component_id}"), None);

    let res = run_db(&s, move |c| {
        let now = epoch()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((status, saved_body)) =
            replay_idempotency(&tx, &actor.organization, &actor.id, &key, &fp, now)?
        {
            return Ok((status, saved_body));
        }

        let kind: Option<String> = tx
            .query_row(
                "SELECT kind FROM port_components WHERE organization_id=?1 AND name=?2",
                params![actor.organization, component_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(kind) = kind else {
            return Ok((404, String::new()));
        };
        if kind != "playground" {
            return Ok((409, String::from("BUILT_IN")));
        }

        tx.execute(
            "DELETE FROM port_components WHERE organization_id=?1 AND name=?2",
            params![actor.organization, component_id],
        )?;
        store_idempotency(&tx, &actor.organization, &actor.id, &key, &fp, now, 204, "")?;
        tx.commit()?;
        Ok((204, String::new()))
    })
    .await;

    match res {
        Ok((404, _)) => problem(
            StatusCode::NOT_FOUND,
            "COMPONENT_NOT_FOUND",
            "Component not found.",
        ),
        Ok((409, tag)) if tag == "BUILT_IN" => problem(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Built-in components cannot be deleted; unpublish instead.",
        ),
        Ok((409, _)) => problem(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_KEY_CONFLICT",
            "That Idempotency-Key was used for a different request.",
        ),
        Ok((status, body)) => respond_raw(
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            body,
        ),
        Err(e) => e,
    }
}

async fn list_bot_components(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let limit = match parse_limit(&q) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let scope_tag = format!("bot_components:{}:{}", actor.organization, bot_id);
    let offset = match decode_cursor(&q, &scope_tag) {
        Ok(o) => o,
        Err(e) => return e,
    };

    match run_db(&s, move |c| {
        let owns_bot: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3)",
            params![bot_id, actor.organization, actor.id],
            |r| r.get(0),
        )?;
        if !owns_bot {
            return Ok(None);
        }

        let mut stmt = c.prepare(
            "SELECT c.name, COALESCE(c.description, c.draft_description)
             FROM port_components c
             WHERE c.organization_id = ?1
               AND c.published = 1
               AND NOT EXISTS (
                 SELECT 1 FROM port_bot_components bc
                 WHERE bc.organization_id = c.organization_id
                   AND bc.bot_id = ?2
                   AND bc.component_name = c.name
                   AND bc.withheld = 1
               )
             ORDER BY c.name ASC
             LIMIT ?3 OFFSET ?4",
        )?;
        let rows = stmt
            .query_map(
                params![actor.organization, bot_id, (limit + 1) as i64, offset as i64],
                |r| {
                    Ok(json!({
                        "name": r.get::<_, String>(0)?,
                        "description": r.get::<_, String>(1)?,
                    }))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let has_more = rows.len() > limit;
        let items: Vec<Value> = rows.into_iter().take(limit).collect();
        let next_cursor = if has_more {
            Some(encode_cursor(offset + limit, &scope_tag))
        } else {
            None
        };
        Ok(Some(json!({
            "components": items,
            "nextCursor": next_cursor
        })))
    })
    .await
    {
        Ok(Some(v)) => respond_json(StatusCode::OK, v),
        Ok(None) => problem(StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found."),
        Err(e) => e,
    }
}

async fn allow_bot_component(
    State(s): State<AuthState>,
    Path((org, bot_id, component_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    mutate_bot_component(s, org, bot_id, component_id, h, false).await
}

async fn withhold_bot_component(
    State(s): State<AuthState>,
    Path((org, bot_id, component_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    mutate_bot_component(s, org, bot_id, component_id, h, true).await
}

async fn mutate_bot_component(
    s: AuthState,
    org: String,
    bot_id: String,
    component_id: String,
    h: HeaderMap,
    withhold: bool,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = match idempotency_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    if !valid_non_empty_param(&bot_id, 200) || !valid_non_empty_param(&component_id, 200) {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid bot or component id.",
        );
    }
    let method = if withhold { "DELETE" } else { "PUT" };
    let fp = fingerprint(
        method,
        &format!("/bots/{bot_id}/components/{component_id}"),
        None,
    );

    let res = run_db(&s, move |c| {
        let now = epoch()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((status, saved_body)) =
            replay_idempotency(&tx, &actor.organization, &actor.id, &key, &fp, now)?
        {
            return Ok((status, saved_body));
        }

        let owns_bot: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3)",
            params![bot_id, actor.organization, actor.id],
            |r| r.get(0),
        )?;
        if !owns_bot {
            return Ok((404, String::from("BOT")));
        }

        let comp_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM port_components WHERE organization_id=?1 AND name=?2)",
            params![actor.organization, component_id],
            |r| r.get(0),
        )?;
        if !comp_exists {
            return Ok((404, String::from("COMPONENT")));
        }

        if withhold {
            tx.execute(
                "INSERT INTO port_bot_components(organization_id, bot_id, component_name, withheld, withheld_at)
                 VALUES (?1, ?2, ?3, 1, ?4)
                 ON CONFLICT(organization_id, bot_id, component_name)
                 DO UPDATE SET withheld=1, withheld_at=CASE WHEN port_bot_components.withheld=1 THEN port_bot_components.withheld_at ELSE excluded.withheld_at END",
                params![actor.organization, bot_id, component_id, now],
            )?;
        } else {
            tx.execute(
                "DELETE FROM port_bot_components WHERE organization_id=?1 AND bot_id=?2 AND component_name=?3",
                params![actor.organization, bot_id, component_id],
            )?;
        }

        store_idempotency(
            &tx,
            &actor.organization,
            &actor.id,
            &key,
            &fp,
            now,
            204,
            "",
        )?;
        tx.commit()?;
        Ok((204, String::new()))
    })
    .await;

    match res {
        Ok((404, kind)) if kind == "BOT" => {
            problem(StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")
        }
        Ok((404, _)) => problem(
            StatusCode::NOT_FOUND,
            "COMPONENT_NOT_FOUND",
            "Component not found.",
        ),
        Ok((409, _)) => problem(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_KEY_CONFLICT",
            "That Idempotency-Key was used for a different request.",
        ),
        Ok((status, body)) => respond_raw(
            StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            body,
        ),
        Err(e) => e,
    }
}

// -----------------------------------------------------------------------------
// 3. GET /api/v2/organizations/{organization}/people/{person}/bot-attention
// -----------------------------------------------------------------------------

/// Queries pending approval count and newest waiting conversationId from `port_approvals`
/// when that table exists (migration 0011+), returning `(0, None)` safely before it exists.
fn safe_pending_approvals(
    c: &rusqlite::Connection,
    org_id: &str,
    owner_id: &str,
    bot_id: &str,
) -> (i64, Option<String>) {
    let table_exists = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='port_approvals')",
            [],
            |r| r.get::<_, bool>(0),
        )
        .unwrap_or(false);
    if !table_exists {
        return (0, None);
    }

    let Ok(mut info_stmt) = c.prepare("PRAGMA table_info(port_approvals)") else {
        return (0, None);
    };
    let cols: HashSet<String> = match info_stmt.query_map([], |r| r.get::<_, String>(1)) {
        Ok(rows) => rows.filter_map(Result::ok).collect(),
        Err(_) => return (0, None),
    };
    if !cols.contains("bot_id") || !cols.contains("status") {
        return (0, None);
    }

    let mut clauses = vec![
        "bot_id = ?1".to_owned(),
        "status IN ('pending', 'waiting')".to_owned(),
    ];
    let mut bind_values: Vec<String> = vec![bot_id.to_owned()];

    if cols.contains("organization_id") {
        bind_values.push(org_id.to_owned());
        clauses.push(format!("organization_id = ?{}", bind_values.len()));
    }
    if cols.contains("owner_id") {
        bind_values.push(owner_id.to_owned());
        clauses.push(format!("owner_id = ?{}", bind_values.len()));
    } else if cols.contains("person_id") {
        bind_values.push(owner_id.to_owned());
        clauses.push(format!("person_id = ?{}", bind_values.len()));
    } else if cols.contains("user_id") {
        bind_values.push(owner_id.to_owned());
        clauses.push(format!("user_id = ?{}", bind_values.len()));
    }

    let where_sql = clauses.join(" AND ");
    let conv_expr = if cols.contains("conversation_id") {
        "MAX(conversation_id)"
    } else {
        "NULL"
    };
    let sql =
        format!("SELECT COALESCE(COUNT(*), 0), {conv_expr} FROM port_approvals WHERE {where_sql}");

    let params_refs: Vec<&dyn rusqlite::ToSql> = bind_values
        .iter()
        .map(|s| s as &dyn rusqlite::ToSql)
        .collect();
    c.query_row(&sql, params_refs.as_slice(), |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
    })
    .unwrap_or((0, None))
}

async fn bot_attention(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let limit = match parse_limit(&q) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let scope_tag = format!("bot_attention:{}:{}", actor.organization, actor.id);
    let offset = match decode_cursor(&q, &scope_tag) {
        Ok(o) => o,
        Err(e) => return e,
    };

    match run_db(&s, move |c| {
        let mut stmt = c.prepare(
            "SELECT id, name
             FROM port_bots
             WHERE organization_id = ?1 AND owner_id = ?2
             ORDER BY name ASC, id ASC
             LIMIT ?3 OFFSET ?4",
        )?;
        let bots = stmt
            .query_map(
                params![
                    actor.organization,
                    actor.id,
                    (limit + 1) as i64,
                    offset as i64
                ],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let has_more = bots.len() > limit;
        let mut attention = Vec::with_capacity(bots.len().min(limit));

        for (bot_id, name) in bots.into_iter().take(limit) {
            let unread: i64 = c.query_row(
                "SELECT COALESCE(COUNT(*), 0)
                 FROM port_conversation_messages m
                 JOIN port_conversations c ON c.id = m.conversation_id
                 WHERE c.organization_id = ?1
                   AND c.owner_id = ?2
                   AND c.deleted = 0
                   AND m.role = 'bot'
                   AND m.bot_id = ?3
                   AND m.created_at > COALESCE(c.last_read_at, 0)",
                params![actor.organization, actor.id, bot_id],
                |r| r.get(0),
            )?;

            let (_running_runs, failed_runs): (i64, i64) = c.query_row(
                "SELECT
                   COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0)
                 FROM port_runs
                 WHERE bot_id = ?1 AND owner_id = ?2",
                params![bot_id, actor.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;

            let (approvals, approval_conv) =
                safe_pending_approvals(c, &actor.organization, &actor.id, &bot_id);

            let waiting_in = match approval_conv {
                Some(conv_id) => Some(conv_id),
                None => c
                    .query_row(
                        "SELECT c.id
                         FROM port_conversation_messages m
                         JOIN port_conversations c ON c.id = m.conversation_id
                         WHERE c.organization_id = ?1
                           AND c.owner_id = ?2
                           AND c.deleted = 0
                           AND m.bot_id = ?3
                           AND m.status = 'waiting'
                         ORDER BY m.created_at DESC, m.id DESC
                         LIMIT 1",
                        params![actor.organization, actor.id, bot_id],
                        |r| r.get(0),
                    )
                    .optional()?,
            };

            attention.push(json!({
                "botId": bot_id,
                "name": name,
                "questions": 0,
                "approvals": approvals,
                "handoffs": 0,
                "unread": unread,
                "paused": false,
                "notify": "all",
                "items": 0,
                "tasks": {
                    "needsInput": approvals,
                    "ready": 0,
                    "failed": failed_runs,
                },
                "waitingIn": waiting_in,
            }));
        }

        let next_cursor = if has_more {
            Some(encode_cursor(offset + limit, &scope_tag))
        } else {
            None
        };
        Ok(json!({
            "attention": attention,
            "lastPingId": Value::Null,
            "nextCursor": next_cursor,
        }))
    })
    .await
    {
        Ok(val) => respond_json(StatusCode::OK, val),
        Err(e) => e,
    }
}

// -----------------------------------------------------------------------------
// 4. Browser endpoints
// -----------------------------------------------------------------------------

async fn person_browser(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    vc: Option<axum::Extension<crate::virtual_computer::VirtualComputerState>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("person_browser:{}:{}", actor.organization, actor.id);
    let stored = run_db(&s, move |c| crate::compat_extra::load_kv(c, &key))
        .await
        .ok()
        .flatten();
    if let Some(val) = stored {
        return respond_json(
            StatusCode::OK,
            crate::compat_extra::person_browser_api_json_with_vc(
                Some(&val),
                &actor.id,
                vc.as_ref().map(|e| &e.0),
            ),
        );
    }
    respond_json(
        StatusCode::OK,
        json!({
            "open": false,
            "tabs": [],
            "available": true,
            "computerId": "ps5-virtual",
            "window": "screen",
            "shows": "screen",
            "narration": "own",
            "note": "In-process PS5 interactive web proxy & virtual browser"
        }),
    )
}

async fn bot_browser(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    match run_db(&s, move |c| {
        Ok(c.query_row(
            "SELECT EXISTS(SELECT 1 FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3)",
            params![bot_id, actor.organization, actor.id],
            |r| r.get::<_, bool>(0),
        )?)
    })
    .await
    {
        Ok(true) => respond_json(
            StatusCode::OK,
            json!({
                "open": false,
                "tabs": [],
                "mine": false,
                "recordingIsMine": false,
                "recordRefused": "Browser recording is unavailable without a remote Chromium bridge on PS5."
            }),
        ),
        Ok(false) => problem(StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found."),
        Err(e) => e,
    }
}

// -----------------------------------------------------------------------------
// 5. Invitations endpoints
// -----------------------------------------------------------------------------

async fn list_my_invitations(
    State(s): State<AuthState>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize_any_org(&s, &h).await {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "invitations": [],
            "nextCursor": Value::Null
        }),
    )
}

async fn list_org_invitations(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Only an admin can list organization invitations.",
        );
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "invitations": [],
            "nextCursor": Value::Null
        }),
    )
}

// -----------------------------------------------------------------------------
// 6. Read-only honest list & setup routes
// -----------------------------------------------------------------------------

async fn get_app_setup(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "directoryAvailable": false,
            "directoryProvider": Value::Null,
            "redirectUri": Value::Null,
            "authorizesPerAction": false,
            "botsMayCallBack": false
        }),
    )
}

async fn list_skills(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let org_id = actor.organization;
    let Ok(skills) = run_db(&s, move |c| crate::compat_extra::read_skills_for_org(c, &org_id)).await else {
        return internal();
    };
    respond_json(
        StatusCode::OK,
        json!({
            "skills": skills,
            "nextCursor": Value::Null
        }),
    )
}

async fn list_shared_use_requests(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Only an admin can list shared-use requests.",
        );
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "sharedUseRequests": [],
            "nextCursor": Value::Null
        }),
    )
}

async fn list_app_access_requests(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    if q.get("appId")
        .is_some_and(|id| !valid_non_empty_param(id, 200))
    {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid appId parameter.",
        );
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "appAccessRequests": [],
            "nextCursor": Value::Null
        }),
    )
}

async fn get_conversation_context(
    State(s): State<CompatContextState>,
    Path((org, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s.auth, &h, &org, false).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    if !valid_non_empty_param(&id, 200) {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid conversation ID.",
        );
    }

    let need_fallback = !s.context.has_conversation_state(&id);
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let conv_id = id.clone();

    let conv_check = run_db(&s.auth, move |c| {
        let bot_ids_raw: Option<String> = c
            .query_row(
                "SELECT bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",
                params![conv_id, org_id, owner_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(bot_ids_raw) = bot_ids_raw else {
            return Ok(None);
        };
        if !need_fallback {
            return Ok(Some(None));
        }

        let mut msgs: Vec<Value> = Vec::new();
        let bots: Vec<String> = serde_json::from_str(&bot_ids_raw).unwrap_or_default();
        if let Some(first_bot) = bots.first() {
            if let Some(sys) = c
                .query_row(
                    "SELECT role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                    params![first_bot, org_id, owner_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
            {
                if !sys.trim().is_empty() {
                    msgs.push(json!({"role": "system", "content": sys}));
                }
            }
        }
        let mut st = c.prepare(
            "SELECT role, text FROM port_conversation_messages WHERE conversation_id=?1 AND text!='' ORDER BY rowid DESC LIMIT 12",
        )?;
        let mut rows = st
            .query_map(params![conv_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.reverse();
        for (role, text) in rows {
            let api_role = if role == "person" { "user" } else { "assistant" };
            msgs.push(json!({"role": api_role, "content": text}));
        }
        Ok(Some(Some(json!({"messages": msgs}))))
    })
    .await;

    let fallback_req = match conv_check {
        Ok(Some(req_opt)) => req_opt,
        Ok(None) => {
            return problem(
                StatusCode::NOT_FOUND,
                "CONVERSATION_NOT_FOUND",
                "Conversation not found.",
            )
        }
        Err(e) => return e,
    };

    let snapshot = s
        .context
        .get_conversation_snapshot(&id, fallback_req.as_ref())
        .await;
    respond_json(
        StatusCode::OK,
        serde_json::to_value(snapshot).unwrap_or_else(|_| json!({})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    fn fixture() -> (Router, Arc<Storage>, std::path::PathBuf) {
        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).unwrap();
        let path =
            std::env::temp_dir().join(format!("openbot-compat-{:x}.db", u64::from_le_bytes(rand)));
        let db = Arc::new(Storage::open(&path).unwrap());
        db.try_with_connection(|c| {
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='port_components')",
                [],
                |r| r.get(0),
            )?;
            if !exists {
                c.execute_batch(migration_sql())?;
            }
            Ok(())
        })
        .unwrap();
        let state = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let app = crate::local_auth::router(state.clone())
            .merge(crate::bots::router(state.clone()))
            .merge(crate::mcp_client::router(state.clone()))
            .merge(router(state));
        (app, db, path)
    }

    async fn setup_owner(app: &Router) -> String {
        let setup = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/port/auth/setup")
                    .header("host", "example.test")
                    .header("origin", "http://example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"a long secure password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);
        setup.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    async fn read_json(res: Response) -> Value {
        let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn req(method: &str, uri: &str, cookie: &str, key: &str, body: &str) -> Request<Body> {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "example.test")
            .header("origin", "http://example.test");
        if !cookie.is_empty() {
            b = b.header("cookie", cookie);
        }
        if !key.is_empty() {
            b = b.header("idempotency-key", key);
        }
        if !body.is_empty() {
            b = b.header("content-type", "application/json");
        }
        b.body(Body::from(body.to_owned())).unwrap()
    }

    #[tokio::test]
    async fn components_lifecycle_auth_pagination_and_bot_holds() {
        let (app, db, path) = fixture();
        let unauth = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/components",
                "",
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let cookie = setup_owner(&app).await;

        // Create a bot owned by owner.
        let bot_res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/bots",
                &cookie,
                "bot-1",
                r#"{"name":"Alpha","title":"Helper","roleDescription":"Helps out","visibility":"private"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(bot_res.status(), StatusCode::CREATED);
        let bot_id = read_json(bot_res).await["bot"]["id"]
            .as_str()
            .unwrap()
            .to_owned();

        // Missing Idempotency-Key fails 400.
        let no_key = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/components/announce",
                &cookie,
                "",
                r#"{"components":[]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(no_key.status(), StatusCode::BAD_REQUEST);

        // Wrong origin fails 403.
        let bad_origin = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/organizations/default/components/announce")
                    .header("origin", "http://evil.test")
                    .header("cookie", &cookie)
                    .header("idempotency-key", "k1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"components":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

        // Name starting with @ is rejected 400.
        let bad_name = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/components/announce",
                &cookie,
                "ann-bad",
                r#"{"components":[{"name":"@bad","title":"Bad","kind":"card","description":"Nope"}]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(bad_name.status(), StatusCode::BAD_REQUEST);

        // Announce two components.
        let payload = r#"{"components":[{"name":"showBarChart","title":"Bar chart","kind":"chart","description":"Compare values."},{"name":"showActivityReport","title":"Activity report","kind":"card","description":"Show activity."}]}"#;
        let ann = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/components/announce",
                &cookie,
                "ann-1",
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(ann.status(), StatusCode::OK);
        assert_eq!(ann.headers()[header::CACHE_CONTROL], "private, no-store");
        let ann_json = read_json(ann).await;
        assert_eq!(
            ann_json,
            json!({ "added": ["showBarChart", "showActivityReport"] })
        );

        // Idempotent replay returns identical body; conflict returns 409.
        let replay = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/components/announce",
                &cookie,
                "ann-1",
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(read_json(replay).await, ann_json);

        let conflict = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/components/announce",
                &cookie,
                "ann-1",
                r#"{"components":[]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        // Re-announce with a new key adds nothing.
        let ann2 = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/components/announce",
                &cookie,
                "ann-2",
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(ann2.status(), StatusCode::OK);
        assert_eq!(read_json(ann2).await, json!({ "added": [] }));

        // Pagination limit=1 + cursor + kind filter.
        let page1 = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/components?limit=1",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(page1.status(), StatusCode::OK);
        let p1_json = read_json(page1).await;
        assert_eq!(p1_json["components"].as_array().unwrap().len(), 1);
        assert_eq!(p1_json["components"][0]["name"], "showActivityReport");
        let cursor = p1_json["nextCursor"].as_str().unwrap().to_owned();

        let page2 = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/components?limit=1&cursor={cursor}"),
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(page2.status(), StatusCode::OK);
        let p2_json = read_json(page2).await;
        assert_eq!(p2_json["components"][0]["name"], "showBarChart");
        assert!(p2_json["nextCursor"].is_null());

        let chart_only = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/components?kind=chart",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(chart_only.status(), StatusCode::OK);
        assert_eq!(
            read_json(chart_only).await["components"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        // Built-in component cannot be deleted -> 409.
        let del_builtin = app
            .clone()
            .oneshot(req(
                "DELETE",
                "/api/v2/organizations/default/components/showBarChart",
                &cookie,
                "del-builtin",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(del_builtin.status(), StatusCode::CONFLICT);

        // Playground component can be deleted -> 204.
        let ann_pg = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/components/announce",
                &cookie,
                "ann-pg",
                r#"{"components":[{"name":"custom_weather","title":"Weather","kind":"playground","description":"Show weather"}]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(ann_pg.status(), StatusCode::OK);
        let del_pg = app
            .clone()
            .oneshot(req(
                "DELETE",
                "/api/v2/organizations/default/components/custom_weather",
                &cookie,
                "del-pg",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(del_pg.status(), StatusCode::NO_CONTENT);

        // Bot components: initially both published components are available.
        let bot_comps = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/bots/{bot_id}/components"),
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(bot_comps.status(), StatusCode::OK);
        assert_eq!(
            read_json(bot_comps).await["components"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        // Withhold showBarChart from bot -> 204.
        let withhold = app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v2/organizations/default/bots/{bot_id}/components/showBarChart"),
                &cookie,
                "wh-1",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(withhold.status(), StatusCode::NO_CONTENT);

        let bot_comps_after = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/bots/{bot_id}/components"),
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        let bc_json = read_json(bot_comps_after).await;
        assert_eq!(bc_json["components"].as_array().unwrap().len(), 1);
        assert_eq!(bc_json["components"][0]["name"], "showActivityReport");

        // Admin GET component reflects withheldFrom.
        let single = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/components/showBarChart",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(single.status(), StatusCode::OK);
        assert_eq!(read_json(single).await["withheldFrom"], json!([bot_id]));

        // Allow showBarChart again -> 204.
        let allow = app
            .clone()
            .oneshot(req(
                "PUT",
                &format!("/api/v2/organizations/default/bots/{bot_id}/components/showBarChart"),
                &cookie,
                "allow-1",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(allow.status(), StatusCode::NO_CONTENT);

        let bot_comps_restored = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/bots/{bot_id}/components"),
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(
            read_json(bot_comps_restored).await["components"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        // Non-owner bot check -> 404.
        db.try_with_connection(|c| {
            c.execute("INSERT INTO auth_users(id,email,display_name,password_hash) VALUES ('other-user','other@example.test','Other','unused')", [])?;
            c.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES ('other-bot','default','other-user','Foreign','','Secret',0)", [])?;
            Ok(())
        }).unwrap();
        let foreign_put = app
            .clone()
            .oneshot(req(
                "PUT",
                "/api/v2/organizations/default/bots/other-bot/components/showBarChart",
                &cookie,
                "foreign-put",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(foreign_put.status(), StatusCode::NOT_FOUND);

        drop(app);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn attention_browser_invitations_and_readonly_compat_routes() {
        let (app, db, path) = fixture();
        let cookie = setup_owner(&app).await;

        let bot_res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/bots",
                &cookie,
                "bot-att",
                r#"{"name":"Ops Bot","title":"","roleDescription":"Ops","visibility":"private"}"#,
            ))
            .await
            .unwrap();
        let bot_id = read_json(bot_res).await["bot"]["id"]
            .as_str()
            .unwrap()
            .to_owned();

        // Bot attention works without port_approvals table.
        let att = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/people/me/bot-attention",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(att.status(), StatusCode::OK);
        let att_json = read_json(att).await;
        assert_eq!(att_json["attention"].as_array().unwrap().len(), 1);
        assert_eq!(att_json["attention"][0]["botId"], bot_id);
        assert_eq!(att_json["attention"][0]["approvals"], 0);
        assert!(att_json["lastPingId"].is_null());
        assert!(att_json["nextCursor"].is_null());

        // Bot attention works when port_approvals exists (simulating migration 0011).
        db.try_with_connection(|c| {
            let owner_id: String = c.query_row("SELECT id FROM auth_users LIMIT 1", [], |r| r.get(0))?;
            let bot_json = serde_json::to_string(&vec![bot_id.as_str()]).unwrap();
            c.execute(
                "INSERT INTO port_conversations(id, organization_id, owner_id, thread_id, bot_ids_json, name, created_at) VALUES ('conv_99', 'default', ?1, 'thread_99', ?2, 'Conv 99', 1)",
                params![owner_id, bot_json],
            )?;
            c.execute(
                "INSERT INTO port_approvals(id, organization_id, actor_id, bot_id, conversation_id, run_id, tool_call_id, tool_ref, effect, scope, thread_id, args_json, action_digest, status, created_at, expires_at)
                 VALUES ('app_1', 'default', ?1, ?2, 'conv_99', 'run_1', 'call_1', 'computer_read_file', 'read', '*', 'thread_99', '{}', X'0000000000000000000000000000000000000000000000000000000000000000', 'pending', 1, 9999999999)",
                params![owner_id, bot_id],
            )
            .map(|_| ())
            .map_err(Into::into)
        })
        .unwrap();

        let att_after = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/people/me/bot-attention",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(att_after.status(), StatusCode::OK);
        let att_after_json = read_json(att_after).await;
        assert_eq!(att_after_json["attention"][0]["approvals"], 1);
        assert_eq!(att_after_json["attention"][0]["tasks"]["needsInput"], 1);
        assert_eq!(att_after_json["attention"][0]["waitingIn"], "conv_99");

        // Other person's attention is forbidden.
        let other_att = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/people/someone-else/bot-attention",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(other_att.status(), StatusCode::FORBIDDEN);

        // Person browser lifecycle: closed initially, then open -> navigate -> tabs -> recording -> clear.
        let pb = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/people/me/browser",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(pb.status(), StatusCode::OK);
        let pb_json = read_json(pb).await;
        assert_eq!(pb_json["open"], false);
        assert_eq!(pb_json["available"], true);
        assert_eq!(pb_json["computerId"], "ps5-virtual");

        let pb_open = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/people/me/browser/open",
                &cookie,
                "k-open-1",
                "{}",
            ))
            .await
            .unwrap();
        assert_eq!(pb_open.status(), StatusCode::OK);
        let pb_open_json = read_json(pb_open).await;
        assert_eq!(pb_open_json["computerId"], "ps5-virtual");
        assert_eq!(pb_open_json["window"], "screen");

        let pb_opened_state = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/people/me/browser",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(pb_opened_state.status(), StatusCode::OK);
        let pb_state_json = read_json(pb_opened_state).await;
        assert_eq!(pb_state_json["open"], true);
        assert_eq!(pb_state_json["tabs"].as_array().unwrap().len(), 1);
        assert_eq!(pb_state_json["recorder"]["phase"], "idle");

        let pb_nav = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/people/me/browser/navigate",
                &cookie,
                "k-nav-1",
                r#"{"url":"https://www.google.com/"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(pb_nav.status(), StatusCode::OK);
        let pb_nav_json = read_json(pb_nav).await;
        assert_eq!(pb_nav_json["tabs"][0]["url"], "https://www.google.com/");

        let pb_rec_start = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/people/me/browser/recording",
                &cookie,
                "k-rec-start",
                r#"{"action":"start","title":"Search task"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(pb_rec_start.status(), StatusCode::OK);
        assert_eq!(read_json(pb_rec_start).await["recorder"]["phase"], "recording");

        let pb_rec_stop = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/people/me/browser/recording",
                &cookie,
                "k-rec-stop",
                r#"{"action":"stop"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(pb_rec_stop.status(), StatusCode::OK);
        let pb_rec_stop_json = read_json(pb_rec_stop).await;
        assert_eq!(pb_rec_stop_json["recorder"]["phase"], "idle");
        assert_eq!(pb_rec_stop_json["recorder"]["lastStopped"]["title"], "Search task");

        let pb_clear = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/people/me/browser/clear",
                &cookie,
                "k-clear",
                "{}",
            ))
            .await
            .unwrap();
        assert_eq!(pb_clear.status(), StatusCode::OK);
        assert_eq!(read_json(pb_clear).await["tabs"][0]["url"], "about:blank");

        let bb = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/computers/{bot_id}/browser"),
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(bb.status(), StatusCode::OK);
        assert_eq!(read_json(bb).await["open"], false);

        let bb_missing = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/computers/missing-bot/browser",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(bb_missing.status(), StatusCode::NOT_FOUND);

        // Remaining read-only compatibility routes.
        for (uri, key, expected) in [
            (
                "/api/v2/organizations/default/shortened-tool-names",
                "names",
                json!({}),
            ),
            ("/api/v2/people/me/invitations", "invitations", json!([])),
            (
                "/api/v2/organizations/default/invitations",
                "invitations",
                json!([]),
            ),
            ("/api/v2/organizations/default/apps", "apps", json!([])),
            (
                "/api/v2/organizations/default/app-setup",
                "directoryAvailable",
                json!(false),
            ),
            ("/api/v2/organizations/default/skills", "skills", json!([])),
            (
                "/api/v2/organizations/default/shared-use-requests",
                "sharedUseRequests",
                json!([]),
            ),
            (
                "/api/v2/organizations/default/app-access-requests",
                "appAccessRequests",
                json!([]),
            ),
        ] {
            let res = app
                .clone()
                .oneshot(req("GET", uri, &cookie, "", ""))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{uri}");
            assert_eq!(res.headers()[header::CACHE_CONTROL], "private, no-store");
            let j = read_json(res).await;
            assert_eq!(j[key], expected, "{uri}");
        }

        // Wrong org returns 404.
        let wrong_org = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/other/shortened-tool-names",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(wrong_org.status(), StatusCode::NOT_FOUND);

        drop(app);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn conversation_context_endpoint_enforces_auth_ownership_and_returns_snapshot() {
        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).unwrap();
        let path =
            std::env::temp_dir().join(format!("openbot-ctx-route-{:x}.db", u64::from_le_bytes(rand)));
        let db = Arc::new(Storage::open(&path).unwrap());
        db.try_with_connection(|c| {
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='port_components')",
                [],
                |r| r.get(0),
            )?;
            if !exists {
                c.execute_batch(migration_sql())?;
            }
            Ok(())
        })
        .unwrap();
        let state = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let ctx_mgr = crate::context_manager::ContextManager::offline(16384);
        let app = crate::local_auth::router(state.clone())
            .merge(crate::bots::router(state.clone()))
            .merge(crate::conversations::router(state.clone()))
            .merge(crate::mcp_client::router(state.clone()))
            .merge(router_with_context(state, ctx_mgr.clone()));

        let unauth = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/conversations/c1/context",
                "",
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let cookie = setup_owner(&app).await;
        let bot_res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/bots",
                &cookie,
                "ctx-bot-1",
                r#"{"name":"Helper","title":"Helper","roleDescription":"Be concise.","visibility":"private"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(bot_res.status(), StatusCode::CREATED);
        let bot_id = read_json(bot_res).await["bot"]["id"].as_str().unwrap().to_owned();

        let conv_res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/conversations",
                &cookie,
                "ctx-conv-1",
                &json!({"botIds": [bot_id]}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(conv_res.status(), StatusCode::CREATED);
        let conv_id = read_json(conv_res).await["conversation"]["id"]
            .as_str()
            .unwrap()
            .to_owned();

        let missing = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/conversations/does-not-exist/context",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let initial = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/conversations/{conv_id}/context"),
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(initial.status(), StatusCode::OK);
        let initial_json = read_json(initial).await;
        assert_eq!(initial_json["context_limit"], 16384);
        assert_eq!(initial_json["compacted"], false);
        assert!(initial_json["used_tokens"].as_u64().unwrap() > 0);

        ctx_mgr.record_conversation_state(
            &conv_id,
            crate::context_manager::TokenBreakdown {
                total_tokens: 4200,
                system_tokens: 600,
                history_tokens: 3000,
                tools_tokens: 600,
            },
            Some(&crate::context_manager::CompactionResult {
                compacted: true,
                before_tokens: 13000,
                after_tokens: 4200,
                threshold_tokens: 12288,
                context_limit: 16384,
                dropped_turns: 3,
                summarized_messages: 6,
            }),
        );

        let recorded = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/conversations/{conv_id}/context"),
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(recorded.status(), StatusCode::OK);
        let recorded_json = read_json(recorded).await;
        assert_eq!(recorded_json["used_tokens"], 4200);
        assert_eq!(recorded_json["context_limit"], 16384);
        assert_eq!(recorded_json["remaining_tokens"], 12184);
        assert_eq!(recorded_json["compacted"], true);
        assert_eq!(recorded_json["compacted_before_tokens"], 13000);
        assert_eq!(recorded_json["compacted_after_tokens"], 4200);
        assert_eq!(recorded_json["dropped_turns"], 3);

        drop(app);
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
