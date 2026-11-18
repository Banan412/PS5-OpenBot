//! Partial bot API: private owner-managed bots only. Runtime execution is not yet implemented.
use crate::local_auth::{identity, AuthState, Identity};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/bots",
            get(list).post(create),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}",
            get(read).patch(update).delete(remove),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/grants",
            get(grants),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/duplicate",
            axum::routing::post(duplicate),
        )
        .layer(DefaultBodyLimit::max(8192))
        .with_state(state)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct GrantQuery {
    kind: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

/// This port has no grant creation or built-in tool grants yet. All tools stay
/// disabled until the governance gateway and grant persistence are implemented.
async fn grants(
    State(s): State<AuthState>,
    Path((org, bot)): Path<(String, String)>,
    Query(q): Query<GrantQuery>,
    h: HeaderMap,
) -> Response {
    let actor = match authorized(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if q.limit.is_some_and(|n| n == 0 || n > 100)
        || q.cursor.is_some()
        || q.kind
            .as_deref()
            .is_some_and(|v| !matches!(v, "action" | "skill" | "bot"))
    {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid grant query.",
        );
    }
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return internal();
    };
    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let bot_c = bot.clone();
    let kind_filter = q.kind.clone();
    let found = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(|c| {
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3)",
                params![bot_c, org_c, actor.id],
                |r| r.get::<_, bool>(0),
            )?;
            if !exists {
                return Ok(None);
            }
            let mut grants = Vec::new();
            if kind_filter.as_deref().is_none_or(|k| k == "action") {
                grants.extend(crate::mcp_client::list_bot_action_grants(c, &org_c, &bot_c));
            }
            if kind_filter.as_deref().is_none_or(|k| k == "skill") {
                grants.extend(crate::mcp_client::list_bot_skill_grants(c, &org_c, &bot_c));
            }
            Ok(Some(grants))
        })
    })
    .await;
    match found {
        Ok(Ok(Some(grants))) => respond(
            StatusCode::OK,
            json!({"grants":grants,"nextCursor":null}).to_string(),
            None,
        ),
        Ok(Ok(None)) => problem(StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found."),
        _ => internal(),
    }
}
fn problem(status: StatusCode, code: &str, detail: &str) -> Response {
    let category = match status {
        StatusCode::UNAUTHORIZED => "unauthenticated",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        _ => "invalid_request",
    };
    let mut r = (status, Json(json!({"type":format!("https://open.bot/errors/{}",code.to_ascii_lowercase().replace('_',"-")),"title":detail,"status":status.as_u16(),"detail":detail,"code":code,"category":category,"retryable":false,"requestId":"unavailable","traceId":"unavailable"}))).into_response();
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
fn internal() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "SERVICE_UNAVAILABLE",
        "Service unavailable.",
    )
}
fn respond(status: StatusCode, body: String, location: Option<String>) -> Response {
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
    if let Some(loc) = location {
        if let Ok(v) = HeaderValue::from_str(&loc) {
            r.headers_mut().insert(header::LOCATION, v);
        }
    }
    r
}
async fn authorized(
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
fn bot(id: &str, name: &str, title: &str, role: &str) -> Value {
    json!({"id":id,"name":name,"title":title,"roleDescription":role,"avatarSeed":id,"visibility":"private","hidden":false,"pinned":false,"systemOwned":false,"packageBotId":null,"endpoint":null,"hasAuth":false,"hasCallbackToken":false,"isolated":false,"canManage":true,"mine":true,"assignedToMe":false,"builtIn":true,"runsOnOpenBotModel":true,"keyFromOpenBot":true,"isolationActive":false,"isolationOffReason":null})
}
fn row_bot(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(bot(
        &r.get::<_, String>(0)?,
        &r.get::<_, String>(1)?,
        &r.get::<_, String>(2)?,
        &r.get::<_, String>(3)?,
    ))
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    hidden: Option<bool>,
    scope: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}
async fn list(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<ListQuery>,
    h: HeaderMap,
) -> Response {
    let i = match authorized(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_scope = match q.scope.as_deref() {
        None | Some("caller") => false,
        Some("organization") => {
            if i.role != "owner" && i.role != "admin" {
                return problem(
                    StatusCode::FORBIDDEN,
                    "PERMISSION_DENIED",
                    "Only an admin can list all organization bots.",
                );
            }
            true
        }
        Some(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Invalid scope parameter.",
            );
        }
    };
    let limit = q.limit.unwrap_or(50);
    if limit == 0 || limit > 100 {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid limit.");
    }
    let cursor = match q.cursor {
        None => None,
        Some(c) => {
            let Some((a, b)) = c.split_once('_') else {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "INVALID_REQUEST",
                    "Invalid cursor.",
                );
            };
            let Ok(n) = i64::from_str_radix(a, 16) else {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "INVALID_REQUEST",
                    "Invalid cursor.",
                );
            };
            if b.len() != 32
                || !b
                    .bytes()
                    .all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase())
            {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "INVALID_REQUEST",
                    "Invalid cursor.",
                );
            }
            Some((n, format!("agent_{b}")))
        }
    };
    if q.hidden.unwrap_or(false) {
        return respond(
            StatusCode::OK,
            json!({"bots":[],"nextCursor":null}).to_string(),
            None,
        );
    }
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return internal();
    };
    let db = s.db.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(|c| {
            let (time, id) = cursor.unwrap_or((0, String::new()));
            let sql = if org_scope {
                "SELECT id,name,title,role_description,created_at FROM port_bots WHERE organization_id=?1 AND (created_at>?3 OR (created_at=?3 AND id>?4)) ORDER BY created_at,id LIMIT ?5"
            } else {
                "SELECT id,name,title,role_description,created_at FROM port_bots WHERE organization_id=?1 AND owner_id=?2 AND (created_at>?3 OR (created_at=?3 AND id>?4)) ORDER BY created_at,id LIMIT ?5"
            };
            let mut stmt = c.prepare(sql)?;
            let rows = stmt
                .query_map(
                    params![i.organization, i.id, time, id, (limit + 1) as i64],
                    |r| Ok((row_bot(r)?, r.get::<_, i64>(4)?, r.get::<_, String>(0)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    })
    .await;
    match result {
        Ok(Ok(mut rows)) => {
            let more = rows.len() > limit;
            if more {
                rows.pop();
            }
            let next = if more {
                rows.last()
                    .map(|(_, t, id)| format!("{:x}_{}", t, id.trim_start_matches("agent_")))
            } else {
                None
            };
            respond(
                StatusCode::OK,
                json!({"bots":rows.into_iter().map(|x|x.0).collect::<Vec<_>>(),"nextCursor":next})
                    .to_string(),
                None,
            )
        }
        _ => internal(),
    }
}
async fn read(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let i = match authorized(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return internal();
    };
    let db = s.db.clone();
    match tokio::task::spawn_blocking(move || {let _permit=permit;db.try_with_connection(|c|Ok(c.query_row("SELECT id,name,title,role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",params![id,i.organization,i.id],row_bot).optional()?))}).await {
      Ok(Ok(Some(v)))=>respond(StatusCode::OK,json!({"bot":v}).to_string(),None),Ok(Ok(None))=>problem(StatusCode::NOT_FOUND,"BOT_NOT_FOUND","Bot not found."),_=>internal()
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fields {
    name: String,
    title: String,
    role_description: String,
    visibility: String,
    endpoint: Option<String>,
    auth: Option<Value>,
    isolated: Option<bool>,
    #[allow(dead_code)]
    instructions: Option<String>,
    harness: Option<String>,
}
fn validate(v: &Fields) -> Result<(), Response> {
    if v.name.trim().is_empty()
        || v.name.trim().chars().count() > 80
        || v.title.chars().count() > 120
        || v.role_description.trim().is_empty()
        || v.role_description.trim().chars().count() > 1000
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "INVALID_BOT",
            "Invalid bot fields.",
        ));
    }
    if v.visibility != "private"
        || v.endpoint.as_deref().is_some_and(|x| !x.is_empty())
        || v.auth.is_some()
        || v.isolated == Some(true)
        || v.harness.as_deref().is_some_and(|x| !x.is_empty())
    {
        return Err(problem(
            StatusCode::NOT_IMPLEMENTED,
            "NOT_IMPLEMENTED",
            "Only private built-in bots are supported yet.",
        ));
    }
    Ok(())
}
async fn create(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(value): Json<Value>,
) -> Response {
    write(s, org, None, h, "POST", Some(value)).await
}
async fn update(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    h: HeaderMap,
    Json(value): Json<Value>,
) -> Response {
    write(s, org, Some(id), h, "PATCH", Some(value)).await
}
async fn remove(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    write(s, org, Some(id), h, "DELETE", None).await
}
async fn duplicate(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    write(s, org, Some(id), h, "DUPLICATE", None).await
}
async fn write(
    s: AuthState,
    org: String,
    id: Option<String>,
    h: HeaderMap,
    method: &'static str,
    value: Option<Value>,
) -> Response {
    let i = match authorized(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = match h.get("idempotency-key").and_then(|v| v.to_str().ok()) {
        Some(k) if !k.is_empty() && k.len() <= 128 => k.to_owned(),
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Idempotency-Key is required.",
            )
        }
    };
    let fields = match &value {
        Some(v) => {
            let f: Fields = match serde_json::from_value(v.clone()) {
                Ok(f) => f,
                Err(_) => {
                    return problem(
                        StatusCode::BAD_REQUEST,
                        "INVALID_BOT",
                        "Invalid bot fields.",
                    )
                }
            };
            if let Err(r) = validate(&f) {
                return r;
            }
            Some(f)
        }
        None => None,
    };
    if method == "PATCH" && value.as_ref().and_then(|v| v.get("harness")).is_some() {
        return problem(StatusCode::BAD_REQUEST, "INVALID_BOT", "Unknown bot field.");
    }
    let mut hash = Sha256::new();
    hash.update(method.as_bytes());
    hash.update([0]);
    hash.update(id.as_deref().unwrap_or("").as_bytes());
    hash.update([0]);
    if let Some(v) = value {
        hash.update(v.to_string().as_bytes())
    };
    let fingerprint = hash.finalize().to_vec();
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => t.as_secs() as i64,
        Err(_) => return internal(),
    };
    let mut random = [0u8; 16];
    if matches!(method, "POST" | "DUPLICATE") && getrandom::getrandom(&mut random).is_err() {
        return internal();
    }
    let new_id = format!(
        "agent_{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return internal();
    };
    let db = s.db.clone();
    let result=tokio::task::spawn_blocking(move ||{let _permit=permit;db.try_with_connection(|c|{
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM port_bot_idempotency WHERE created_at<?1",params![now-86400])?;
        let existing=tx.query_row("SELECT fingerprint,status,body,location FROM port_bot_idempotency WHERE organization_id=?1 AND actor_id=?2 AND idem_key=?3",params![i.organization,i.id,key],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,u16>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?))).optional()?;
        if let Some((old,status,body,loc))=existing {return if old==fingerprint {Ok((status,body,loc))}else{Ok((409,String::new(),None))};}
        let (status,body,loc)=match method {
            "POST"=>{let f=fields.unwrap();tx.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![new_id,i.organization,i.id,f.name.trim(),f.title,f.role_description.trim(),now])?; let b=bot(&new_id,f.name.trim(),&f.title,f.role_description.trim()); (201,json!({"bot":b}).to_string(),Some(format!("/api/v2/organizations/{}/bots/{}",i.organization,new_id)))},
            "DUPLICATE"=>{let source=id.unwrap();let original:Option<(String,String,String)>=tx.query_row("SELECT name,title,role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",params![source,i.organization,i.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;let Some((name,title,role))=original else{return Ok((404,String::new(),None))};tx.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![new_id,i.organization,i.id,name,title,role,now])?;(201,json!({"bot":bot(&new_id,&name,&title,&role)}).to_string(),Some(format!("/api/v2/organizations/{}/bots/{}",i.organization,new_id)))},
            "PATCH"=>{let f=fields.unwrap();let id=id.unwrap();let n=tx.execute("UPDATE port_bots SET name=?1,title=?2,role_description=?3 WHERE id=?4 AND organization_id=?5 AND owner_id=?6",params![f.name.trim(),f.title,f.role_description.trim(),id,i.organization,i.id])?;if n==0{return Ok((404,String::new(),None))} (200,json!({"bot":bot(&id,f.name.trim(),&f.title,f.role_description.trim())}).to_string(),None)},
            _=>{let n=tx.execute("DELETE FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",params![id.unwrap(),i.organization,i.id])?; if n==0{return Ok((404,String::new(),None))} (204,String::new(),None)}
        };
        tx.execute("INSERT INTO port_bot_idempotency(organization_id,actor_id,idem_key,fingerprint,created_at,status,body,location) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![i.organization,i.id,key,fingerprint,now,status,body,loc])?;tx.commit()?;Ok((status,body,loc))
    })}).await;
    match result {
        Ok(Ok((409, _, _))) => problem(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_KEY_CONFLICT",
            "Idempotency-Key was used for a different request.",
        ),
        Ok(Ok((404, _, _))) => problem(StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found."),
        Ok(Ok((code, body, loc))) => respond(
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            body,
            loc,
        ),
        _ => internal(),
    }
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
    #[tokio::test]
    async fn private_crud_auth_and_idempotency() {
        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).unwrap();
        let path =
            std::env::temp_dir().join(format!("openbot-bots-{:x}.db", u64::from_le_bytes(rand)));
        let db = Arc::new(Storage::open(&path).unwrap());
        let state = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let app = crate::local_auth::router(state.clone()).merge(router(state));
        let req = |method: &str, uri: &str, cookie: &str, key: &str, body: &str| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("idempotency-key", key)
                .body(Body::from(body.to_owned()))
                .unwrap()
        };
        let anon = app
            .clone()
            .oneshot(req("GET", "/api/v2/organizations/default/bots", "", "", ""))
            .await
            .unwrap();
        assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
        let setup=app.clone().oneshot(req("POST","/api/port/auth/setup","","",r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"a long secure password"}"#)).await.unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);
        let cookie = setup.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let path = "/api/v2/organizations/default/bots";
        let body = r#"{"name":"Helper","title":"","roleDescription":"Help the user","visibility":"private"}"#;
        let created = app
            .clone()
            .oneshot(req("POST", path, &cookie, "create-key", body))
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let location = created.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        let first = to_bytes(created.into_body(), 8192).await.unwrap();
        let grants = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("{location}/grants?limit=100"),
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(grants.status(), StatusCode::OK);
        let grants: Value =
            serde_json::from_slice(&to_bytes(grants.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(grants["grants"], json!([]));
        assert!(grants["nextCursor"].is_null());
        let no_session = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{location}/grants"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_session.status(), StatusCode::UNAUTHORIZED);
        let missing = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/bots/missing/grants",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let repeated = app
            .clone()
            .oneshot(req("POST", path, &cookie, "create-key", body))
            .await
            .unwrap();
        assert_eq!(repeated.status(), StatusCode::CREATED);
        assert_eq!(to_bytes(repeated.into_body(), 8192).await.unwrap(), first);
        let conflict = app
            .clone()
            .oneshot(req(
                "POST",
                path,
                &cookie,
                "create-key",
                r#"{"name":"Other","title":"","roleDescription":"Help","visibility":"private"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let wrong = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/elsewhere/bots",
                &cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::NOT_FOUND);
        let list = app
            .clone()
            .oneshot(req("GET", path, &cookie, "", ""))
            .await
            .unwrap();
        let json: Value =
            serde_json::from_slice(&to_bytes(list.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(json["bots"].as_array().unwrap().len(), 1);
        let copy_path = format!("{location}/duplicate");
        let duplicate = app
            .clone()
            .oneshot(req("POST", &copy_path, &cookie, "copy-key", ""))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CREATED);
        let copy_location = duplicate.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        assert_ne!(copy_location, location);
        let copy_body = to_bytes(duplicate.into_body(), 8192).await.unwrap();
        let copy: Value = serde_json::from_slice(&copy_body).unwrap();
        assert_eq!(copy["bot"]["name"], "Helper");
        assert_eq!(copy["bot"]["roleDescription"], "Help the user");
        let repeat = app
            .clone()
            .oneshot(req("POST", &copy_path, &cookie, "copy-key", ""))
            .await
            .unwrap();
        assert_eq!(repeat.status(), StatusCode::CREATED);
        assert_eq!(repeat.headers()[header::LOCATION], copy_location);
        assert_eq!(to_bytes(repeat.into_body(), 8192).await.unwrap(), copy_body);
        let other_source = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/bots/missing/duplicate",
                &cookie,
                "copy-key",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(other_source.status(), StatusCode::CONFLICT);
        let missing_source = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/bots/missing/duplicate",
                &cookie,
                "missing-key",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(missing_source.status(), StatusCode::NOT_FOUND);
        db.try_with_connection(|c| {
            c.execute("INSERT INTO auth_users(id,email,display_name,password_hash) VALUES ('other-owner','other@example.test','Other','unused')", [])?;
            c.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES ('other-bot','default','other-owner','Private','','secret',0)", [])?;
            Ok(())
        }).unwrap();
        let foreign_source = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/bots/other-bot/duplicate",
                &cookie,
                "foreign-key",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(foreign_source.status(), StatusCode::NOT_FOUND);
        let anonymous = app
            .clone()
            .oneshot(req("POST", &copy_path, "", "anon-key", ""))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        let changed = app
            .clone()
            .oneshot(req(
                "PATCH",
                &location,
                &cookie,
                "change-key",
                r#"{"name":"Changed","title":"","roleDescription":"Help","visibility":"private"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(changed.status(), StatusCode::OK);
        let deleted = app
            .clone()
            .oneshot(req("DELETE", &location, &cookie, "delete-key", ""))
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let missing = app
            .oneshot(req("GET", &location, &cookie, "", ""))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_file(path);
    }
}
