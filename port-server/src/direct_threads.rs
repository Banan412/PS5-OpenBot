//! Persistent, owner-scoped allocation of direct Bot chat threads.
//! The caller binding a thread to a Bot must hold an IMMEDIATE transaction.
use crate::{
    local_auth::{self, AuthState, Identity},
    storage::StorageError,
};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/conversation-threads",
            post(mint),
        )
        .route(
            "/api/v2/organizations/{organization}/conversation-threads/{thread_id}",
            get(status),
        )
        .with_state(state)
}
fn problem(status: StatusCode, title: &str) -> Response {
    let mut r = (
        status,
        Json(json!({"type":"about:blank","title":title,"status":status.as_u16()})),
    )
        .into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    r
}
fn answer(status: StatusCode, v: serde_json::Value) -> Response {
    let mut r = (status, Json(v)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    r
}
async fn actor(s: &AuthState, h: &HeaderMap, org: &str, write: bool) -> Result<Identity, Response> {
    if write && !s.valid_origin(h).await {
        return Err(problem(StatusCode::FORBIDDEN, "Forbidden"));
    }
    match local_auth::identity(s, h).await {
        Ok(Some(i)) if i.organization == org || i.slug == org => Ok(i),
        Ok(Some(_)) => Err(problem(StatusCode::NOT_FOUND, "Organization not found")),
        Ok(None) => Err(problem(StatusCode::UNAUTHORIZED, "Sign in required")),
        Err(_) => Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service unavailable",
        )),
    }
}
fn uuid() -> Result<String, StorageError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b)
        .map_err(|_| StorageError::InvalidDatabase("entropy unavailable"))?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let h: String = b.iter().map(|v| format!("{v:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn valid_uuid(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}
fn epoch() -> Result<i64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
        .ok_or(StorageError::InvalidDatabase("clock unavailable"))
}
async fn mint(State(s): State<AuthState>, Path(org): Path<String>, headers: HeaderMap) -> Response {
    let i = match actor(&s, &headers, &org, true).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut keys = headers.get_all("idempotency-key").iter();
    let key = match (keys.next(), keys.next()) {
        (Some(k), None) => match k.to_str() {
            Ok(k) if !k.is_empty() && k.len() <= 128 && !k.chars().any(char::is_control) => {
                k.to_owned()
            }
            _ => return problem(StatusCode::BAD_REQUEST, "Invalid Idempotency-Key"),
        },
        _ => return problem(StatusCode::BAD_REQUEST, "Idempotency-Key required"),
    };
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable");
    };
    let db = s.db.clone();
    let result=tokio::task::spawn_blocking(move||{let _permit=permit;db.try_with_connection(|c|{
        let tx=c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;let now=epoch()?;
        tx.execute("DELETE FROM port_direct_thread_requests WHERE created_at<?1",params![now-86400])?;
        let prior:Option<String>=tx.query_row("SELECT thread_id FROM port_direct_thread_requests WHERE organization_id=?1 AND owner_id=?2 AND request_key=?3",params![i.organization,i.id,key],|r|r.get(0)).optional()?;
        if let Some(id)=prior{return Ok(Some(id));}
        let count:i64=tx.query_row("SELECT COUNT(*) FROM port_direct_threads WHERE organization_id=?1 AND owner_id=?2",params![i.organization,i.id],|r|r.get(0))?;if count>=1000{return Ok(None)}
        let id=uuid()?;tx.execute("INSERT INTO port_direct_threads(thread_id,organization_id,owner_id,created_at) VALUES(?1,?2,?3,?4)",params![id,i.organization,i.id,now])?;
        tx.execute("INSERT INTO port_direct_thread_requests(organization_id,owner_id,request_key,thread_id,created_at) VALUES(?1,?2,?3,?4,?5)",params![i.organization,i.id,key,id,now])?;tx.commit()?;Ok(Some(id))
    })}).await;
    match result {
        Ok(Ok(Some(id))) => answer(
            StatusCode::CREATED,
            json!({"threadId":id,"liveThreadId":id}),
        ),
        Ok(Ok(None)) => problem(StatusCode::SERVICE_UNAVAILABLE, "Thread limit reached"),
        _ => problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    }
}
async fn status(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let i = match actor(&s, &headers, &org, false).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !valid_uuid(&id) {
        return problem(StatusCode::BAD_REQUEST, "Invalid thread ID");
    }
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable");
    };
    let db = s.db.clone();
    let check_id = id.clone();
    let result=tokio::task::spawn_blocking(move||{let _permit=permit;db.try_with_connection(|c|Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM port_direct_threads d WHERE d.thread_id=?1 AND d.organization_id=?2 AND d.owner_id=?3 AND (d.conversation_id IS NULL OR EXISTS(SELECT 1 FROM port_conversations c WHERE c.id=d.conversation_id AND c.deleted=0))) OR EXISTS(SELECT 1 FROM port_conversations c WHERE c.thread_id=?1 AND c.organization_id=?2 AND c.owner_id=?3 AND c.deleted=0)",params![check_id,i.organization,i.id],|r|r.get::<_,bool>(0))?))}).await;
    match result {
        Ok(Ok(known)) => answer(
            StatusCode::OK,
            json!({"threadId":id,"liveThreadId":id,"known":known}),
        ),
        _ => problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    }
}

/// Bind a minted, owner-scoped direct thread to one owned Bot and return its
/// conversation id. Caller MUST hold an IMMEDIATE SQLite transaction. An
/// unknown, deleted, unowned, or already differently-bound thread is refused.
pub(crate) fn bind_to_bot(
    c: &Connection,
    organization: &str,
    owner: &str,
    thread: &str,
    bot: &str,
) -> Result<Option<String>, StorageError> {
    if !valid_uuid(thread) {
        return Ok(None);
    }
    let row:Option<(Option<String>,Option<String>)>=c.query_row("SELECT bot_id,conversation_id FROM port_direct_threads WHERE thread_id=?1 AND organization_id=?2 AND owner_id=?3",params![thread,organization,owner],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((bound, conversation)) = row else {
        return Ok(None);
    };
    if let Some(bound) = bound {
        if bound != bot {
            return Ok(None);
        }
        let Some(conversation) = conversation else {
            return Err(StorageError::InvalidDatabase("incomplete direct thread"));
        };
        let accessible:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND thread_id=?4 AND deleted=0)",params![conversation,organization,owner,thread],|r|r.get(0))?;
        return Ok(if accessible { Some(conversation) } else { None });
    }
    let name: Option<String> = c
        .query_row(
            "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
            params![bot, organization, owner],
            |r| r.get(0),
        )
        .optional()?;
    let Some(name) = name else { return Ok(None) };
    let conversation = uuid()?;
    let bots =
        serde_json::to_string(&[bot]).map_err(|_| StorageError::InvalidDatabase("invalid bot"))?;
    let now = epoch()?;
    c.execute("INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![conversation,organization,owner,thread,bots,name,now])?;
    let n=c.execute("UPDATE port_direct_threads SET bot_id=?4,conversation_id=?5 WHERE thread_id=?1 AND organization_id=?2 AND owner_id=?3 AND bot_id IS NULL",params![thread,organization,owner,bot,conversation])?;
    if n != 1 {
        return Err(StorageError::InvalidDatabase("direct thread bind race"));
    }
    Ok(Some(conversation))
}

/// Check a minted direct thread without binding it; both the thread and Bot
/// must belong to the same owner and organization. A differently bound or
/// deleted conversation is denied. This does not mutate state.
pub(crate) fn can_access(
    c: &Connection,
    organization: &str,
    owner: &str,
    thread: &str,
    bot: &str,
) -> Result<bool, StorageError> {
    if !valid_uuid(thread) {
        return Ok(false);
    }
    Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM port_direct_threads d JOIN port_bots b ON b.id=?4 AND b.organization_id=d.organization_id AND b.owner_id=d.owner_id WHERE d.thread_id=?1 AND d.organization_id=?2 AND d.owner_id=?3 AND (d.bot_id IS NULL OR d.bot_id=?4) AND (d.conversation_id IS NULL OR EXISTS(SELECT 1 FROM port_conversations c WHERE c.id=d.conversation_id AND c.thread_id=d.thread_id AND c.organization_id=d.organization_id AND c.owner_id=d.owner_id AND c.deleted=0)))",params![thread,organization,owner,bot],|r|r.get(0))?)
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
    async fn allocation_is_persistent_private_idempotent_and_one_bot_only() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "openbot-direct-{:x}.db",
            u64::from_le_bytes(random)
        ));
        let db = Arc::new(Storage::open(&path).unwrap());
        db.try_with_connection(|c|{let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='port_direct_threads')",[],|r|r.get(0))?;if !exists{c.execute_batch(include_str!("../migrations/0008_direct_threads.sql"))?;}Ok(())}).unwrap();
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let app = local_auth::router(auth.clone()).merge(router(auth));
        let setup=Request::builder().method("POST").uri("/api/port/auth/setup").header("host","example.test").header("origin","http://example.test").header("content-type","application/json").body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#)).unwrap();
        let setup = app.clone().oneshot(setup).await.unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);
        let cookie = setup.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let mint = || {
            Request::builder()
                .method("POST")
                .uri("/api/v2/organizations/default/conversation-threads")
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("cookie", &cookie)
                .header("idempotency-key", "mint-1")
                .body(Body::empty())
                .unwrap()
        };
        let first = app.clone().oneshot(mint()).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let one: serde_json::Value =
            serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
        let thread = one["threadId"].as_str().unwrap().to_owned();
        assert!(valid_uuid(&thread));
        let repeat = app.clone().oneshot(mint()).await.unwrap();
        let two: serde_json::Value =
            serde_json::from_slice(&to_bytes(repeat.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(one, two);
        let wrong_origin = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversation-threads")
            .header("origin", "http://evil.test")
            .header("cookie", &cookie)
            .header("idempotency-key", "bad")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(wrong_origin).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let (owner,conversation)=db.try_with_connection(|c|{
            let owner:String=c.query_row("SELECT id FROM auth_users LIMIT 1",[],|r|r.get(0))?;
            c.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES('b1','default',?1,'One','','help',0)",params![owner])?;
            c.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES('b2','default',?1,'Two','','help',0)",params![owner])?;
            assert!(can_access(c,"default",&owner,&thread,"b1")?);assert!(!can_access(c,"default","other",&thread,"b1")?);
            let tx=c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;let id=bind_to_bot(&tx,"default",&owner,&thread,"b1")?.unwrap();assert_eq!(bind_to_bot(&tx,"default",&owner,&thread,"b1")?,Some(id.clone()));assert_eq!(bind_to_bot(&tx,"default",&owner,&thread,"b2")?,None);assert_eq!(bind_to_bot(&tx,"default","other",&thread,"b1")?,None);tx.commit()?;Ok((owner,id))
        }).unwrap();
        let read = Request::builder()
            .uri(format!(
                "/api/v2/organizations/default/conversation-threads/{thread}"
            ))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let result = app.clone().oneshot(read).await.unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(result.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(value["known"], true);
        db.try_with_connection(|c| {
            c.execute(
                "UPDATE port_conversations SET deleted=1 WHERE id=?1",
                params![conversation],
            )?;
            assert!(!can_access(c, "default", &owner, &thread, "b1")?);
            Ok(())
        })
        .unwrap();
        let read = Request::builder()
            .uri(format!(
                "/api/v2/organizations/default/conversation-threads/{thread}"
            ))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let result = app.oneshot(read).await.unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(result.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(value["known"], false);
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
