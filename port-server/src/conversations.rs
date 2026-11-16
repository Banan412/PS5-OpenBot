//! Partial, private conversation endpoints. Sending messages and group collaboration are
//! deliberately unavailable until a durable run engine and membership model exist.
use crate::{
    local_auth::{self, AuthState, Identity},
    storage::StorageError,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    routing::{get, post},
    response::{IntoResponse, Response},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn router(s: AuthState) -> Router {
    let attachments = Router::new()
        .route(
            "/api/v2/organizations/{organization}/conversations/{id}/attachments",
            post(upload_attachment),
        )
        .route(
            "/api/v2/organizations/{organization}/attachments/{attachment_id}",
            get(download_attachment).delete(remove_attachment),
        )
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(s.clone());
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/conversations",
            get(list).post(create),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/{id}",
            get(show).patch(update).delete(remove),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/{id}/messages",
            get(messages),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(s)
        .merge(attachments)
}
fn problem(status: StatusCode, message: &'static str) -> Response {
    let mut r = (
        status,
        Json(json!({"type":"about:blank","title":message,"status":status.as_u16()})),
    )
        .into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    r
}
fn output(status: StatusCode, value: Value, location: Option<&str>) -> Response {
    let mut r = (status, Json(value)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    if let Some(loc) = location {
        if let Ok(h) = loc.parse() {
            r.headers_mut().insert(header::LOCATION, h);
        }
    }
    r
}
async fn actor(
    s: &AuthState,
    h: &HeaderMap,
    organization: &str,
    write: bool,
) -> Result<Identity, Response> {
    if write && !s.valid_origin(h).await {
        return Err(problem(StatusCode::FORBIDDEN, "Forbidden"));
    }
    match local_auth::identity(s, h).await {
        Ok(Some(i)) if i.organization == organization || i.slug == organization => Ok(i),
        Ok(Some(_)) => Err(problem(StatusCode::NOT_FOUND, "Organization not found")),
        Ok(None) => Err(problem(StatusCode::UNAUTHORIZED, "Unauthenticated")),
        Err(_) => Err(problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service unavailable",
        )),
    }
}
fn epoch() -> Result<i64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or(StorageError::InvalidDatabase("clock unavailable"))
}
fn random_id() -> Result<String, StorageError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b)
        .map_err(|_| StorageError::InvalidDatabase("entropy unavailable"))?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}
fn key(h: &HeaderMap) -> Result<String, Response> {
    let mut keys = h.get_all("idempotency-key").iter();
    match (keys.next(), keys.next()) {
        (Some(k), None) => match k.to_str() {
            Ok(k) if !k.is_empty() && k.len() <= 128 && !k.chars().any(char::is_control) => {
                Ok(k.into())
            }
            _ => Err(problem(StatusCode::BAD_REQUEST, "Invalid Idempotency-Key")),
        },
        _ => Err(problem(StatusCode::BAD_REQUEST, "Idempotency-Key required")),
    }
}
fn fingerprint(method: &str, path: &str, body: &Value) -> Vec<u8> {
    let mut d = Sha256::new();
    d.update(method.as_bytes());
    d.update([0]);
    d.update(path.as_bytes());
    d.update([0]);
    d.update(body.to_string().as_bytes());
    d.finalize().to_vec()
}
// Caller holds an IMMEDIATE transaction; changed requests cannot reuse a key.
fn replay(
    c: &rusqlite::Connection,
    org: &str,
    owner: &str,
    key: &str,
    fp: &[u8],
    now: i64,
) -> Result<Option<(u16, Value, Option<String>)>, StorageError> {
    c.execute(
        "DELETE FROM port_conversation_idempotency WHERE created_at < ?1",
        params![now - 86400],
    )?;
    let row:Option<(Vec<u8>,u16,String,Option<String>)>=c.query_row("SELECT fingerprint,status,body,location FROM port_conversation_idempotency WHERE organization_id=?1 AND owner_id=?2 AND request_key=?3",params![org,owner,key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    match row {
        None => Ok(None),
        Some((hash, status, body, loc)) if hash == fp => Ok(Some((
            status,
            serde_json::from_str(&body)
                .map_err(|_| StorageError::InvalidDatabase("invalid stored response"))?,
            loc,
        ))),
        Some(_) => Ok(Some((
            409,
            json!({"type":"about:blank","title":"Idempotency conflict","status":409}),
            None,
        ))),
    }
}
fn remember(
    c: &rusqlite::Connection,
    org: &str,
    owner: &str,
    key: &str,
    fp: &[u8],
    status: u16,
    body: &Value,
    loc: Option<&str>,
    now: i64,
) -> Result<(), StorageError> {
    c.execute(
        "INSERT INTO port_conversation_idempotency VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![org, owner, key, fp, status, body.to_string(), loc, now],
    )?;
    Ok(())
}
fn replay_response((status, body, loc): (u16, Value, Option<String>)) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status == 204 {
        return StatusCode::NO_CONTENT.into_response();
    }
    output(code, body, loc.as_deref())
}
fn row(
    c: &rusqlite::Connection,
    org: &str,
    owner: &str,
    id: &str,
    summary: bool,
) -> Result<Option<Value>, StorageError> {
    let data:Option<(String,String,String,String,Option<String>,bool,i64,Option<i64>,Option<i64>)>=c.query_row("SELECT id,thread_id,bot_ids_json,name,title,pinned,created_at,last_read_at,last_message_at FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",params![id,org,owner],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))).optional()?;
    let Some((id, thread, bots, name, title, pinned, created, read, last)) = data else {
        return Ok(None);
    };
    let bots: Vec<String> = serde_json::from_str(&bots)
        .map_err(|_| StorageError::InvalidDatabase("invalid bot list"))?;
    let mut active = false;
    for bot in &bots {
        let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3)",params![bot,org,owner],|r|r.get(0))?;
        active |= exists;
    }
    let time = |n: Option<i64>| -> rusqlite::Result<Option<String>> {
        match n {
            Some(n) => c.query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%SZ',?1,'unixepoch')",
                params![n],
                |r| r.get(0),
            ),
            None => Ok(None),
        }
    };
    let mut v = json!({"id":id,"name":name,"botIds":bots,"threadId":thread,"active":active,"lastMessageAt":time(last)?});
    if summary {
        let opening:Option<String>=c.query_row("SELECT text FROM port_conversation_messages WHERE conversation_id=?1 AND role='person' ORDER BY created_at,id LIMIT 1",params![id],|r|r.get(0)).optional()?;
        let latest:Option<(String,Option<String>)>=c.query_row("SELECT text,bot_id FROM port_conversation_messages WHERE conversation_id=?1 AND (role='person' OR (status='completed' AND text!='')) ORDER BY created_at DESC,rowid DESC LIMIT 1",params![id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (last_text, last_bot) = latest
            .map(|(text, bot)| (Some(text), bot))
            .unwrap_or((None, None));
        let o = v.as_object_mut().unwrap();
        o.insert("summary".into(), json!(title));
        o.insert("opening".into(), json!(opening));
        o.insert("lastMessage".into(), json!(last_text));
        o.insert("lastMessageBotId".into(), json!(last_bot));
        o.insert("createdAt".into(), json!(time(Some(created))?));
        o.insert("pinned".into(), json!(pinned));
        o.insert("lastReadAt".into(), json!(time(read)?));
        o.insert("canRename".into(), json!(true));
        o.insert("task".into(), json!(false));
        o.insert("work".into(), json!([]));
    } else {
        v.as_object_mut().unwrap().insert("work".into(), json!([]));
    }
    Ok(Some(v))
}
async fn db<F>(s: &AuthState, f: F) -> Result<Value, Response>
where
    F: FnOnce(&mut rusqlite::Connection) -> Result<Value, StorageError> + Send + 'static,
{
    let permit = s
        .db_jobs
        .clone()
        .try_acquire_owned()
        .map_err(|_| problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"))?;
    let db = s.db.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(f)
    })
    .await
    .map_err(|_| problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"))?
    .map_err(|_| problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"))
}
fn paging(q: &HashMap<String, String>) -> Result<(usize, usize), Response> {
    let limit = match q.get("limit") {
        Some(s) => s.parse::<usize>().ok().filter(|v| (1..=200).contains(v)),
        None => Some(50),
    }
    .ok_or_else(|| problem(StatusCode::BAD_REQUEST, "Invalid limit"))?;
    let offset = match q.get("cursor") {
        None => 0,
        Some(s) => {
            let bytes = URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|_| problem(StatusCode::BAD_REQUEST, "Invalid cursor"))?;
            let txt = std::str::from_utf8(&bytes)
                .map_err(|_| problem(StatusCode::BAD_REQUEST, "Invalid cursor"))?;
            txt.parse::<usize>()
                .ok()
                .filter(|v| *v <= 100000)
                .ok_or_else(|| problem(StatusCode::BAD_REQUEST, "Invalid cursor"))?
        }
    };
    Ok((limit, offset))
}
async fn list(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let i = match actor(&s, &headers, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let (limit, offset) = match paging(&q) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let query = q.get("q").cloned();
    if query.as_ref().is_some_and(|v| {
        v.chars().count() < 2 || v.chars().count() > 200 || v.chars().any(char::is_control)
    }) {
        return problem(StatusCode::BAD_REQUEST, "Invalid search");
    }
    // Search results are capped at 50 by the upstream API contract.
    let limit = if query.is_some() {
        limit.min(50)
    } else {
        limit
    };
    match db(&s,move|c|{let mut st=c.prepare("SELECT id FROM port_conversations WHERE organization_id=?1 AND owner_id=?2 AND deleted=0 AND (?5 IS NULL OR instr(lower(name),lower(?5))>0 OR instr(lower(COALESCE(title,'')),lower(?5))>0 OR EXISTS(SELECT 1 FROM port_conversation_messages m WHERE m.conversation_id=port_conversations.id AND instr(lower(m.text),lower(?5))>0)) ORDER BY pinned DESC, COALESCE(last_message_at,created_at) DESC,id DESC LIMIT ?3 OFFSET ?4")?;let ids=st.query_map(params![i.organization,i.id,(limit+1) as i64,offset as i64,query],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;let more=ids.len()>limit;let mut items=Vec::new();for id in ids.iter().take(limit){if let Some(v)=row(c,&i.organization,&i.id,id,true)?{items.push(v)}} Ok(json!({"conversations":items,"nextCursor":if more {Some(URL_SAFE_NO_PAD.encode((offset+limit).to_string()))} else {None}}))}).await {Ok(v)=>output(StatusCode::OK,v,None),Err(e)=>e}
}
async fn show(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let i = match actor(&s, &headers, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    match db(&s, move |c| {
        Ok(json!(row(c, &i.organization, &i.id, &id, false)?))
    })
    .await
    {
        Ok(Value::Null) => problem(StatusCode::NOT_FOUND, "Conversation not found"),
        Ok(v) => output(StatusCode::OK, json!({"conversation":v}), None),
        Err(e) => e,
    }
}
async fn create(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let i = match actor(&s, &headers, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = match key(&headers) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let Some(obj) = body.as_object() else {
        return problem(StatusCode::BAD_REQUEST, "Invalid request");
    };
    if obj.keys().any(|k| k != "botIds" && k != "group")
        || obj.get("group").is_some_and(|g| !g.is_boolean())
    {
        return problem(StatusCode::BAD_REQUEST, "Invalid request");
    }
    let is_group = obj.get("group").and_then(Value::as_bool) == Some(true);
    let Some(raw) = obj.get("botIds").and_then(Value::as_array) else {
        return problem(StatusCode::BAD_REQUEST, "Invalid bot list");
    };
    if raw.is_empty() || raw.len() > 20 {
        return problem(StatusCode::BAD_REQUEST, "Invalid bot list");
    }
    let mut bots = Vec::new();
    let mut seen = HashSet::new();
    for b in raw {
        let Some(b) = b.as_str() else {
            return problem(StatusCode::BAD_REQUEST, "Invalid bot list");
        };
        if b.trim().is_empty() || b.chars().count() > 200 || !seen.insert(b.to_string()) {
            return problem(StatusCode::BAD_REQUEST, "Invalid bot list");
        }
        bots.push(b.to_string());
    }
    let fp = fingerprint("POST", &format!("/conversations"), &body);
    let path_org = org.clone();
    match db(&s,move|c|{let now=epoch()?;let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
      if let Some((status,body,loc))=replay(&tx,&i.organization,&i.id,&key,&fp,now)?{return Ok(json!({"status":status,"body":body,"location":loc}));}
      let mut names=Vec::new();for bot in &bots {let name:Option<String>=tx.query_row("SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",params![bot,i.organization,i.id],|r|r.get(0)).optional()?;match name{Some(name)=>names.push(name),None=>return Ok(json!({"status":404}))}}
      let serialized=serde_json::to_string(&bots).map_err(|_|StorageError::InvalidDatabase("invalid bot list"))?;
      let existing:Option<String>=if is_group || bots.len() > 1 { None } else { tx.query_row("SELECT id FROM port_conversations WHERE organization_id=?1 AND owner_id=?2 AND bot_ids_json=?3 AND deleted=0 LIMIT 1",params![i.organization,i.id,serialized],|r|r.get(0)).optional()? };
      let id=match existing {Some(id)=>id,None=>{let id=random_id()?;let thread=random_id()?;tx.execute("INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![id,i.organization,i.id,thread,serialized,names.join(", "),now])?;id}};
      let conversation=row(&tx,&i.organization,&i.id,&id,false)?.ok_or(StorageError::InvalidDatabase("missing created conversation"))?;let response=json!({"conversation":conversation});let location=format!("/api/v2/organizations/{path_org}/conversations/{id}");
      remember(&tx,&i.organization,&i.id,&key,&fp,201,&response,Some(&location),now)?;tx.commit()?;Ok(json!({"status":201,"body":response,"location":location}))
    }).await {Ok(v)=>dispatch(v),Err(e)=>e}
}
fn dispatch(v: Value) -> Response {
    let status = v.get("status").and_then(Value::as_u64).unwrap_or(500) as u16;
    if status == 404 {
        return problem(StatusCode::NOT_FOUND, "Not found");
    }
    replay_response((
        status,
        v.get("body").cloned().unwrap_or(Value::Null),
        v.get("location").and_then(Value::as_str).map(str::to_owned),
    ))
}
async fn update(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let i = match actor(&s, &headers, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = match key(&headers) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let Some(obj) = body.as_object() else {
        return problem(StatusCode::BAD_REQUEST, "Invalid request");
    };
    if obj.is_empty()
        || obj.keys().any(|k| k != "title" && k != "pinned")
        || obj.get("pinned").is_some_and(|v| !v.is_boolean())
    {
        return problem(StatusCode::BAD_REQUEST, "Invalid request");
    }
    let title = match obj.get("title") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.chars().count() > 80 || s.chars().any(char::is_control) {
                return problem(StatusCode::BAD_REQUEST, "Invalid title");
            }
            Some(if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            })
        }
        _ => return problem(StatusCode::BAD_REQUEST, "Invalid title"),
    };
    let pinned = obj.get("pinned").and_then(Value::as_bool);
    let fp = fingerprint("PATCH", &format!("/conversations/{id}"), &body);
    match db(&s,move|c|{let now=epoch()?;let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;if let Some((status,body,loc))=replay(&tx,&i.organization,&i.id,&key,&fp,now)?{return Ok(json!({"status":status,"body":body,"location":loc}));}if row(&tx,&i.organization,&i.id,&id,false)?.is_none(){return Ok(json!({"status":404}));}
      let mut answer=serde_json::Map::new();if let Some(t)=title{tx.execute("UPDATE port_conversations SET title=?1 WHERE id=?2 AND organization_id=?3 AND owner_id=?4",params![t,id,i.organization,i.id])?;answer.insert("summary".into(),json!(t));}if let Some(p)=pinned{tx.execute("UPDATE port_conversations SET pinned=?1 WHERE id=?2 AND organization_id=?3 AND owner_id=?4",params![p,id,i.organization,i.id])?;answer.insert("pinned".into(),json!(p));}let answer=Value::Object(answer);remember(&tx,&i.organization,&i.id,&key,&fp,200,&answer,None,now)?;tx.commit()?;Ok(json!({"status":200,"body":answer}))}).await{Ok(v)=>dispatch(v),Err(e)=>e}
}
async fn remove(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let i = match actor(&s, &headers, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = match key(&headers) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let discard = match q.get("discardFailedStart").map(String::as_str) {
        None | Some("false") => false,
        Some("true") => true,
        _ => return problem(StatusCode::BAD_REQUEST, "Invalid request"),
    };
    let fp = fingerprint(
        "DELETE",
        &format!("/conversations/{id}"),
        &json!({"discardFailedStart":discard}),
    );
    match db(&s, move |c| {
        let now = epoch()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((status, body, loc)) = replay(&tx, &i.organization, &i.id, &key, &fp, now)? {
            return Ok(json!({"status":status,"body":body,"location":loc}));
        }
        if discard {
            let has: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM port_conversation_messages m JOIN port_conversations c ON c.id=m.conversation_id WHERE c.id=?1 AND c.organization_id=?2 AND c.owner_id=?3 AND c.deleted=0)",
                params![id, i.organization, i.id],
                |r| r.get(0),
            )?;
            if has {
                return Ok(json!({"status":409,"body":{"type":"about:blank","title":"Conversation has messages","status":409}}));
            }
        }
        let changed = tx.execute(
            "UPDATE port_conversations SET deleted=1 WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",
            params![id, i.organization, i.id],
        )?;
        if changed == 0 {
            return Ok(json!({"status":404}));
        }
        let body = Value::Null;
        remember(&tx, &i.organization, &i.id, &key, &fp, 204, &body, None, now)?;
        tx.commit()?;
        Ok(json!({"status":204,"body":body}))
    })
    .await
    {
        Ok(v) => dispatch(v),
        Err(e) => e,
    }
}
async fn messages(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let i = match actor(&s, &headers, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let (limit, offset) = match paging(&q) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let bot = q.get("botId").cloned();
    if bot
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.chars().count() > 200)
    {
        return problem(StatusCode::BAD_REQUEST, "Invalid bot");
    }
    match db(&s,move|c|{if row(c,&i.organization,&i.id,&id,false)?.is_none(){return Ok(json!({"notFound":true}));}let mut st=c.prepare("SELECT id,role,person_id,bot_id,text,status,strftime('%Y-%m-%dT%H:%M:%SZ',created_at,'unixepoch') FROM port_conversation_messages WHERE conversation_id=?1 AND (?2 IS NULL OR bot_id IS NULL OR bot_id=?2) AND NOT (role='bot' AND status='completed' AND trim(text)='') ORDER BY created_at DESC,id DESC LIMIT ?3 OFFSET ?4")?;let mut items=st.query_map(params![id,bot,(limit+1) as i64,offset as i64],|r|{let mid:String=r.get(0)?;Ok((mid.clone(),json!({"id":mid,"role":r.get::<_,String>(1)?,"personId":r.get::<_,Option<String>>(2)?,"botId":r.get::<_,Option<String>>(3)?,"text":r.get::<_,String>(4)?,"status":r.get::<_,String>(5)?,"createdAt":r.get::<_,Option<String>>(6)?})))})?.collect::<Result<Vec<_>,_>>()?;drop(st);let more=items.len()>limit;items.truncate(limit);let mut out=Vec::with_capacity(items.len());let mut att_st=c.prepare("SELECT id,filename,mime_type,size_bytes FROM port_attachments WHERE conversation_id=?1 AND message_id=?2 ORDER BY rowid ASC")?;for(mid,mut msg) in items{let atts=att_st.query_map(params![id,mid],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"mimeType":r.get::<_,String>(2)?,"sizeBytes":r.get::<_,i64>(3)?})))?.collect::<Result<Vec<_>,_>>()?;if !atts.is_empty(){if let Some(obj)=msg.as_object_mut(){obj.insert("attachments".into(),Value::Array(atts));}}out.push(msg);}Ok(json!({"messages":out,"nextCursor":if more{Some(URL_SAFE_NO_PAD.encode((offset+limit).to_string()))}else{None}}))}).await {Ok(v) if v.get("notFound").is_some()=>problem(StatusCode::NOT_FOUND,"Conversation not found"),Ok(v)=>output(StatusCode::OK,v,None),Err(e)=>e}
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn sniff_mime(filename: &str, declared: Option<&str>, bytes: &[u8]) -> String {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "image/png".to_owned();
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return "image/jpeg".to_owned();
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return "image/gif".to_owned();
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return "image/webp".to_owned();
    }
    if bytes.starts_with(b"%PDF-") {
        return "application/pdf".to_owned();
    }
    let guessed = mime_guess::from_path(filename).first_or_octet_stream().to_string();
    if guessed != "application/octet-stream" {
        return guessed;
    }
    if let Some(d) = declared.map(str::trim).filter(|s| !s.is_empty() && *s != "application/octet-stream") {
        return d.to_owned();
    }
    if std::str::from_utf8(bytes).is_ok() {
        "text/plain".to_owned()
    } else {
        "application/octet-stream".to_owned()
    }
}

fn extract_multipart_file(headers: &HeaderMap, body: &[u8]) -> Option<(String, Option<String>, Option<String>, Vec<u8>)> {
    let ct = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    let b_pos = ct.to_ascii_lowercase().find("boundary=")?;
    let raw_b = ct[b_pos + 9..].split(';').next()?.trim().trim_matches('"');
    if raw_b.is_empty() || raw_b.len() > 128 {
        return None;
    }
    let delim = format!("--{raw_b}");
    let delim_bytes = delim.as_bytes();
    let mut pos = find_bytes(body, delim_bytes)?;
    let mut file_name: Option<String> = None;
    let mut file_ct: Option<String> = None;
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut upload_group: Option<String> = None;

    while pos < body.len() {
        pos += delim_bytes.len();
        if body[pos..].starts_with(b"--") {
            break;
        }
        if body[pos..].starts_with(b"\r\n") {
            pos += 2;
        } else if body[pos..].starts_with(b"\n") {
            pos += 1;
        }
        let next = find_bytes(&body[pos..], delim_bytes).map(|o| pos + o)?;
        let mut part = &body[pos..next];
        if part.ends_with(b"\r\n") {
            part = &part[..part.len() - 2];
        } else if part.ends_with(b"\n") {
            part = &part[..part.len() - 1];
        }
        let (hdr_end, sep_len) = if let Some(p) = find_bytes(part, b"\r\n\r\n") {
            (p, 4)
        } else if let Some(p) = find_bytes(part, b"\n\n") {
            (p, 2)
        } else {
            pos = next;
            continue;
        };
        let hdr_str = String::from_utf8_lossy(&part[..hdr_end]);
        let content = &part[hdr_end + sep_len..];
        let mut part_name = None;
        let mut part_filename = None;
        let mut part_ct = None;
        for line in hdr_str.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-disposition:") {
                for seg in line.split(';') {
                    let s = seg.trim();
                    if let Some(v) = s.strip_prefix("name=") {
                        part_name = Some(v.trim_matches('"').to_owned());
                    } else if let Some(v) = s.strip_prefix("filename=") {
                        part_filename = Some(v.trim_matches('"').to_owned());
                    }
                }
            } else if lower.starts_with("content-type:") {
                part_ct = line.split_once(':').map(|(_, v)| v.trim().to_owned());
            }
        }
        match part_name.as_deref() {
            Some("file") => {
                file_name = part_filename.filter(|s| !s.trim().is_empty()).or_else(|| Some("attachment".to_owned()));
                file_ct = part_ct;
                file_bytes = Some(content.to_vec());
            }
            Some("uploadGroup") => {
                let s = String::from_utf8_lossy(content).trim().to_owned();
                if !s.is_empty() {
                    upload_group = Some(s);
                }
            }
            _ => {}
        }
        pos = next;
    }

    let bytes = file_bytes?;
    let name = file_name.unwrap_or_else(|| "attachment".to_owned());
    Some((name, file_ct, upload_group, bytes))
}

async fn upload_attachment(
    State(s): State<AuthState>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let i = match actor(&s, &headers, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let Some((raw_name, declared_ct, upload_group, data)) = extract_multipart_file(&headers, &body) else {
        return problem(StatusCode::BAD_REQUEST, "Invalid multipart upload");
    };
    if data.is_empty() || data.len() > 8 * 1024 * 1024 {
        return problem(StatusCode::BAD_REQUEST, "Attachment must be between 1 byte and 8 MB");
    }
    let clean_name = raw_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("attachment")
        .chars()
        .filter(|c| !c.is_control())
        .take(180)
        .collect::<String>();
    let name = if clean_name.is_empty() {
        "attachment".to_owned()
    } else {
        clean_name
    };
    let mime = sniff_mime(&name, declared_ct.as_deref(), &data);
    let extracted_text = if mime.starts_with("text/")
        || matches!(mime.as_str(), "application/json" | "application/xml" | "application/javascript")
    {
        std::str::from_utf8(&data)
            .ok()
            .map(|t| t.chars().take(12_000).collect::<String>())
    } else {
        None
    };
    let size_bytes = data.len() as i64;
    let org_s = i.organization.clone();
    let owner_s = i.id.clone();
    match db(&s, move |c| {
        if row(c, &org_s, &owner_s, &id, false)?.is_none() {
            return Ok(json!({"notFound": true}));
        }
        let att_id = format!("att_{}", random_id()?);
        let now = epoch()?;
        c.execute(
            "INSERT INTO port_attachments(id,organization_id,conversation_id,owner_id,filename,mime_type,size_bytes,upload_group,data,extracted_text,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![att_id, org_s, id, owner_s, name, mime, size_bytes, upload_group, data, extracted_text, now],
        )?;
        Ok(json!({
            "id": att_id,
            "name": name,
            "mimeType": mime,
            "sizeBytes": size_bytes,
        }))
    })
    .await
    {
        Ok(v) if v.get("notFound").is_some() => problem(StatusCode::NOT_FOUND, "Conversation not found"),
        Ok(v) => output(StatusCode::CREATED, v, None),
        Err(e) => e,
    }
}

async fn download_attachment(
    State(s): State<AuthState>,
    Path((org, attachment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let i = match actor(&s, &headers, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let permit = match s.db_jobs.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    };
    let database = s.db.clone();
    let org_s = i.organization.clone();
    let owner_s = i.id.clone();
    let res = tokio::task::spawn_blocking(move || {
        let _p = permit;
        database.try_with_connection(|c| {
            c.query_row(
                "SELECT filename, mime_type, data FROM port_attachments WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![attachment_id, org_s, owner_s],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?)),
            )
            .optional()
            .map_err(StorageError::from)
        })
    })
    .await;
    match res {
        Ok(Ok(Some((_name, mime, bytes)))) => {
            let mut r = Response::new(axum::body::Body::from(bytes));
            *r.status_mut() = StatusCode::OK;
            if let Ok(hv) = header::HeaderValue::from_str(&mime) {
                r.headers_mut().insert(header::CONTENT_TYPE, hv);
            }
            r.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                header::HeaderValue::from_static("nosniff"),
            );
            r.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("private, max-age=3600"),
            );
            r
        }
        Ok(Ok(None)) => problem(StatusCode::NOT_FOUND, "Attachment not found"),
        _ => problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    }
}

async fn remove_attachment(
    State(s): State<AuthState>,
    Path((org, attachment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let i = match actor(&s, &headers, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_s = i.organization.clone();
    let owner_s = i.id.clone();
    match db(&s, move |c| {
        let row: Option<Option<i64>> = c
            .query_row(
                "SELECT attached_at FROM port_attachments WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![attachment_id, org_s, owner_s],
                |r| r.get(0),
            )
            .optional()?;
        let Some(attached_at) = row else {
            return Ok(json!({"status": 404}));
        };
        if attached_at.is_some() {
            return Ok(json!({"status": 409}));
        }
        c.execute(
            "DELETE FROM port_attachments WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
            params![attachment_id, org_s, owner_s],
        )?;
        Ok(json!({"status": 204}))
    })
    .await
    {
        Ok(v) if v["status"] == 404 => problem(StatusCode::NOT_FOUND, "Attachment not found"),
        Ok(v) if v["status"] == 409 => problem(StatusCode::CONFLICT, "Attachment already sent"),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use std::sync::Arc;
    use tower::ServiceExt;
    #[tokio::test]
    async fn private_crud_idempotency_and_origin() {
        let path =
            std::env::temp_dir().join(format!("openbot-conversation-{}.db", random_id().unwrap()));
        let db = Arc::new(crate::storage::Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let routes = local_auth::router(auth.clone()).merge(router(auth));
        let setup=Request::builder().method("POST").uri("/api/port/auth/setup").header("origin","http://example.test").header("host","example.test").header("content-type","application/json").body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#)).unwrap();
        let response = routes.clone().oneshot(setup).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        db.try_with_connection(|c|{c.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot-1','default',id,'Helper','', '',0 FROM auth_users LIMIT 1",[])?;Ok(())}).unwrap();
        let request = |method: &str, uri: &str, key: &str, body: &str, origin: &str| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("cookie", &cookie)
                .header("origin", origin)
                .header("host", "example.test")
                .header("idempotency-key", key)
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap()
        };
        let collection = "/api/v2/organizations/default/conversations";
        let bad = routes
            .clone()
            .oneshot(request(
                "POST",
                collection,
                "bad",
                r#"{"botIds":["bot-1"]}"#,
                "http://evil.test",
            ))
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::FORBIDDEN);
        let first = routes
            .clone()
            .oneshot(request(
                "POST",
                collection,
                "create-1",
                r#"{"botIds":["bot-1"]}"#,
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let v: Value =
            serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
        let id = v["conversation"]["id"].as_str().unwrap();
        let replay = routes
            .clone()
            .oneshot(request(
                "POST",
                collection,
                "create-1",
                r#"{"botIds":["bot-1"]}"#,
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::CREATED);
        let replay: Value =
            serde_json::from_slice(&to_bytes(replay.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(replay["conversation"]["id"], id);
        let conflict = routes
            .clone()
            .oneshot(request(
                "POST",
                collection,
                "create-1",
                r#"{"botIds":["other"]}"#,
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let uri = format!("{collection}/{id}");
        let patch = routes
            .clone()
            .oneshot(request(
                "PATCH",
                &uri,
                "patch-1",
                r#"{"title":"Project","pinned":true}"#,
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(patch.status(), StatusCode::OK);
        let list = routes
            .clone()
            .oneshot(
                Request::builder()
                    .uri(collection)
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let list: Value =
            serde_json::from_slice(&to_bytes(list.into_body(), 16384).await.unwrap()).unwrap();
        assert_eq!(list["conversations"][0]["summary"], "Project");
        assert_eq!(list["conversations"][0]["pinned"], true);
        // Search covers the displayed name, title and all saved message text.
        db.try_with_connection(|c| {
            c.execute("INSERT INTO port_conversation_messages(id,conversation_id,role,text,status,created_at) VALUES ('m1',?1,'person','100% Hotel Booking','completed',1)", params![id])?;
            c.execute("INSERT INTO auth_users(id,email,display_name,password_hash) VALUES ('other-owner','other@example.test','Other','unused')", [])?;
            c.execute("INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES ('other-conversation','default','other-owner','other-thread','[]','Hotel secret',1)", [])?;
            c.execute("INSERT INTO port_conversation_messages(id,conversation_id,role,text,status,created_at) VALUES ('other-message','other-conversation','person','hotel secret','completed',1)", [])?;
            c.execute("INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at,deleted) SELECT 'deleted-conversation','default',id,'deleted-thread','[]','Hotel deleted',1,1 FROM auth_users WHERE id <> 'other-owner'", [])?;
            Ok(())
        }).unwrap();
        for query in ["helper", "PROJECT", "100%25", "hotel"] {
            let result = routes
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("{collection}?q={query}"))
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(result.status(), StatusCode::OK);
            let result: Value =
                serde_json::from_slice(&to_bytes(result.into_body(), 16384).await.unwrap())
                    .unwrap();
            assert_eq!(
                result["conversations"].as_array().unwrap().len(),
                1,
                "query {query}"
            );
            assert_eq!(result["conversations"][0]["id"], id);
        }
        let empty = routes
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{collection}?q=missing"))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let empty: Value =
            serde_json::from_slice(&to_bytes(empty.into_body(), 16384).await.unwrap()).unwrap();
        assert!(empty["conversations"].as_array().unwrap().is_empty());
        let denied = routes
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri.replace("default", "another"))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        let deleted = routes
            .clone()
            .oneshot(request(
                "DELETE",
                &uri,
                "delete-1",
                "",
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let missing = routes
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let delete_again = routes
            .clone()
            .oneshot(request(
                "DELETE",
                &uri,
                "delete-again",
                "",
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(delete_again.status(), StatusCode::NOT_FOUND);
        let delete_missing = routes
            .clone()
            .oneshot(request(
                "DELETE",
                &format!("{collection}/does-not-exist"),
                "delete-missing",
                "",
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(delete_missing.status(), StatusCode::NOT_FOUND);
        let delete_foreign = routes
            .clone()
            .oneshot(request(
                "DELETE",
                &format!("{collection}/other-conversation"),
                "delete-foreign",
                "",
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(delete_foreign.status(), StatusCode::NOT_FOUND);
        let delete_discard_deleted = routes
            .oneshot(request(
                "DELETE",
                &format!("{uri}?discardFailedStart=true"),
                "delete-discard-deleted",
                "",
                "http://example.test",
            ))
            .await
            .unwrap();
        assert_eq!(delete_discard_deleted.status(), StatusCode::NOT_FOUND);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn delete_discard_failed_start_checks_deleted_flag() {
        let path =
            std::env::temp_dir().join(format!("openbot-conversation-{}.db", random_id().unwrap()));
        let db = Arc::new(crate::storage::Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let routes = local_auth::router(auth.clone()).merge(router(auth));
        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("origin", "http://example.test")
            .header("host", "example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let response = routes.clone().oneshot(setup).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        db.try_with_connection(|c| {
            c.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot-1','default',id,'Helper','', '',0 FROM auth_users LIMIT 1", [])?;
            Ok(())
        })
        .unwrap();
        let create = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations")
            .header("cookie", &cookie)
            .header("origin", "http://example.test")
            .header("host", "example.test")
            .header("idempotency-key", "c1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"botIds":["bot-1"]}"#))
            .unwrap();
        let created = routes.clone().oneshot(create).await.unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let v: Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 4096).await.unwrap()).unwrap();
        let id = v["conversation"]["id"].as_str().unwrap().to_owned();
        db.try_with_connection(|c| {
            c.execute("INSERT INTO port_conversation_messages(id,conversation_id,role,text,status,created_at) VALUES ('m1',?1,'person','hello','completed',1)", params![id])?;
            Ok(())
        })
        .unwrap();

        let delete_conflict = routes
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/v2/organizations/default/conversations/{id}?discardFailedStart=true"
                    ))
                    .header("cookie", &cookie)
                    .header("origin", "http://example.test")
                    .header("host", "example.test")
                    .header("idempotency-key", "d1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_conflict.status(), StatusCode::CONFLICT);

        let delete_force = routes
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/v2/organizations/default/conversations/{id}"
                    ))
                    .header("cookie", &cookie)
                    .header("origin", "http://example.test")
                    .header("host", "example.test")
                    .header("idempotency-key", "d2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_force.status(), StatusCode::NO_CONTENT);

        let delete_after_soft_delete = routes
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/v2/organizations/default/conversations/{id}?discardFailedStart=true"
                    ))
                    .header("cookie", &cookie)
                    .header("origin", "http://example.test")
                    .header("host", "example.test")
                    .header("idempotency-key", "d3")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_after_soft_delete.status(), StatusCode::NOT_FOUND);

        // Creating a group conversation with multiple bots succeeds even across repeated creations.
        db.try_with_connection(|c| {
            c.execute(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot-2','default',id,'Bot 2','','',0 FROM auth_users LIMIT 1",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let g1 = routes
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/organizations/default/conversations")
                    .header("cookie", &cookie)
                    .header("origin", "http://example.test")
                    .header("host", "example.test")
                    .header("idempotency-key", "grp-1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"botIds":["bot-1","bot-2"],"group":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(g1.status(), StatusCode::CREATED);
        let g1_v: Value =
            serde_json::from_slice(&to_bytes(g1.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(g1_v["conversation"]["botIds"], json!(["bot-1", "bot-2"]));
        let g2 = routes
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/organizations/default/conversations")
                    .header("cookie", &cookie)
                    .header("origin", "http://example.test")
                    .header("host", "example.test")
                    .header("idempotency-key", "grp-2")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"botIds":["bot-1","bot-2"],"group":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(g2.status(), StatusCode::CREATED);
        let g2_v: Value =
            serde_json::from_slice(&to_bytes(g2.into_body(), 4096).await.unwrap()).unwrap();
        assert_ne!(g1_v["conversation"]["id"], g2_v["conversation"]["id"]);

        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
