//! Limited Phoenix Channels conversation gateway. No recorder or run-mode support.
use crate::{
    event_journal,
    local_auth::{self, AuthState},
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, Semaphore};

static CHANNEL_EVENTS_TX: OnceLock<broadcast::Sender<(String, String, Value)>> = OnceLock::new();

fn channel_events_tx() -> &'static broadcast::Sender<(String, String, Value)> {
    CHANNEL_EVENTS_TX.get_or_init(|| {
        let (tx, _) = broadcast::channel(256);
        tx
    })
}

pub(crate) fn notify_channel_activity(org_id: &str, owner_id: &str, event: Value) {
    let _ = channel_events_tx().send((org_id.to_owned(), owner_id.to_owned(), event));
}

#[derive(Clone)]
struct Ticket {
    session: [u8; 32],
    owner: String,
    organization: String,
    conversation: String,
    thread: String,
    run: Option<String>,
    key: String,
    expires: Instant,
    expires_at: String,
    used: bool,
}
#[derive(Clone)]
pub struct Gateway {
    auth: AuthState,
    runs: Option<crate::runs::RunState>,
    tickets: Arc<Mutex<HashMap<String, Ticket>>>,
    sockets: Arc<Semaphore>,
}
impl Gateway {
    pub fn new(auth: AuthState, runs: Option<crate::runs::RunState>) -> Self {
        Self {
            auth,
            runs,
            tickets: Arc::new(Mutex::new(HashMap::new())),
            sockets: Arc::new(Semaphore::new(8)),
        }
    }
}
pub fn router(state: Gateway) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/conversations/{id}/join-tokens",
            post(ticket),
        )
        .route(
            "/api/v2/organizations/{organization}/conversation-events",
            get(conversation_events_ws),
        )
        .route("/api/intelligence/client/websocket", get(socket))
        .with_state(state)
}

async fn conversation_events_ws(
    State(s): State<Gateway>,
    Path(org): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !s.auth.valid_origin(&headers).await {
        return problem(StatusCode::FORBIDDEN, "Forbidden");
    }
    let actor = match local_auth::identity(&s.auth, &headers).await {
        Ok(Some(i)) if i.organization == org => i,
        Ok(Some(_)) => return problem(StatusCode::NOT_FOUND, "Not found"),
        _ => return problem(StatusCode::UNAUTHORIZED, "Sign in required"),
    };
    let mut rx = channel_events_tx().subscribe();
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    ws.max_message_size(16384)
        .max_frame_size(16384)
        .on_upgrade(move |mut socket| async move {
            let mut keepalive = tokio::time::interval(Duration::from_secs(20));
            let mut session_check = Instant::now() + Duration::from_secs(10);
            loop {
                tokio::select! {
                    msg = socket.recv() => {
                        if !matches!(msg, Some(Ok(_))) {
                            break;
                        }
                    }
                    ev = rx.recv() => {
                        match ev {
                            Ok((ev_org, ev_owner, payload)) => {
                                if ev_org == org_id && ev_owner == owner_id
                                    && socket.send(Message::Text(payload.to_string().into())).await.is_err()
                                {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                if socket.send(Message::Text(r#"{"resync":true}"#.into())).await.is_err() {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    _ = keepalive.tick() => {
                        if Instant::now() >= session_check {
                            if !matches!(local_auth::check_session_without_refresh(&s.auth, &headers).await, Ok(Some(i)) if i.id == owner_id && i.organization == org_id) {
                                break;
                            }
                            session_check = Instant::now() + Duration::from_secs(10);
                        }
                    }
                }
            }
        })
}
fn problem(code: StatusCode, text: &str) -> Response {
    let mut r = (
        code,
        Json(json!({"type":"about:blank","title":text,"status":code.as_u16()})),
    )
        .into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    r
}
fn token_response(raw: &str, t: &Ticket) -> Response {
    let mut r=(StatusCode::CREATED,Json(json!({"joinToken":raw,"expiresAt":t.expires_at,"threadId":t.thread,"runId":t.run,"realtime":{"clientUrl":"/api/intelligence/client","topic":format!("thread:{}",t.thread)}}))).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    r
}
async fn ticket(
    State(s): State<Gateway>,
    Path((org, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !s.auth.valid_origin(&headers).await {
        return problem(StatusCode::FORBIDDEN, "Forbidden");
    }
    let actor = match local_auth::identity(&s.auth, &headers).await {
        Ok(Some(i)) if i.organization == org || i.slug == org => i,
        Ok(Some(_)) => return problem(StatusCode::NOT_FOUND, "Not found"),
        Ok(None) => return problem(StatusCode::UNAUTHORIZED, "Sign in required"),
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "Unavailable"),
    };
    let Some(binding) = local_auth::session_binding(&headers) else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in required");
    };
    let mut keys = headers.get_all("idempotency-key").iter();
    let key = match (keys.next(), keys.next()) {
        (Some(v), None) => match v.to_str() {
            Ok(v) if !v.is_empty() && v.len() <= 128 && !v.chars().any(char::is_control) => {
                v.to_owned()
            }
            _ => return problem(StatusCode::BAD_REQUEST, "Invalid Idempotency-Key"),
        },
        _ => return problem(StatusCode::BAD_REQUEST, "Idempotency-Key required"),
    };
    let Ok(permit) = s.auth.db_jobs.clone().try_acquire_owned() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Unavailable");
    };
    let db = s.auth.db.clone();
    let cid = id.clone();
    let owner = actor.id.clone();
    let organization = actor.organization.clone();
    let found=tokio::task::spawn_blocking(move||{let _p=permit;db.try_with_connection(|c|{let row:Option<(String,Option<String>,bool)>=c.query_row("SELECT c.thread_id,(SELECT id FROM port_runs WHERE conversation_id=c.id AND status='running' ORDER BY created_at DESC LIMIT 1),EXISTS(SELECT 1 FROM port_runs WHERE conversation_id=c.id) FROM port_conversations c WHERE c.id=?1 AND c.owner_id=?2 AND c.organization_id=?3 AND c.deleted=0",params![cid,owner,organization],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;let expires:String=c.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now','+30 seconds')",[],|r|r.get(0))?;Ok((row,expires))})}).await;
    let ((thread, run), expires_at) = match found {
        Ok(Ok((Some((thread, run, true)), expiry))) => ((thread, run), expiry),
        Ok(Ok((Some((_, _, false)), _))) => {
            return problem(StatusCode::CONFLICT, "Conversation is not joinable")
        }
        Ok(Ok((None, _))) => return problem(StatusCode::NOT_FOUND, "Conversation not found"),
        _ => return problem(StatusCode::SERVICE_UNAVAILABLE, "Unavailable"),
    };
    let mut store = match s.tickets.lock() {
        Ok(m) => m,
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "Unavailable"),
    };
    store.retain(|_, t| !t.used && t.expires > Instant::now());
    if let Some((raw, t)) = store
        .iter()
        .find(|(_, t)| t.owner == actor.id && t.key == key)
    {
        if t.conversation != id || t.session != binding || t.used {
            return problem(StatusCode::CONFLICT, "Idempotency key conflict");
        };
        return token_response(raw, t);
    }
    if store.len() >= 128 {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Too many pending tickets");
    }
    let mut bytes = [0u8; 32];
    if getrandom::getrandom(&mut bytes).is_err() {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Unavailable");
    };
    let raw: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let t = Ticket {
        session: binding,
        owner: actor.id,
        organization: actor.organization,
        conversation: id,
        thread,
        run,
        key,
        expires: Instant::now() + Duration::from_secs(30),
        expires_at,
        used: false,
    };
    let response = token_response(&raw, &t);
    store.insert(raw, t);
    response
}
#[derive(Deserialize)]
struct SocketQuery {
    join_token: String,
    vsn: String,
}
async fn socket(
    State(s): State<Gateway>,
    Query(q): Query<SocketQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if q.vsn != "2.0.0" || q.join_token.len() != 64 || !s.auth.valid_origin(&headers).await {
        return problem(StatusCode::FORBIDDEN, "Forbidden");
    }
    let Some(binding) = local_auth::session_binding(&headers) else {
        return problem(StatusCode::UNAUTHORIZED, "Sign in required");
    };
    let actor = match local_auth::identity(&s.auth, &headers).await {
        Ok(Some(i)) => i,
        _ => return problem(StatusCode::UNAUTHORIZED, "Sign in required"),
    };
    let permit = match s.sockets.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "Too many sockets"),
    };
    let ticket = {
        let mut store = match s.tickets.lock() {
            Ok(m) => m,
            Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "Unavailable"),
        };
        let Some(t) = store.get_mut(&q.join_token) else {
            return problem(StatusCode::UNAUTHORIZED, "Invalid ticket");
        };
        if t.used
            || t.expires <= Instant::now()
            || t.session != binding
            || t.owner != actor.id
            || t.organization != actor.organization
        {
            return problem(StatusCode::UNAUTHORIZED, "Invalid ticket");
        };
        t.used = true;
        t.clone()
    };
    ws.max_message_size(16384)
        .max_frame_size(16384)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            serve(socket, s, ticket, headers).await
        })
}
async fn frame(ws: &mut WebSocket, v: Value) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            ws.send(Message::Text(v.to_string().into()))
        )
        .await,
        Ok(Ok(()))
    )
}
async fn replay(s: &Gateway, t: &Ticket, after: Option<String>) -> Result<Vec<Value>, ()> {
    let permit = s.auth.db_jobs.clone().try_acquire_owned().map_err(|_| ())?;
    let db = s.auth.db.clone();
    let id = t.conversation.clone();
    let owner = t.owner.clone();
    let organization = t.organization.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let allowed = db.try_with_connection(|c| Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM port_conversations WHERE id=?1 AND owner_id=?2 AND organization_id=?3 AND deleted=0)", params![id,owner,organization], |r| r.get::<_,bool>(0))?)).map_err(|_| ())?;
        if !allowed { return Err(()); }
        event_journal::replay(&db, &id, after.as_deref(), 128).map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}
async fn serve(mut ws: WebSocket, s: Gateway, t: Ticket, headers: HeaderMap) {
    let topic = format!("thread:{}", t.thread);
    let mut joined = false;
    let mut join_ref = Value::Null;
    let mut cursor: Option<String> = None;
    let mut last_epoch: u64 = 0;
    let mut timer = tokio::time::interval(Duration::from_millis(500));
    let mut check = Instant::now() + Duration::from_secs(5);
    let join_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        tokio::select! {
          msg=ws.recv()=>{let Some(Ok(Message::Text(text)))=msg else{break};let Ok(v)=serde_json::from_str::<Value>(&text) else{break};let Some(a)=v.as_array().filter(|a|a.len()==5) else{break};let event=a[3].as_str().unwrap_or("");let target=a[2].as_str().unwrap_or("");
            if target=="phoenix" && event=="heartbeat" {if !frame(&mut ws,json!([null,a[1],"phoenix","phx_reply",{"status":"ok","response":{}}])).await{break}continue}
            if !joined && target==topic && event=="phx_join" {
                let payload=match a[4].as_object(){Some(v)=>v,None=>break};
                if payload.get("stream_mode").and_then(Value::as_str).is_some_and(|mode|mode!="connect") {let _=frame(&mut ws,json!([a[0],a[1],topic,"phx_reply",{"status":"error","response":{"reason":"run mode unavailable"}}])).await;break;}
                cursor=match payload.get("last_seen_event_id"){None|Some(Value::Null)=>None,Some(Value::String(x)) if x.len()<=32=>Some(x.clone()),_=>break};
                join_ref=a[0].clone();joined=true;
                if !frame(&mut ws,json!([join_ref,a[1],topic,"phx_reply",{"status":"ok","response":{}}])).await||!frame(&mut ws,json!([join_ref,null,topic,"connected",{"thread_id":t.thread,"user_id":t.owner,"organization_id":t.organization}])).await{break}
                last_epoch = event_journal::journal_epoch();
                loop {let events=match replay(&s,&t,cursor.clone()).await {Ok(e)=>e,Err(_)=>{let _=frame(&mut ws,json!([join_ref,null,topic,"replay_failed",{"reason":"replay unavailable","retryable":true}])).await;return;}};let count=events.len();for event in events {cursor=event["metadata"]["cpki_event_id"].as_str().map(str::to_owned);if !frame(&mut ws,json!([join_ref,null,topic,"ag_ui_event",event])).await{return;}}if count<128{break}}
                if !frame(&mut ws,json!([join_ref,null,topic,"replay_complete",{"thread_id":t.thread,"latestEventId":cursor}])).await{break}
            } else if joined && target==topic && event=="phx_leave" {let _=frame(&mut ws,json!([join_ref,a[1],topic,"phx_reply",{"status":"ok","response":{}}])).await;break}
            else if joined && target==topic && event=="stop_run" {
                let current=local_auth::check_session_without_refresh(&s.auth,&headers).await;
                if !matches!(current,Ok(Some(i)) if i.id==t.owner && i.organization==t.organization) { break; }
                let id=a[4].as_object().and_then(|p| if p.len()==1 {p.get("run_id")} else {None}).and_then(Value::as_str).filter(|v| !v.is_empty() && v.len()<=160 && v.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_'|b'.')));
                let result=match (&s.runs,id) { (Some(runs),Some(id))=>runs.stop_thread_run(t.owner.clone(),t.organization.clone(),t.conversation.clone(),t.thread.clone(),id.to_owned()).await, _=>Err(()) };
                let response=match result {Ok(stopped)=>json!({"status":"ok","response":{"stopped":stopped}}),Err(())=>json!({"status":"error","response":{"reason":"stop unavailable or invalid request"}})};
                if !frame(&mut ws,json!([join_ref,a[1],topic,"phx_reply",response])).await{break}
            }
            else {break}
          },
          _=tokio::time::sleep_until(join_deadline),if !joined=>break,
          _=timer.tick(),if joined=>{
            if Instant::now()>=check {match local_auth::check_session_without_refresh(&s.auth,&headers).await{Ok(Some(i)) if i.id==t.owner&&i.organization==t.organization=>{},_=>break}check=Instant::now()+Duration::from_secs(5);}
            let now_epoch = event_journal::journal_epoch();
            if now_epoch != last_epoch {
                let events=match replay(&s,&t,cursor.clone()).await{Ok(v)=>v,Err(_)=>{let _=frame(&mut ws,json!([join_ref,null,topic,"replay_failed",{"reason":"replay unavailable","retryable":true}])).await;break}};
                if events.len() < 128 {
                    last_epoch = now_epoch;
                }
                for event in events {cursor=event["metadata"]["cpki_event_id"].as_str().map(str::to_owned);if !frame(&mut ws,json!([join_ref,null,topic,"ag_ui_event",event])).await{return;}}
            }
          }
        }
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
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message as ClientMessage};
    use tower::ServiceExt;

    #[tokio::test]
    async fn ticket_socket_replay_and_single_use() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path =
            std::env::temp_dir().join(format!("openbot-ws-{:x}.db", u64::from_le_bytes(random)));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let runs = crate::runs::RunState::new(auth.clone(), "http://127.0.0.1:9/v1", "mock".into()).unwrap();
        let token = runs.test_register_run("run");
        let app = local_auth::router(auth.clone()).merge(router(Gateway::new(auth, Some(runs))));
        let setup=Request::builder().method("POST").uri("/api/port/auth/setup").header("host","example.test").header("origin","http://example.test").header("content-type","application/json").body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#)).unwrap();
        let response = app.clone().oneshot(setup).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        db.try_with_connection(|c|{c.execute_batch("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','help',0 FROM auth_users LIMIT 1; INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'thread','[\"bot\"]','Bot',0 FROM auth_users LIMIT 1; INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) SELECT 'run','conv',id,'bot','m','a','key',x'01','completed',0 FROM auth_users LIMIT 1;")?;Ok(())}).unwrap();
        db.try_with_connection(|c| { c.execute("UPDATE port_runs SET status='running' WHERE id='run'", [])?; Ok(()) }).unwrap();
        event_journal::append(
            &db,
            "conv",
            json!({"type":"RUN_STARTED","threadId":"thread","runId":"run"}),
        )
        .unwrap();
        let ticket_request = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/join-tokens")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("idempotency-key", "join")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(ticket_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let ticket: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let test_app = app.clone();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let url = format!(
            "ws://{address}/api/intelligence/client/websocket?join_token={}&vsn=2.0.0",
            ticket["joinToken"].as_str().unwrap()
        );
        let make_request = || {
            let mut r = url.clone().into_client_request().unwrap();
            r.headers_mut()
                .insert("host", "example.test".parse().unwrap());
            r.headers_mut()
                .insert("origin", "http://example.test".parse().unwrap());
            r.headers_mut().insert("cookie", cookie.parse().unwrap());
            r
        };
        let (mut ws, _) = tokio_tungstenite::connect_async(make_request())
            .await
            .unwrap();
        ws.send(ClientMessage::Text(
            json!(["1", "1", ticket["realtime"]["topic"], "phx_join", {}])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let mut names = Vec::new();
        for _ in 0..4 {
            let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let value: Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
            names.push(value[3].as_str().unwrap().to_owned());
        }
        assert_eq!(
            names,
            ["phx_reply", "connected", "ag_ui_event", "replay_complete"]
        );
        for (id, expected) in [("other", false), ("run", true)] {
            ws.send(ClientMessage::Text(json!(["1", "stop", ticket["realtime"]["topic"], "stop_run", {"run_id": id}]).to_string().into())).await.unwrap();
            let frame = tokio::time::timeout(Duration::from_secs(3), ws.next()).await.unwrap().unwrap().unwrap();
            let reply: Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
            assert_eq!(reply[3], "phx_reply");
            assert_eq!(reply[4]["response"]["stopped"], expected);
            assert_eq!(token.is_cancelled(), expected);
        }
        let reuse = tokio_tungstenite::connect_async(make_request()).await;
        assert!(
            matches!(reuse,Err(tokio_tungstenite::tungstenite::Error::Http(ref r)) if r.status()==StatusCode::UNAUTHORIZED)
        );
        ws.close(None).await.unwrap();
        let fresh = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/join-tokens")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("idempotency-key", "join-again")
            .body(Body::empty())
            .unwrap();
        let fresh = test_app.oneshot(fresh).await.unwrap();
        let ticket: Value =
            serde_json::from_slice(&to_bytes(fresh.into_body(), 4096).await.unwrap()).unwrap();
        let url = format!(
            "ws://{address}/api/intelligence/client/websocket?join_token={}&vsn=2.0.0",
            ticket["joinToken"].as_str().unwrap()
        );
        let mut request = url.into_client_request().unwrap();
        request
            .headers_mut()
            .insert("host", "example.test".parse().unwrap());
        request
            .headers_mut()
            .insert("origin", "http://example.test".parse().unwrap());
        request
            .headers_mut()
            .insert("cookie", cookie.parse().unwrap());
        let (mut resumed, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        resumed
            .send(ClientMessage::Text(
                json!(["2","2",ticket["realtime"]["topic"],"phx_join",{"last_seen_event_id":"1"}])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let mut names = Vec::new();
        for _ in 0..3 {
            let frame = tokio::time::timeout(Duration::from_secs(3), resumed.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let value: Value = serde_json::from_str(frame.to_text().unwrap()).unwrap();
            names.push(value[3].as_str().unwrap().to_owned());
        }
        assert_eq!(names, ["phx_reply", "connected", "replay_complete"]);
        resumed.close(None).await.unwrap();
        server.abort();
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
