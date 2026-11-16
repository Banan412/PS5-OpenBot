//! Partial CopilotKit v2 SSE adapter for authenticated private text conversations.
//! It delegates all message writes to the canonical run service. Tools, generative
//! UI, stop, multi-agent collaboration and full OpenBot parity are not supported.
use crate::{
    direct_threads, event_journal,
    local_auth::{self, AuthState},
    runs::{self, RunState},
    storage::StorageError,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::stream;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, Semaphore};

#[derive(Clone)]
pub struct Copilot {
    auth: AuthState,
    runs: RunState,
    streams: Arc<Semaphore>,
}
impl Copilot {
    pub fn new(auth: AuthState, runs: RunState) -> Self {
        Self {
            auth,
            runs,
            streams: Arc::new(Semaphore::new(8)),
        }
    }
}
pub fn router(state: Copilot) -> Router {
    Router::new()
        .route("/api/copilotkit/info", get(info))
        .route("/api/copilotkit/agent/{agent}/run", post(run))
        .route("/api/copilotkit/agent/{agent}/connect", post(connect))
        .route("/api/copilotkit/threads/{thread_id}/messages", get(thread_messages))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}
fn error(status: StatusCode, message: &str) -> Response {
    let mut r = (status, Json(json!({"error":message}))).into_response();
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}
async fn actor(s: &Copilot, h: &HeaderMap, write: bool) -> Result<local_auth::Identity, Response> {
    if write && !s.auth.valid_origin(h).await {
        return Err(error(StatusCode::FORBIDDEN, "Forbidden"));
    }
    match local_auth::identity(&s.auth, h).await {
        Ok(Some(i)) => {
            if let Some(org) = h.get("openbot-organization") {
                if org
                    .to_str()
                    .ok()
                    .is_none_or(|v| v != i.organization && v != i.slug)
                {
                    return Err(error(StatusCode::NOT_FOUND, "Organization not found"));
                }
            }
            Ok(i)
        }
        Ok(None) => Err(error(StatusCode::UNAUTHORIZED, "Sign in required")),
        Err(_) => Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service unavailable",
        )),
    }
}
async fn db<T: Send + 'static>(
    s: &AuthState,
    f: impl FnOnce(&mut rusqlite::Connection) -> Result<T, StorageError> + Send + 'static,
) -> Result<T, Response> {
    let permit = s
        .db_jobs
        .clone()
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"))?;
    let db = s.db.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(f)
    })
    .await
    .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"))?
    .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"))
}
async fn info(State(s): State<Copilot>, h: HeaderMap) -> Response {
    let i = match actor(&s, &h, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let result=db(&s.auth,move|c|{let mut stmt=c.prepare("SELECT id,name FROM port_bots WHERE organization_id=?1 AND owner_id=?2 ORDER BY id LIMIT 257")?;let rows=stmt.query_map(params![i.organization,i.id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;Ok(rows)}).await;
    let agents = match result {
        Ok(rows) if rows.len() <= 256 => {
            let mut map = Map::new();
            for (id, name) in rows {
                map.insert(
                    id.clone(),
                    json!({"name":id,"description":name,"className":"OpenBotPort"}),
                );
            }
            map
        }
        Ok(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "Too many bots"),
        Err(e) => return e,
    };
    let mut r=Json(json!({"version":"port-0.1","agents":agents,"mode":"sse","audioFileTranscriptionEnabled":false,"suggestions":false,"a2uiEnabled":false,"openGenerativeUIEnabled":false,"threadEndpoints":{"list":false,"inspect":false,"mutations":false,"realtimeMetadata":false},"telemetryDisabled":true})).into_response();
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}
fn identifier(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 160 && !s.chars().any(char::is_control))
        .map(str::to_owned)
}
fn extract_user_text(content: Option<&Value>) -> Option<String> {
    let val = content?;
    if let Some(s) = val.as_str() {
        return Some(s.to_owned());
    }
    if let Some(parts) = val.as_array() {
        let mut out = String::new();
        for p in parts {
            if p.get("type").and_then(Value::as_str) == Some("text") {
                if let Some(t) = p.get("text").and_then(Value::as_str) {
                    if !out.is_empty() && !t.is_empty() {
                        out.push('\n');
                    }
                    out.push_str(t);
                }
            }
        }
        return Some(out);
    }
    None
}
fn input_text(body: &Value) -> Option<(String, String)> {
    let messages = body.get("messages")?.as_array()?;
    if messages.is_empty() || messages.len() > 512 {
        return None;
    }
    let last = messages.last()?;
    if last.get("role")?.as_str()? != "user" {
        return None;
    }
    let id = identifier(last.get("id"))?;
    let text = extract_user_text(last.get("content"))?;
    if text.trim().is_empty() || text.chars().count() > 16000 {
        return None;
    }
    Some((id, text))
}
async fn bind(
    s: &Copilot,
    i: &local_auth::Identity,
    thread: &str,
    bot: &str,
) -> Result<Option<String>, Response> {
    let org = i.organization.clone();
    let owner = i.id.clone();
    let thread = thread.to_owned();
    let bot = bot.to_owned();
    db(&s.auth,move|c|{let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
 let existing:Option<(String,String)>=tx.query_row("SELECT id,bot_ids_json FROM port_conversations WHERE thread_id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",params![thread,org,owner],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
 let id=if let Some((id,bot_json))=existing {let bots:Vec<String>=serde_json::from_str(&bot_json).map_err(|_|StorageError::InvalidDatabase("invalid bot list"))?;if bots.contains(&bot){Some(id)}else{None}} else {direct_threads::bind_to_bot(&tx,&org,&owner,&thread,&bot)?};tx.commit()?;Ok(id)}).await
}
async fn run(
    State(s): State<Copilot>,
    Path(bot): Path<String>,
    mut h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let i = match actor(&s, &h, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let Some(thread) = identifier(body.get("threadId")) else {
        return error(StatusCode::BAD_REQUEST, "Invalid thread");
    };
    let Some(run_id) = identifier(body.get("runId")) else {
        return error(StatusCode::BAD_REQUEST, "Invalid run");
    };
    let Some((message_id, text)) = input_text(&body) else {
        if let Some(tool_resp) = try_tool_continuation(&s, &i, &bot, &thread, &run_id, &body, &h).await {
            return tool_resp;
        }
        return error(
            StatusCode::BAD_REQUEST,
            "Only text user messages are supported",
        );
    };
    if bot.is_empty() || bot.len() > 200 {
        return error(StatusCode::BAD_REQUEST, "Invalid bot");
    }
    let permit = match s.streams.clone().try_acquire_owned() {
        Ok(v) => v,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "Too many streams"),
    };
    let conversation = match bind(&s, &i, &thread, &bot).await {
        Ok(Some(v)) => v,
        Ok(None) => return error(StatusCode::NOT_FOUND, "Thread or bot not found"),
        Err(e) => return e,
    };
    let digest =
        Sha256::digest(format!("copilot\0{}\0{}\0{}", i.id, conversation, message_id).as_bytes());
    let key = format!(
        "copilot-{}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    h.insert(
        "idempotency-key",
        HeaderValue::from_str(&key).expect("generated key"),
    );
    let response = runs::send_with_run_id(
        State(s.runs.clone()),
        Path((i.organization.clone(), conversation.clone())),
        h.clone(),
        Json(runs::Input {
            id: message_id.clone(),
            text,
            bot_id: Some(bot),
            ..Default::default()
        }),
        Some(run_id.clone()),
    )
    .await;
    if response.status() != StatusCode::ACCEPTED {
        return response;
    }
    // Confirm the canonical durable id even on an idempotent replay. Never
    // attach a stream to a caller-supplied id that names a different run.
    let owner = i.id.clone();
    let cid = conversation.clone();
    let expected_message = message_id;
    let persisted = db(&s.auth, move |c| {
        Ok(c.query_row(
        "SELECT id FROM port_runs WHERE conversation_id=?1 AND owner_id=?2 AND user_message_id=?3",
        params![cid,owner,expected_message], |r| r.get::<_,String>(0)
    ).optional()?)
    })
    .await;
    match persisted {
        Ok(Some(id)) if id == run_id => {}
        Ok(_) => return error(StatusCode::CONFLICT, "Run identity conflict"),
        Err(e) => return e,
    }
    let (tx, rx) = mpsc::channel::<String>(16);
    let worker = s.clone();
    let owner = i.id;
    let organization = i.organization;
    tokio::spawn(async move {
        let _permit = permit;
        stream_run(
            worker,
            conversation,
            thread,
            run_id,
            owner,
            organization,
            h,
            tx,
        )
        .await;
    });
    sse(rx)
}
async fn try_tool_continuation(
    s: &Copilot,
    i: &local_auth::Identity,
    bot: &str,
    thread: &str,
    run_id: &str,
    body: &Value,
    _h: &HeaderMap,
) -> Option<Response> {
    let messages = body.get("messages")?.as_array()?;
    if messages.is_empty() || messages.len() > 512 {
        return None;
    }
    let last = messages.last()?;
    if last.get("role")?.as_str()? != "tool" {
        return None;
    }
    if bot.is_empty() || bot.len() > 200 {
        return Some(error(StatusCode::BAD_REQUEST, "Invalid bot"));
    }
    let permit = match s.streams.clone().try_acquire_owned() {
        Ok(v) => v,
        Err(_) => return Some(error(StatusCode::SERVICE_UNAVAILABLE, "Too many streams")),
    };
    let conversation = match bind(s, i, thread, bot).await {
        Ok(Some(v)) => v,
        Ok(None) => return Some(error(StatusCode::NOT_FOUND, "Thread or bot not found")),
        Err(e) => return Some(e),
    };
    let tc_id = last
        .get("toolCallId")
        .or_else(|| last.get("tool_call_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let tool_content = last.get("content").and_then(Value::as_str).unwrap_or("");
    let waiting_placeholder = tool_content.contains("\"waiting\":true");

    let org = i.organization.clone();
    let owner = i.id.clone();
    let bot_c = bot.to_owned();
    let conv_c = conversation.clone();
    let tc_c = tc_id.clone();
    let lookup = db(&s.auth, move |c| {
        let instructions: Option<String> = c
            .query_row(
                "SELECT role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![bot_c, org, owner],
                |r| r.get(0),
            )
            .optional()?;
        let approval_state: Option<(String, String, i64)> = if !tc_c.is_empty() {
            c.query_row(
                "SELECT id, status, created_at FROM port_approvals WHERE organization_id=?1 AND actor_id=?2 AND conversation_id=?3 AND tool_call_id=?4 ORDER BY created_at DESC LIMIT 1",
                params![org, owner, conv_c, tc_c],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
        } else {
            None
        };
        let resumed_text: Option<String> = if let Some((_, ref st, app_ts)) = approval_state {
            if st != "pending" {
                c.query_row(
                    "SELECT text FROM port_conversation_messages WHERE conversation_id=?1 AND role='bot' AND bot_id=?2 AND status='completed' AND text!='' AND created_at>=?3 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                    params![conv_c, bot_c, app_ts],
                    |r| r.get(0),
                )
                .optional()?
            } else {
                None
            }
        } else {
            None
        };
        Ok((instructions, approval_state, resumed_text))
    })
    .await;

    let (instructions, approval_state, resumed_text) = match lookup {
        Ok(v) => v,
        Err(e) => return Some(e),
    };
    let Some(instructions) = instructions else {
        return Some(error(StatusCode::NOT_FOUND, "Bot not found"));
    };

    let (tx, rx) = mpsc::channel::<String>(32);
    let thread_s = thread.to_owned();
    let run_s = run_id.to_owned();
    let worker = s.clone();
    let conv_s = conversation.clone();
    let org_s = i.organization.clone();
    let owner_s = i.id.clone();
    let bot_s = bot.to_owned();

    // Already handled by approval interrupt / server-side resume: avoid duplicate model calls.
    if waiting_placeholder || approval_state.is_some() {
        tokio::spawn(async move {
            let _permit = permit;
            let _ = send_event(&tx, &json!({"type":"RUN_STARTED","threadId":thread_s,"runId":run_s})).await;
            if let Some((app_id, status, _)) = approval_state {
                if status == "pending" {
                    let _ = send_event(
                        &tx,
                        &json!({
                            "type": "RUN_FINISHED",
                            "threadId": thread_s,
                            "runId": run_s,
                            "outcome": {
                                "type": "interrupt",
                                "interrupts": [{
                                    "id": app_id,
                                    "reason": "tool_call",
                                    "toolCallId": tc_id,
                                }]
                            }
                        }),
                    )
                    .await;
                    return;
                }
                if let Some(text) = resumed_text {
                    let msg_id = format!("assistant_resume_{run_s}");
                    let _ = send_event(&tx, &json!({"type":"TEXT_MESSAGE_START","messageId":msg_id,"role":"assistant"})).await;
                    let _ = send_event(&tx, &json!({"type":"TEXT_MESSAGE_CONTENT","messageId":msg_id,"delta":text})).await;
                    let _ = send_event(&tx, &json!({"type":"TEXT_MESSAGE_END","messageId":msg_id})).await;
                }
            }
            let _ = send_event(&tx, &json!({"type":"RUN_FINISHED","threadId":thread_s,"runId":run_s})).await;
        });
        return Some(sse(rx));
    }

    // Standard client-side tool continuation turn: forward OpenAI messages and stream response.
    let mut oai_messages = vec![json!({"role": "system", "content": instructions})];
    let total_msgs = messages.len();
    let start_idx = total_msgs.saturating_sub(8);
    for (idx, m) in messages.iter().enumerate().skip(start_idx) {
        let is_recent = idx + 2 >= total_msgs;
        let Some(role) = m.get("role").and_then(Value::as_str) else {
            continue;
        };
        match role {
            "user" => {
                if let Some(c) = m.get("content") {
                    let clipped = match c {
                        Value::String(s) if !is_recent => Value::String(crate::runs::clip_chars(s, 900)),
                        other => other.clone(),
                    };
                    oai_messages.push(json!({"role": "user", "content": clipped}));
                }
            }
            "assistant" => {
                let mut entry = Map::new();
                entry.insert("role".into(), json!("assistant"));
                match m.get("content") {
                    Some(Value::String(s)) if !is_recent => {
                        entry.insert("content".into(), Value::String(crate::runs::clip_chars(s, 900)));
                    }
                    Some(c) if !c.is_null() => {
                        entry.insert("content".into(), c.clone());
                    }
                    _ => {
                        entry.insert("content".into(), Value::Null);
                    }
                }
                if let Some(tcs) = m.get("toolCalls").and_then(Value::as_array) {
                    if !tcs.is_empty() {
                        let norm_tcs: Vec<Value> = tcs
                            .iter()
                            .filter_map(|tc| {
                                let obj = tc.as_object()?;
                                let id = obj.get("id")?.as_str()?;
                                let f = obj.get("function").and_then(Value::as_object);
                                let name = f
                                    .and_then(|fo| fo.get("name"))
                                    .or_else(|| obj.get("name"))
                                    .and_then(Value::as_str)?;
                                let args_val = f
                                    .and_then(|fo| fo.get("arguments"))
                                    .or_else(|| obj.get("arguments"));
                                let args_str = match args_val {
                                    Some(Value::String(s)) => s.clone(),
                                    Some(v) if !v.is_null() => v.to_string(),
                                    _ => "{}".to_owned(),
                                };
                                Some(json!({
                                    "id": id,
                                    "type": "function",
                                    "function": { "name": name, "arguments": args_str }
                                }))
                            })
                            .collect();
                        if !norm_tcs.is_empty() {
                            entry.insert("tool_calls".into(), Value::Array(norm_tcs));
                        }
                    }
                }
                oai_messages.push(Value::Object(entry));
            }
            "tool" => {
                let tid = m
                    .get("toolCallId")
                    .or_else(|| m.get("tool_call_id"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let content_str = match m.get("content") {
                    Some(Value::String(s)) => s.clone(),
                    Some(v) if !v.is_null() => v.to_string(),
                    _ => "{}".to_owned(),
                };
                oai_messages.push(json!({"role": "tool", "tool_call_id": tid, "content": crate::runs::clip_chars(&content_str, 3500)}));
            }
            _ => {}
        }
    }

    tokio::spawn(async move {
        let _permit = permit;
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut req = json!({
            "model": worker.runs.model_id,
            "messages": oai_messages,
            "tools": runs::tools_schema(),
            "n": 1
        });
        if worker.runs.model_id == "auto" {
            if let Err(reason) = crate::runs::resolve_active_model(&worker.runs.model, &mut req, &cancel).await {
                let _ = send_event(&tx, &json!({"type":"RUN_STARTED","threadId":thread_s,"runId":run_s})).await;
                let _ = send_event(&tx, &json!({"type":"RUN_ERROR","threadId":thread_s,"runId":run_s,"message":reason})).await;
                return;
            }
        }
        let msg_id = format!("assistant_tool_{run_s}");
        let (ev_tx, mut ev_rx) = mpsc::channel(32);
        let model_client = worker.runs.model.clone();
        let t_c = thread_s.clone();
        let r_c = run_s.clone();
        let m_c = msg_id.clone();
        let c_c = cancel.clone();
        let task = tokio::spawn(async move {
            crate::run_engine::stream_turn(model_client, req, &t_c, &r_c, &m_c, true, ev_tx, c_c).await
        });
        let _ = send_event(&tx, &json!({"type":"RUN_STARTED","threadId":thread_s,"runId":run_s})).await;
        let mut answer = String::new();
        let mut sent_terminal = false;
        while let Some(ev) = ev_rx.recv().await {
            let kind = ev.get("type").and_then(Value::as_str).unwrap_or("");
            if kind == "TEXT_MESSAGE_CONTENT" {
                if let Some(d) = ev.get("delta").and_then(Value::as_str) {
                    answer.push_str(d);
                }
            }
            if kind == "RUN_FINISHED" || kind == "RUN_ERROR" {
                sent_terminal = true;
            }
            if !send_event(&tx, &ev).await {
                cancel.cancel();
                break;
            }
        }
        let task_res = task.await;
        if !sent_terminal {
            match task_res {
                Ok(Err(e)) => {
                    let _ = send_event(&tx, &json!({"type":"RUN_ERROR","threadId":thread_s,"runId":run_s,"message":e.to_string()})).await;
                }
                _ => {
                    let _ = send_event(&tx, &json!({"type":"RUN_FINISHED","threadId":thread_s,"runId":run_s})).await;
                }
            }
        }
        if !answer.trim().is_empty() {
            let db_pool = worker.auth.db.clone();
            let conv_w = conv_s.clone();
            let owner_w = owner_s.clone();
            let bot_w = bot_s.clone();
            let ans_w = answer.clone();
            let mid_w = msg_id.clone();
            let iso = tokio::task::spawn_blocking(move || {
                db_pool.try_with_connection(|c| {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    c.execute(
                        "INSERT OR REPLACE INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,?5,'completed',?6)",
                        params![mid_w, conv_w, owner_w, bot_w, ans_w, ts],
                    )?;
                    c.execute(
                        "UPDATE port_conversations SET last_message_at=MAX(COALESCE(last_message_at,0),?2) WHERE id=?1",
                        params![conv_w, ts],
                    )?;
                    c.query_row(
                        "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', ?1, 'unixepoch')",
                        params![ts],
                        |r| r.get::<_, String>(0),
                    )
                    .map_err(StorageError::from)
                })
            })
            .await;
            if let Ok(Ok(iso_ts)) = iso {
                let first_line = answer.lines().next().unwrap_or("").trim().to_owned();
                let summary_text = answer.split_whitespace().collect::<Vec<_>>().join(" ");
                crate::realtime::notify_channel_activity(
                    &org_s,
                    &owner_s,
                    json!({
                        "channelId": conv_s,
                        "lastMessage": summary_text,
                        "lastMessageAt": iso_ts,
                        "lastMessageAgentId": bot_s,
                        "firstLine": first_line,
                    }),
                );
            }
        }
    });
    Some(sse(rx))
}

fn sse(rx: mpsc::Receiver<String>) -> Response {
    let stream = stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|s| (Ok::<_, Infallible>(s), rx))
    });
    let mut r = Response::new(Body::from_stream(stream));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );
    r.headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    r
}
async fn send_event(tx: &mpsc::Sender<String>, event: &Value) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            tx.send(format!("data: {}\n\n", event))
        )
        .await,
        Ok(Ok(()))
    )
}
async fn stream_run(
    s: Copilot,
    conversation: String,
    thread: String,
    run: String,
    owner: String,
    org: String,
    headers: HeaderMap,
    tx: mpsc::Sender<String>,
) {
    let mut cursor: Option<String> = None;
    let mut in_run = false;
    let deadline = Instant::now() + Duration::from_secs(610);
    let mut auth_at = Instant::now() + Duration::from_secs(5);
    let mut unavailable = 0u8;
    let mut terminal_polls = 0u8;
    let mut keepalive = Instant::now() + Duration::from_secs(15);
    let mut last_epoch: u64 = 0;
    let mut next_poll_at = Instant::now();
    loop {
        if tx.is_closed() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = send_event(
                &tx,
                &json!({"type":"RUN_ERROR","message":"Run stream timed out"}),
            )
            .await;
            return;
        }
        if Instant::now() >= auth_at {
            match local_auth::check_session_without_refresh(&s.auth, &headers).await {
                Ok(Some(i)) if i.id == owner && i.organization == org => {}
                _ => return,
            };
            auth_at = Instant::now() + Duration::from_secs(5)
        }
        // Recheck the live conversation's ownership and deletion state while
        // the stream is open; session revocation is checked above.
        let cid = conversation.clone();
        let oid = owner.clone();
        let org_id = org.clone();
        let tid = thread.clone();
        let rid = run.clone();
        let allowed = db(&s.auth, move |c| Ok(c.query_row(
            "SELECT EXISTS(SELECT 1 FROM port_conversations c JOIN port_runs r ON r.conversation_id=c.id WHERE c.id=?1 AND c.owner_id=?2 AND c.organization_id=?3 AND c.thread_id=?4 AND c.deleted=0 AND r.id=?5 AND r.owner_id=?2)",
            params![cid,oid,org_id,tid,rid], |r| r.get::<_,bool>(0)
        )?)).await;
        match allowed {
            Ok(true) => {}
            Ok(false) => return,
            Err(_) => {
                unavailable += 1;
                if unavailable >= 20 {
                    let _ = send_event(
                        &tx,
                        &json!({"type":"RUN_ERROR","message":"Conversation stream unavailable"}),
                    )
                    .await;
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        }
        let now_epoch = crate::event_journal::journal_epoch();
        if now_epoch == last_epoch && Instant::now() < next_poll_at {
            if Instant::now() >= keepalive {
                if !matches!(
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        tx.send(": keepalive\n\n".to_owned())
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    return;
                }
                keepalive = Instant::now() + Duration::from_secs(15)
            }
            tokio::select! {_ = tx.closed()=>return,_=tokio::time::sleep(Duration::from_millis(200))=>{}}
            continue;
        }
        next_poll_at = Instant::now() + Duration::from_secs(1);
        let permit = match s.auth.db_jobs.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let database = s.auth.db.clone();
        let id = conversation.clone();
        let from = cursor.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _p = permit;
            event_journal::replay(&database, &id, from.as_deref(), 128)
        })
        .await;
        let events = match result {
            Ok(Ok(v)) => {
                unavailable = 0;
                v
            }
            _ => {
                unavailable += 1;
                if unavailable >= 20 {
                    let _ = send_event(
                        &tx,
                        &json!({"type":"RUN_ERROR","message":"Conversation stream unavailable"}),
                    )
                    .await;
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let n = events.len();
        if n < 128 {
            last_epoch = now_epoch;
        }
        for event in events {
            cursor = event
                .get("metadata")
                .and_then(|m| m.get("cpki_event_id"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
            if kind == "RUN_STARTED" {
                in_run = event.get("runId").and_then(Value::as_str) == Some(run.as_str());
            }
            if in_run {
                if !send_event(&tx, &event).await {
                    return;
                }
                if kind == "RUN_FINISHED" || kind == "RUN_ERROR" {
                    return;
                }
            }
        }
        if n == 128 {
            continue;
        }
        let cid = conversation.clone();
        let rid = run.clone();
        let status = db(&s.auth, move |c| {
            Ok(c.query_row(
                "SELECT status FROM port_runs WHERE id=?1 AND conversation_id=?2",
                params![rid, cid],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
        })
        .await;
        match status {
            Ok(Some(v)) if v == "running" => terminal_polls = 0,
            Ok(Some(v)) => {
                terminal_polls += 1;
                if terminal_polls >= 2 {
                    let ev = if v == "completed" {
                        json!({"type":"RUN_FINISHED","threadId":thread,"runId":run})
                    } else {
                        json!({"type":"RUN_ERROR","message":"Run ended without a complete event stream"})
                    };
                    let _ = send_event(&tx, &ev).await;
                    return;
                }
            }
            Ok(None) => return,
            Err(_) => {}
        }
        if Instant::now() >= keepalive {
            if !matches!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    tx.send(": keepalive\n\n".to_owned())
                )
                .await,
                Ok(Ok(()))
            ) {
                return;
            }
            keepalive = Instant::now() + Duration::from_secs(15)
        }
        tokio::select! {_ = tx.closed()=>return,_=tokio::time::sleep(Duration::from_millis(200))=>{}}
    }
}

async fn thread_messages(
    State(s): State<Copilot>,
    Path(thread_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let i = match actor(&s, &headers, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org = i.organization.clone();
    let owner = i.id.clone();
    let tid = thread_id.clone();
    let Ok(rows) = db(&s.auth, move |c| {
        let conv_id: Option<String> = c
            .query_row(
                "SELECT id FROM port_conversations WHERE thread_id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0 LIMIT 1",
                params![tid, org, owner],
                |r| r.get(0),
            )
            .optional()?;
        let Some(conv_id) = conv_id else {
            return Ok(None);
        };
        let mut st = c.prepare(
            "SELECT id, role, text FROM port_conversation_messages WHERE conversation_id=?1 AND status='completed' AND text!='' ORDER BY created_at ASC, rowid ASC",
        )?;
        let msgs = st
            .query_map(params![conv_id], |r| {
                let id: String = r.get(0)?;
                let role: String = r.get(1)?;
                let text: String = r.get(2)?;
                Ok(json!({
                    "id": id,
                    "role": if role == "person" { "user" } else { "assistant" },
                    "content": text,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(msgs))
    })
    .await
    else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable");
    };
    let Some(messages) = rows else {
        return error(StatusCode::NOT_FOUND, "Thread not found");
    };
    let mut r = (StatusCode::OK, Json(json!({ "messages": messages }))).into_response();
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    r
}

/// A connect returns the persisted text transcript; if a run is in progress,
/// it also follows that run from its start. A minted, unbound direct thread is
/// empty but must belong to the caller and name an owned bot.
async fn connect(
    State(s): State<Copilot>,
    Path(bot): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let i = match actor(&s, &h, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let Some(thread) = identifier(body.get("threadId")) else {
        return error(StatusCode::BAD_REQUEST, "Invalid thread");
    };
    if bot.is_empty() || bot.len() > 200 {
        return error(StatusCode::BAD_REQUEST, "Invalid bot");
    }
    let permit = match s.streams.clone().try_acquire_owned() {
        Ok(v) => v,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "Too many streams"),
    };
    let org = i.organization.clone();
    let owner = i.id.clone();
    let wanted = thread.clone();
    let bot_id = bot.clone();
    let result=db(&s.auth,move|c|{
   let row:Option<(String,String)>=c.query_row("SELECT id,bot_ids_json FROM port_conversations WHERE thread_id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",params![wanted,org,owner],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
   let Some((conversation,bot_json))=row else {return Ok(if direct_threads::can_access(c,&org,&owner,&wanted,&bot_id)? {Some((None,Vec::<Value>::new(),None))} else {None})};
   let bots:Vec<String>=serde_json::from_str(&bot_json).map_err(|_|StorageError::InvalidDatabase("invalid bot list"))?;
   if !bots.contains(&bot_id){return Ok(None)}
   let mut stmt=c.prepare("SELECT id,role,text FROM port_conversation_messages WHERE conversation_id=?1 AND (role='person' OR (role='bot' AND bot_id=?2 AND status!='running' AND text!='')) AND status!='queued' ORDER BY rowid ASC LIMIT 201")?;
   let messages=stmt.query_map(params![conversation,bot_id],|r|{let id:String=r.get(0)?;let role:String=r.get(1)?;let text:String=r.get(2)?;Ok(json!({"id":id,"role":if role=="person"{"user"}else{"assistant"},"content":text}))})?.collect::<rusqlite::Result<Vec<_>>>()?;
   if messages.len()>200 || messages.iter().map(|v|v.to_string().len()).sum::<usize>()>1024*1024{return Err(StorageError::InvalidDatabase("conversation snapshot exceeds limit"))}
   let run:Option<String>=c.query_row("SELECT id FROM port_runs WHERE conversation_id=?1 AND bot_id=?2 AND status='running' ORDER BY rowid DESC LIMIT 1",params![conversation,bot_id],|r|r.get(0)).optional()?;
   Ok(Some((Some(conversation),messages,run)))
 }).await;
    let (conversation, messages, run) = match result {
        Ok(Some(v)) => v,
        Ok(None) => return error(StatusCode::NOT_FOUND, "Thread or bot not found"),
        Err(e) => return e,
    };
    let (tx, rx) = mpsc::channel::<String>(16);
    let worker = s.clone();
    let owner = i.id;
    let organization = i.organization;
    tokio::spawn(async move {
        let _permit = permit;
        if !send_event(
            &tx,
            &json!({"type":"MESSAGES_SNAPSHOT","messages":messages}),
        )
        .await
        {
            return;
        }
        if let (Some(conversation), Some(run)) = (conversation, run) {
            stream_run(
                worker,
                conversation,
                thread,
                run,
                owner,
                organization,
                h,
                tx,
            )
            .await;
        }
    });
    sse(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    #[tokio::test]
    async fn authenticated_sdk_text_run_and_snapshot() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let body="data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello from mock\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";
            let response=format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "openbot-copilot-{:x}.db",
            u64::from_le_bytes(random)
        ));
        let db = Arc::new(Storage::open(&path).unwrap());
        // In the isolated build storage may not yet have integrated the direct-thread migration.
        db.try_with_connection(|c|{let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='port_direct_threads')",[],|r|r.get(0))?;if !exists {c.execute_batch(include_str!("../migrations/0008_direct_threads.sql"))?;}Ok(())}).unwrap();
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let runs =
            RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap();
        let app = local_auth::router(auth.clone()).merge(router(Copilot::new(auth, runs)));
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
        let thread = "11111111-1111-4111-8111-111111111111";
        db.try_with_connection(|c|{c.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Helper','','Be helpful',0 FROM auth_users LIMIT 1",[])?;c.execute("INSERT INTO port_direct_threads(thread_id,organization_id,owner_id,created_at) SELECT ?1,'default',id,0 FROM auth_users LIMIT 1",params![thread])?;Ok(())}).unwrap();
        let get_info = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/copilotkit/info")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_info.status(), StatusCode::OK);
        let info: Value =
            serde_json::from_slice(&to_bytes(get_info.into_body(), 4096).await.unwrap()).unwrap();
        assert!(info["agents"].get("bot").is_some());
        let make = |uri: &str, body: Value| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("cookie", &cookie)
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let connect = app
            .clone()
            .oneshot(make(
                "/api/copilotkit/agent/bot/connect",
                json!({"threadId":thread}),
            ))
            .await
            .unwrap();
        assert_eq!(connect.status(), StatusCode::OK);
        let body = to_bytes(connect.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("MESSAGES_SNAPSHOT"));
        let denied = app
            .clone()
            .oneshot(make(
                "/api/copilotkit/agent/bot/connect",
                json!({"threadId":"22222222-2222-4222-8222-222222222222"}),
            ))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        let run=app.clone().oneshot(make("/api/copilotkit/agent/bot/run",json!({"threadId":thread,"runId":"run-1","messages":[{"id":"message-1","role":"user","content":"Hello"}]}))).await.unwrap();
        assert_eq!(run.status(), StatusCode::OK);
        let body = tokio::time::timeout(Duration::from_secs(10), to_bytes(run.into_body(), 65536))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("RUN_STARTED"));
        assert!(text.contains("Hello from mock"));
        assert!(text.contains("RUN_FINISHED"));
        assert!(text.contains("run-1"));
        let retry=app.clone().oneshot(make("/api/copilotkit/agent/bot/run",json!({"threadId":thread,"runId":"run-1","messages":[{"id":"message-1","role":"user","content":"Hello"}]}))).await.unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        let replay =
            tokio::time::timeout(Duration::from_secs(10), to_bytes(retry.into_body(), 65536))
                .await
                .unwrap()
                .unwrap();
        assert!(String::from_utf8_lossy(&replay).contains("RUN_FINISHED"));
        let conflict=app.clone().oneshot(make("/api/copilotkit/agent/bot/run",json!({"threadId":thread,"runId":"different-run","messages":[{"id":"message-1","role":"user","content":"Hello"}]}))).await.unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let follow = app
            .oneshot(make(
                "/api/copilotkit/agent/bot/connect",
                json!({"threadId":thread}),
            ))
            .await
            .unwrap();
        let body = to_bytes(follow.into_body(), 65536).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Hello from mock"));
        let canonical = db
            .try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT id FROM port_runs WHERE user_message_id='message-1'",
                    [],
                    |r| r.get::<_, String>(0),
                )?)
            })
            .unwrap();
        assert_eq!(canonical, "run-1");
        mock.await.unwrap();
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn multi_turn_after_tool_calls_succeeds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Opened YouTube\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "openbot-copilot-multiturn-{:x}.db",
            u64::from_le_bytes(random)
        ));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let runs =
            RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap();
        let app = local_auth::router(auth.clone()).merge(router(Copilot::new(auth, runs)));
        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let response = app.clone().oneshot(setup).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let thread = "33333333-3333-4333-8333-333333333333";
        db.try_with_connection(|c| {
            c.execute("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Helper','','Be helpful',0 FROM auth_users LIMIT 1", [])?;
            c.execute("INSERT INTO port_direct_threads(thread_id,organization_id,owner_id,created_at) SELECT ?1,'default',id,0 FROM auth_users LIMIT 1", params![thread])?;
            Ok(())
        })
        .unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/api/copilotkit/agent/bot/run")
            .header("cookie", &cookie)
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "threadId": thread,
                    "runId": "run-turn-2",
                    "messages": [
                        {"id": "u1", "role": "user", "content": "Open google.com"},
                        {"id": "a1", "role": "assistant", "content": null, "toolCalls": [{"id": "tc1", "type": "function", "function": {"name": "computer_web_fetch", "arguments": "{\"url\":\"https://google.com\"}"}}]},
                        {"id": "t1", "role": "tool", "toolCallId": "tc1", "content": "{\"status\":200,\"title\":\"Google\"}"},
                        {"id": "a2", "role": "assistant", "content": "I opened Google."},
                        {"id": "u2", "role": "user", "content": [{"type": "text", "text": "Now open youtube.com"}]}
                    ]
                })
                .to_string(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = tokio::time::timeout(Duration::from_secs(10), to_bytes(res.into_body(), 65536))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("Opened YouTube"));
        assert!(text.contains("RUN_FINISHED"));
        mock.await.unwrap();
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
