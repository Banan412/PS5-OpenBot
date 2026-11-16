//! Experimental, opt-in host model runs. Tools and WebSocket delivery are not implemented.
use crate::{
    approvals_api,
    event_journal,
    governance,
    local_auth::{self, AuthState},
    model::ModelClient,
    run_engine,
    storage::{Storage, StorageError},
    virtual_computer,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct RunState {
    pub(crate) auth: AuthState,
    pub(crate) model: ModelClient,
    pub(crate) model_id: String,
    capacity: Arc<Semaphore>,
    active: Arc<Mutex<HashMap<String, CancellationToken>>>,
    registration: Arc<tokio::sync::Mutex<()>>,
    virtual_computer: Option<virtual_computer::VirtualComputerState>,
}
impl RunState {
    pub fn new(
        auth: AuthState,
        url: &str,
        model_id: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if model_id.trim().is_empty() || model_id.len() > 200 {
            return Err("invalid model ID".into());
        }
        let model = ModelClient::new(url, Duration::from_secs(5), Duration::from_secs(600))?;
        // Runs interrupted by a process restart have an unknown outcome; never rerun them.
        recover_interrupted(&auth.db)?;
        Ok(Self {
            auth,
            model,
            model_id,
            capacity: Arc::new(Semaphore::new(1)),
            active: Arc::new(Mutex::new(HashMap::new())),
            registration: Arc::new(tokio::sync::Mutex::new(())),
            virtual_computer: None,
        })
    }

    pub fn with_virtual_computer(
        mut self,
        vc: virtual_computer::VirtualComputerState,
    ) -> Self {
        self.virtual_computer = Some(vc);
        self
    }

    pub(crate) fn virtual_computer_state(&self) -> Option<virtual_computer::VirtualComputerState> {
        self.virtual_computer.clone()
    }

    /// Stop only a running job belonging to the authenticated thread scope.
    pub(crate) async fn stop_thread_run(&self, owner: String, org: String, conversation: String, thread: String, run: String) -> Result<bool, ()> {
        let _registration = self.registration.lock().await;
        let permit = self.auth.db_jobs.clone().try_acquire_owned().map_err(|_| ())?;
        let db = self.auth.db.clone();
        let run_id = run.clone();
        let allowed = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            db.try_with_connection(|c| Ok(c.query_row(
                "SELECT EXISTS(SELECT 1 FROM port_runs r JOIN port_conversations c ON c.id=r.conversation_id WHERE r.id=?1 AND r.owner_id=?2 AND r.status='running' AND c.id=?3 AND c.thread_id=?4 AND c.organization_id=?5 AND c.owner_id=?2 AND c.deleted=0)",
                params![run_id, owner, conversation, thread, org], |r| r.get::<_, bool>(0))?))
        }).await.map_err(|_| ())?.map_err(|_| ())?;
        if !allowed { return Ok(false); }
        let map = self.active.lock().map_err(|_| ())?;
        Ok(map.get(&run).is_some_and(|token| { token.cancel(); true }))
    }

    #[cfg(test)]
    pub(crate) fn test_register_run(&self, run: &str) -> CancellationToken {
        let token = CancellationToken::new();
        self.active.lock().unwrap().insert(run.to_owned(), token.clone());
        token
    }
}

/// Mark interrupted runs and their transcript entries failed in the same
/// transaction as their terminal replay event. A full journal records a
/// durable gap, so consumers cannot mistake an incomplete replay for complete.
fn recover_interrupted(db: &Storage) -> Result<(), StorageError> {
    db.try_with_connection(|c| {
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut query=tx.prepare("SELECT r.id,r.conversation_id,r.assistant_message_id,c.thread_id FROM port_runs r JOIN port_conversations c ON c.id=r.conversation_id WHERE r.status='running' LIMIT 4097")?;
        let runs=query.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(query);
        if runs.len()>4096 {return Err(StorageError::InvalidDatabase("too many interrupted runs"));}
        for (run,conversation,message,thread) in runs {
            let (count,total,last):(i64,i64,i64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(bytes),0),COALESCE(MAX(sequence),0) FROM port_run_events WHERE conversation_id=?1",params![conversation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            let next=last.checked_add(1).ok_or(StorageError::InvalidDatabase("event sequence overflow"))?;
            let event=json!({"type":"RUN_ERROR","threadId":thread,"runId":run,"message":"Run interrupted by server restart","metadata":{"cpki_event_id":next.to_string()}}).to_string();
            if count<event_journal::MAX_EVENTS && event.len()<=event_journal::MAX_EVENT_BYTES && total.saturating_add(event.len() as i64)<=event_journal::MAX_TOTAL_BYTES {
                tx.execute("INSERT INTO port_run_events(conversation_id,sequence,event_json,bytes) VALUES(?1,?2,?3,?4)",params![conversation,next,event,event.len() as i64])?;
            } else {
                tx.execute("INSERT INTO port_metadata(key,value) VALUES(?1,'terminal event missing after restart') ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![format!("conversation_replay_gap:{conversation}")])?;
            }
            tx.execute("UPDATE port_conversation_messages SET status='failed' WHERE conversation_id=?1 AND id=?2",params![conversation,message])?;
            tx.execute("UPDATE port_runs SET status='failed' WHERE id=?1",params![run])?;
        }
        tx.commit()?;Ok(())
    })
}
pub fn router(state: RunState) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/conversations/{id}/messages",
            post(send),
        )
        .route("/api/copilotkit/agent/{agent}/stop/{thread}", post(stop))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(state)
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
fn accepted(id: &str, queued: bool) -> Response {
    let mut r = (StatusCode::ACCEPTED, Json(json!({"id":id,"queued":queued}))).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    r
}
fn random_id() -> Result<String, StorageError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| StorageError::InvalidDatabase("entropy unavailable"))?;
    Ok(bytes.iter().map(|x| format!("{x:02x}")).collect())
}
fn now() -> Result<i64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|x| i64::try_from(x.as_secs()).ok())
        .ok_or(StorageError::InvalidDatabase("clock unavailable"))
}
fn is_silent_group_pass(text: &str) -> bool {
    let t = text.trim();
    t.is_empty()
        || t.eq_ignore_ascii_case("[PASS]")
        || t.eq_ignore_ascii_case("[NO_REPLY]")
        || t.eq_ignore_ascii_case("[SILENT]")
}

fn contains_phrase_ci(haystack_lower: &str, needle_lower: &str) -> bool {
    let needle_lower = needle_lower.trim();
    if needle_lower.len() < 2 {
        return false;
    }
    for (idx, _) in haystack_lower.match_indices(needle_lower) {
        let before_ok = haystack_lower[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_idx = idx + needle_lower.len();
        let after_ok = haystack_lower[after_idx..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

fn select_group_turn_bots(
    bots: &[String],
    bot_names: &HashMap<String, String>,
    text: &str,
) -> Vec<String> {
    if bots.len() <= 1 {
        return bots.to_vec();
    }
    let lower = text.to_lowercase();
    if contains_phrase_ci(&lower, "@all")
        || contains_phrase_ci(&lower, "everyone")
        || contains_phrase_ci(&lower, "all bots")
        || contains_phrase_ci(&lower, "all of you")
    {
        return bots.to_vec();
    }
    let matched: Vec<String> = bots
        .iter()
        .filter(|id| {
            bot_names
                .get(*id)
                .is_some_and(|name| contains_phrase_ci(&lower, &name.to_lowercase()))
        })
        .cloned()
        .collect();
    if !matched.is_empty() {
        matched
    } else {
        bots.to_vec()
    }
}

pub(crate) async fn trigger_scheduled_message(
    s: &RunState,
    org: &str,
    owner: &str,
    conversation_id: &str,
    bot_id: &str,
    instruction: &str,
) -> Result<(), String> {
    let permit = s
        .capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| "model capacity busy".to_owned())?;
    let db = s.auth.db.clone();
    let org_s = org.to_owned();
    let owner_s = owner.to_owned();
    let conv_s = conversation_id.to_owned();
    let bot_s = bot_id.to_owned();
    let text_s = instruction.to_owned();
    let prep = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let conv: Option<(String, String)> = tx
                .query_row(
                    "SELECT thread_id, bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",
                    params![conv_s, org_s, owner_s],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((thread, bot_json)) = conv else {
                return Ok(None);
            };
            let bots: Vec<String> = serde_json::from_str(&bot_json).unwrap_or_default();
            if !bots.contains(&bot_s) {
                return Ok(None);
            }
            let active: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM port_runs WHERE conversation_id=?1 AND status='running')",
                params![conv_s],
                |r| r.get(0),
            )?;
            if active {
                return Ok(None);
            }
            let instructions: Option<String> = tx
                .query_row(
                    "SELECT role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                    params![bot_s, org_s, owner_s],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(instructions) = instructions else {
                return Ok(None);
            };
            let run = random_id()?;
            let msg_id = format!("routine_u_{}", random_id()?);
            let reply = format!("assistant_{}", random_id()?);
            let req_key = format!("routine_{run}");
            let ts = now()?;
            tx.execute(
                "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'person',?3,NULL,?4,'completed',?5)",
                params![msg_id, conv_s, owner_s, text_s, ts],
            )?;
            tx.execute(
                "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','running',?5)",
                params![reply, conv_s, owner_s, bot_s, ts],
            )?;
            tx.execute(
                "INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'running',?9)",
                params![run, conv_s, owner_s, bot_s, msg_id, reply, req_key, vec![0u8; 32], ts],
            )?;
            tx.execute(
                "UPDATE port_conversations SET last_message_at=?2 WHERE id=?1",
                params![conv_s, ts],
            )?;
            let messages = vec![
                json!({"role": "system", "content": instructions}),
                json!({"role": "user", "content": text_s}),
            ];
            tx.commit()?;
            Ok(Some((thread, run, reply, messages)))
        })
    })
    .await
    .map_err(|_| "routine task join error".to_owned())?
    .map_err(|e| format!("{e}"))?;
    let Some((thread, run, reply, messages)) = prep else {
        return Err("conversation missing, busy, or bot inactive".to_owned());
    };
    let auth = s.auth.clone();
    let model = s.model.clone();
    let vc = s.virtual_computer.clone();
    let active = s.active.clone();
    let request = json!({"model": s.model_id, "messages": messages, "n": 1});
    let org_c = org.to_owned();
    let owner_c = owner.to_owned();
    let bot_c = bot_id.to_owned();
    let conv_c = conversation_id.to_owned();
    tokio::spawn(async move {
        let _permit = permit;
        let cancel = CancellationToken::new();
        active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(run.clone(), cancel.clone());
        execute(
            auth,
            model,
            vc,
            request,
            org_c,
            owner_c,
            bot_c,
            conv_c,
            thread,
            run.clone(),
            reply,
            cancel,
        )
        .await;
        active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&run);
    });
    Ok(())
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Input {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) text: String,
    pub(crate) bot_id: Option<String>,
    #[serde(default)]
    pub(crate) attachment_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StopScope {
    run_id: Option<String>,
}

async fn stop(
    State(s): State<RunState>,
    Path((bot, thread)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !s.auth.valid_origin(&headers).await {
        return problem(StatusCode::FORBIDDEN, "Forbidden");
    }
    let actor = match local_auth::identity(&s.auth, &headers).await {
        Ok(Some(i)) => i,
        Ok(None) => return problem(StatusCode::UNAUTHORIZED, "Sign in required"),
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    };
    if headers.get("openbot-organization").is_some_and(|v| {
        v.to_str()
            .ok()
            .is_none_or(|v| v != actor.organization && v != actor.slug)
    }) {
        return problem(StatusCode::NOT_FOUND, "Organization not found");
    }
    let scope = if body.is_empty() {
        StopScope { run_id: None }
    } else {
        match serde_json::from_slice::<StopScope>(&body) {
            Ok(v) => v,
            Err(_) => return problem(StatusCode::BAD_REQUEST, "Invalid stop request"),
        }
    };
    if scope
        .run_id
        .as_ref()
        .is_some_and(|v| v.trim().is_empty() || v.len() > 160 || v.chars().any(char::is_control))
    {
        return problem(StatusCode::BAD_REQUEST, "Invalid run ID");
    }
    let _registration = s.registration.lock().await;
    let Ok(permit) = s.auth.db_jobs.clone().try_acquire_owned() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable");
    };
    let db = s.auth.db.clone();
    let result = tokio::task::spawn_blocking(move || { let _permit=permit; db.try_with_connection(|c| {
        let row:Option<Option<String>>=c.query_row("SELECT (SELECT id FROM port_runs r WHERE r.conversation_id=c.id AND r.bot_id=?1 AND r.status='running' AND (?5 IS NULL OR r.id=?5) LIMIT 1) FROM port_conversations c JOIN port_bots b ON b.id=?1 AND b.organization_id=c.organization_id AND b.owner_id=c.owner_id WHERE c.thread_id=?2 AND c.organization_id=?3 AND c.owner_id=?4 AND c.deleted=0",params![bot,thread,actor.organization,actor.id,scope.run_id],|r|r.get(0)).optional()?;
        Ok(row)
    }) }).await;
    let run = match result {
        Ok(Ok(Some(v))) => v,
        Ok(Ok(None)) => return problem(StatusCode::NOT_FOUND, "Thread or bot not found"),
        _ => return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    };
    let stopped = run
        .as_ref()
        .and_then(|id| s.active.lock().ok().and_then(|map| map.get(id).cloned()))
        .is_some_and(|token| {
            token.cancel();
            true
        });
    let mut response = Json(if stopped { json!({"stopped":true,"interrupt":{"type":"RUN_ERROR","message":"Run stopped by user","code":"STOPPED"}}) } else { json!({"stopped":false}) }).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    response
}
#[derive(Debug, PartialEq, Eq)]
enum Existing {
    None,
    Replay,
    Conflict,
}

/// Check both uniqueness constraints independently: a key and message id can
/// otherwise point to different existing runs, so an OR ... LIMIT 1 is unsafe.
fn existing(
    c: &rusqlite::Connection,
    owner: &str,
    conversation: &str,
    message: &str,
    key: &str,
    fingerprint: &[u8],
) -> Result<Existing, StorageError> {
    let by_key: Option<Vec<u8>> = c
        .query_row(
            "SELECT fingerprint FROM port_runs WHERE owner_id=?1 AND request_key=?2",
            params![owner, key],
            |r| r.get(0),
        )
        .optional()?;
    let by_message: Option<Vec<u8>> = c.query_row("SELECT fingerprint FROM port_runs WHERE conversation_id=?1 AND user_message_id=?2 AND owner_id=?3",params![conversation,message,owner],|r|r.get(0)).optional()?;
    if by_key.as_ref().is_some_and(|v| v.as_slice() != fingerprint)
        || by_message
            .as_ref()
            .is_some_and(|v| v.as_slice() != fingerprint)
    {
        return Ok(Existing::Conflict);
    }
    if by_key.is_some() || by_message.is_some() {
        Ok(Existing::Replay)
    } else {
        Ok(Existing::None)
    }
}

/// A retry of an already accepted request does not require a model slot.
async fn retry_while_busy(
    s: &RunState,
    owner: &str,
    org: &str,
    conversation: &str,
    bot: &str,
    message: &str,
    key: &str,
    fingerprint: &[u8],
) -> Response {
    let Ok(permit) = s.auth.db_jobs.clone().try_acquire_owned() else {
        return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable");
    };
    let db = s.auth.db.clone();
    let owner = owner.to_owned();
    let org = org.to_owned();
    let conversation = conversation.to_owned();
    let bot = bot.to_owned();
    let lookup_message = message.to_owned();
    let key = key.to_owned();
    let fingerprint = fingerprint.to_vec();
    let result=tokio::task::spawn_blocking(move || { let _permit=permit; db.try_with_connection(|c| {
        let bots: Option<String> = c.query_row("SELECT c.bot_ids_json FROM port_conversations c JOIN port_bots b ON b.id=?1 AND b.organization_id=c.organization_id AND b.owner_id=c.owner_id WHERE c.id=?2 AND c.organization_id=?3 AND c.owner_id=?4 AND c.deleted=0",params![bot,conversation,org,owner],|r|r.get(0)).optional()?;
        let Some(bots)=bots else { return Ok(None); };
        let bots:Vec<String>=serde_json::from_str(&bots).map_err(|_|StorageError::InvalidDatabase("invalid bot list"))?;
        if !bots.contains(&bot) { return Ok(None); }
        Ok(Some(existing(c,&owner,&conversation,&lookup_message,&key,&fingerprint)?))
    })}).await;
    match result {
        Ok(Ok(Some(Existing::Replay))) => accepted(message, false),
        Ok(Ok(Some(Existing::Conflict))) => {
            problem(StatusCode::CONFLICT, "Message or idempotency key conflict")
        }
        Ok(Ok(None)) => problem(StatusCode::NOT_FOUND, "Conversation or bot not found"),
        _ => problem(StatusCode::SERVICE_UNAVAILABLE, "Model is busy"),
    }
}
pub(crate) async fn send(
    State(s): State<RunState>,
    Path((org, conversation)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> Response {
    send_with_run_id(
        State(s),
        Path((org, conversation)),
        headers,
        Json(input),
        None,
    )
    .await
}

/// Internal SDK entry point. Its run id is treated as untrusted input and is
/// included in the fingerprint so a retry cannot silently change run identity.
pub(crate) async fn send_with_run_id(
    State(s): State<RunState>,
    Path((org, conversation)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<Input>,
    requested_run_id: Option<String>,
) -> Response {
    if requested_run_id.as_ref().is_some_and(|id| {
        id.is_empty()
            || id.len() > 160
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    }) {
        return problem(StatusCode::BAD_REQUEST, "Invalid run id");
    }
    if !s.auth.valid_origin(&headers).await {
        return problem(StatusCode::FORBIDDEN, "Forbidden");
    }
    let actor = match local_auth::identity(&s.auth, &headers).await {
        Ok(Some(i)) if i.organization == org || i.slug == org => i,
        Ok(Some(_)) => return problem(StatusCode::NOT_FOUND, "Organization not found"),
        Ok(None) => return problem(StatusCode::UNAUTHORIZED, "Sign in required"),
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    };
    if let Some(id) = input.bot_id.as_deref() {
        if id.is_empty() || id.len() > 200 {
            return problem(StatusCode::BAD_REQUEST, "Bot is required");
        }
    }
    let bot_override = input.bot_id.clone();
    let attachment_ids: Vec<String> = input
        .attachment_ids
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.trim().is_empty() && s.len() <= 160 && !s.chars().any(char::is_control))
        .collect();
    if attachment_ids.len() > 8 {
        return problem(StatusCode::BAD_REQUEST, "Too many attachments");
    }
    if input.id.is_empty()
        || input.id.chars().count() > 160
        || input.id.chars().any(char::is_control)
        || (input.text.trim().is_empty() && attachment_ids.is_empty())
        || input.text.chars().count() > 16000
    {
        return problem(StatusCode::BAD_REQUEST, "Invalid message");
    }
    let stored_text = if input.text.trim().is_empty() && !attachment_ids.is_empty() {
        "Shared attachment(s)".to_owned()
    } else {
        input.text.clone()
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
    let mut fingerprint_input = json!({
        "id": input.id,
        "text": input.text,
        "botId": bot_override,
        "conversation": conversation,
        "attachmentIds": attachment_ids,
    });
    if let Some(id) = &requested_run_id {
        fingerprint_input["runId"] = Value::String(id.clone());
    }
    let fingerprint = Sha256::digest(fingerprint_input.to_string().as_bytes()).to_vec();
    let permit = match s.capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            if let Some(ref b) = bot_override {
                return retry_while_busy(
                    &s,
                    &actor.id,
                    &actor.organization,
                    &conversation,
                    b,
                    &input.id,
                    &key,
                    &fingerprint,
                )
                .await;
            }
            return problem(StatusCode::CONFLICT, "Conversation already running");
        }
    };
    let registration = s.registration.clone();
    let registration_guard = registration.lock().await;
    let db_permit = match s.auth.db_jobs.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    };
    let db = s.auth.db.clone();
    let owner = actor.id.clone();
    let org_id = actor.organization.clone();
    let conversation_id = conversation.clone();
    let owner_run = owner.clone();
    let org_run = org_id.clone();
    let message_id = input.id.clone();
    let text = stored_text;
    let attach_ids = attachment_ids.clone();
    let vc_for_attach = s.virtual_computer.clone();
    let result=tokio::task::spawn_blocking(move||{let _p=db_permit;db.try_with_connection(|c|{
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let conv:Option<(String,String)>=tx.query_row("SELECT thread_id,bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",params![conversation_id,org_id,owner],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((thread,bot_json))=conv else{return Ok(json!({"result":"missing"}))};
        let bots:Vec<String>=serde_json::from_str(&bot_json).map_err(|_|StorageError::InvalidDatabase("invalid bot list"))?;
        if bots.is_empty(){return Ok(json!({"result":"missing"}))}
        let mut bot_names: HashMap<String, String> = HashMap::new();
        for b in &bots {
            if let Ok(Some(name)) = tx.query_row(
                "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![b, org_id, owner],
                |r| r.get::<_, String>(0),
            ).optional() {
                bot_names.insert(b.clone(), name);
            }
        }
        let turn_bots:Vec<String>=match &bot_override {
            Some(b)=>{if !bots.contains(b){return Ok(json!({"result":"missing"}))} vec![b.clone()]}
            None=>select_group_turn_bots(&bots, &bot_names, &text),
        };
        let bot_id=turn_bots[0].clone();
        let instructions:Option<String>=tx.query_row("SELECT role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",params![bot_id,org_id,owner],|r|r.get(0)).optional()?;
        let Some(instructions)=instructions else{return Ok(json!({"result":"missing"}))};
        match existing(&tx,&owner,&conversation_id,&message_id,&key,&fingerprint)? { Existing::Replay=>return Ok(json!({"result":"replay"})), Existing::Conflict=>return Ok(json!({"result":"conflict"})), Existing::None=>{} }
        let gap:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM port_metadata WHERE key=?1)",params![format!("conversation_replay_gap:{conversation_id}")],|r|r.get(0))?;
        if gap{return Ok(json!({"result":"gap"}))}
        let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM port_runs WHERE conversation_id=?1 AND status='running')",params![conversation_id],|r|r.get(0))?;
        if active{return Ok(json!({"result":"busy"}))}
        let run=match requested_run_id {Some(id)=>{let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM port_runs WHERE id=?1)",params![id],|r|r.get(0))?;if exists{return Ok(json!({"result":"conflict"}))}id},None=>random_id()?};let reply=format!("assistant_{}",random_id()?);let timestamp=now()?;
        tx.execute("INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'person',?3,NULL,?4,'completed',?5)",params![message_id,conversation_id,owner,text,timestamp])?;
        let mut attached_files: Vec<(String, String, i64, Vec<u8>, Option<String>)> = Vec::new();
        for att_id in &attach_ids {
            let row: Option<(String, String, i64, Vec<u8>, Option<String>)> = tx.query_row(
                "SELECT filename, mime_type, size_bytes, data, extracted_text FROM port_attachments WHERE id=?1 AND conversation_id=?2 AND owner_id=?3 AND (message_id IS NULL OR message_id=?4)",
                params![att_id, conversation_id, owner, message_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            ).optional()?;
            let Some(meta) = row else {
                return Ok(json!({"result":"invalid_attachment"}));
            };
            tx.execute(
                "UPDATE port_attachments SET message_id=?1, attached_at=?2 WHERE id=?3 AND conversation_id=?4",
                params![message_id, timestamp, att_id, conversation_id],
            )?;
            attached_files.push(meta);
        }
        tx.execute("INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','running',?5)",params![reply,conversation_id,owner,bot_id,timestamp])?;
        tx.execute("INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'running',?9)",params![run,conversation_id,owner,bot_id,message_id,reply,key,fingerprint,timestamp])?;
        tx.execute("UPDATE port_conversations SET last_message_at=?2 WHERE id=?1",params![conversation_id,timestamp])?;
        let mut st=tx.prepare("SELECT id,role,bot_id,text FROM port_conversation_messages WHERE conversation_id=?1 AND status='completed' AND (role='person' OR (role='bot' AND bot_id=?2 AND text!='')) ORDER BY rowid DESC LIMIT 8")?;
        let mut history=st.query_map(params![conversation_id,bot_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,String>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;drop(st);history.reverse();
        let sys = if bots.len() > 1 {
            let self_name = bot_names.get(&bot_id).map(String::as_str).unwrap_or(&bot_id);
            let team = bots.iter().map(|b| bot_names.get(b).map(String::as_str).unwrap_or(b.as_str())).collect::<Vec<_>>().join(", ");
            format!("You are {self_name} in a group conversation with: {team}.\n{instructions}")
        } else {
            instructions
        };
        let mut messages=vec![json!({"role":"system","content":sys})];
        let history_len = history.len();
        for (idx, (mid, role, _bid, mut msg_text)) in history.into_iter().enumerate() {
            let is_recent = idx + 2 >= history_len;
            if !is_recent {
                msg_text = clip_chars(&msg_text, 900);
            }
            if role == "person" {
                let mut att_st = tx.prepare("SELECT filename, mime_type, size_bytes, extracted_text FROM port_attachments WHERE conversation_id=?1 AND message_id=?2 ORDER BY rowid ASC")?;
                let atts = att_st.query_map(params![conversation_id, mid], |r| {
                    Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)?, r.get::<_,Option<String>>(3)?))
                })?.collect::<rusqlite::Result<Vec<_>>>()?;
                drop(att_st);
                if !atts.is_empty() {
                    let max_att = if is_recent { 1800 } else { 400 };
                    let mut note = String::new();
                    for (fname, mime, sz, ext) in atts {
                        note.push_str(&format!("\n[Attached file: uploads/{fname} ({mime}, {sz} bytes)]"));
                        if let Some(t) = ext.filter(|s| !s.trim().is_empty()) {
                            let clipped = clip_chars(t.trim(), max_att);
                            note.push_str(&format!("\n--- Content of {fname} ---\n{clipped}\n--- End of {fname} ---"));
                        }
                    }
                    msg_text.push_str(&note);
                }
            }
            messages.push(json!({"role":if role=="person"{"user"}else{"assistant"},"content":msg_text}));
        }
        tx.commit()?;
        Ok(json!({"result":"started","thread":thread,"run":run,"reply":reply,"bot":bot_id,"extraBots":turn_bots[1..],"messages":messages,"stagedFiles": attached_files.into_iter().map(|(name, _, _, data, _)| (name, data)).collect::<Vec<_>>()}))
    })}).await;
    let data = match result {
        Ok(Ok(v)) => v,
        _ => return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    };
    match data["result"].as_str() {
        Some("missing") => return problem(StatusCode::NOT_FOUND, "Conversation or bot not found"),
        Some("invalid_attachment") => {
            return problem(StatusCode::BAD_REQUEST, "One or more attachments could not be found")
        }
        Some("conflict") => {
            return problem(StatusCode::CONFLICT, "Message or idempotency key conflict")
        }
        Some("busy") => return problem(StatusCode::CONFLICT, "Conversation already running"),
        Some("gap") => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Conversation event history is incomplete",
            )
        }
        Some("replay") => return accepted(&input.id, false),
        Some("started") => {}
        _ => return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    };
    if let (Some(vc_state), Some(files)) = (
        vc_for_attach.as_ref(),
        data.get("stagedFiles").and_then(Value::as_array),
    ) {
        if !files.is_empty() {
            let mut target_bots = vec![data["bot"].as_str().unwrap_or("").to_owned()];
            if let Some(extra) = data.get("extraBots").and_then(Value::as_array) {
                for b in extra {
                    if let Some(s) = b.as_str() {
                        target_bots.push(s.to_owned());
                    }
                }
            }
            for item in files {
                if let (Some(fname), Some(bytes_val)) = (item.get(0).and_then(Value::as_str), item.get(1).and_then(Value::as_array)) {
                    let bytes: Vec<u8> = bytes_val.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
                    let safe_name: String = fname
                        .chars()
                        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
                        .collect();
                    if !safe_name.is_empty() {
                        for bid in &target_bots {
                            vc_state.stage_uploaded_file(&org_run, &owner_run, bid, &safe_name, &bytes);
                        }
                    }
                }
            }
        }
    }
    let thread = data["thread"].as_str().unwrap().to_owned();
    let run = data["run"].as_str().unwrap().to_owned();
    let reply = data["reply"].as_str().unwrap().to_owned();
    let bot_run = data["bot"].as_str().unwrap().to_owned();
    let extra_bots: Vec<String> = data["extraBots"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let model = s.model.clone();
    let model_id = s.model_id.clone();
    let request = json!({"model":model_id.clone(),"messages":data["messages"],"n":1});
    let cancellation = CancellationToken::new();
    let active = s.active.clone();
    let vc = s.virtual_computer.clone();
    active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(run.clone(), cancellation.clone());
    drop(registration_guard);
    tokio::spawn(async move {
        let _permit = permit;
        execute(
            s.auth.clone(),
            model.clone(),
            vc.clone(),
            request,
            org_run.clone(),
            owner_run.clone(),
            bot_run,
            conversation.clone(),
            thread.clone(),
            run.clone(),
            reply,
            cancellation,
        )
        .await;
        active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&run);
        for next_bot in extra_bots {
            execute_followup_group_bot(
                &s.auth,
                &model,
                &model_id,
                &vc,
                &active,
                &org_run,
                &owner_run,
                &next_bot,
                &conversation,
                &thread,
            )
            .await;
        }
    });
    accepted(&input.id, true)
}
async fn execute(
    auth: AuthState,
    model: ModelClient,
    vc: Option<virtual_computer::VirtualComputerState>,
    request: Value,
    org: String,
    owner: String,
    bot: String,
    conversation: String,
    thread: String,
    run: String,
    reply: String,
    external_cancel: CancellationToken,
) {
    let cancel = external_cancel.child_token();
    let mut current_request = request;
    let configured_model = current_request
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_owned();
    let choice_db = auth.db.clone();
    let choice_key = format!("model_choice:{org}:{owner}:{conversation}");
    if let Ok(Ok(Some(raw_choice))) = tokio::task::spawn_blocking(move || {
        choice_db.try_with_connection(|c| {
            c.query_row(
                "SELECT value FROM port_compat_kv WHERE scope=?1",
                params![choice_key],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(StorageError::from)
        })
    })
    .await
    {
        if let Ok(parsed) = serde_json::from_str::<Value>(&raw_choice) {
            if let Some(m) = parsed
                .get("model")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "auto")
            {
                current_request["model"] = Value::String(m.to_owned());
            }
            if let Some(eff) = parsed
                .get("effort")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| matches!(*s, "off" | "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"))
            {
                current_request["reasoning_effort"] = Value::String(eff.to_owned());
                let hint = if eff == "off" || eff == "none" {
                    "Thinking mode: Off. Answer directly and concisely."
                } else {
                    match eff {
                        "minimal" | "low" => "Thinking mode: Low. Reason briefly before answering.",
                        "medium" => "Thinking mode: Medium. Reason carefully before answering.",
                        _ => "Thinking mode: High. Analyze thoroughly step-by-step and double-check details before answering.",
                    }
                };
                if let Some(msgs) = current_request.get_mut("messages").and_then(Value::as_array_mut) {
                    if let Some(sys) = msgs.first_mut().filter(|m| m.get("role").and_then(Value::as_str) == Some("system")) {
                        if let Some(prev) = sys.get("content").and_then(Value::as_str) {
                            sys["content"] = Value::String(format!("{prev}\n{hint}"));
                        }
                    }
                }
            }
        }
    }
    let selected_model = current_request
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if configured_model == "auto" || selected_model.is_empty() || selected_model == "auto" {
        if let Err(reason) = resolve_active_model(&model, &mut current_request, &cancel).await {
            finalize_run(
                &auth,
                &conversation,
                &thread,
                &run,
                &reply,
                "",
                true,
                &external_cancel,
                None,
                Some(&reason),
            )
            .await;
            return;
        }
    }

    if vc.is_none() {
        let producer_cancel = cancel.clone();
        let (tx, mut rx) = mpsc::channel(16);
        let t = thread.clone();
        let r = run.clone();
        let m = reply.clone();
        let req_clone = current_request.clone();
        let task = tokio::spawn(async move {
            run_engine::stream_text(model, req_clone, &t, &r, &m, tx, producer_cancel).await
        });
        let mut answer = String::new();
        let mut failed = false;
        let mut failure_detail: Option<String> = None;
        let mut terminal = None;
        while let Some(event) = rx.recv().await {
            if event.get("type").and_then(Value::as_str) == Some("RUN_FINISHED") {
                terminal = Some(event);
                continue;
            }
            if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                if answer.len().saturating_add(delta.len()) > 1024 * 1024 {
                    failed = true;
                    cancel.cancel();
                    break;
                }
                answer.push_str(delta);
            }
            if !append_event(&auth, &conversation, event, &cancel).await {
                failed = true;
                cancel.cancel();
                break;
            }
        }
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                failed = true;
                failure_detail = Some(e.to_string());
            }
            Err(_) => {
                failed = true;
            }
        }
        if external_cancel.is_cancelled() || terminal.is_none() {
            failed = true;
        }
        finalize_run(
            &auth,
            &conversation,
            &thread,
            &run,
            &reply,
            &answer,
            failed,
            &external_cancel,
            terminal,
            failure_detail.as_deref(),
        )
        .await;
        return;
    }

    let vc = vc.unwrap();
    let mut total_answer = String::new();
    let mut failed = false;
    let mut terminal: Option<Value> = None;
    let mut failure_detail: Option<String> = None;
    if !append_event(
        &auth,
        &conversation,
        json!({"type":"RUN_STARTED","threadId":thread,"runId":run}),
        &cancel,
    )
    .await
    {
        failed = true;
    }
    current_request["tools"] = tools_schema();
    if !failed {
        (failed, terminal, failure_detail) = execute_tool_rounds(
            &auth,
            &model,
            &vc,
            &mut current_request,
            &org,
            &owner,
            &bot,
            &conversation,
            &thread,
            &run,
            &reply,
            &cancel,
            &mut total_answer,
            0,
        )
        .await;
    }
    if external_cancel.is_cancelled() || terminal.is_none() {
        failed = true;
    }
    finalize_run(
        &auth,
        &conversation,
        &thread,
        &run,
        &reply,
        &total_answer,
        failed,
        &external_cancel,
        terminal,
        failure_detail.as_deref(),
    )
    .await;
}

pub(crate) fn clip_chars(text: &str, max_chars: usize) -> String {
    let mut iter = text.char_indices();
    match iter.nth(max_chars) {
        Some((idx, _)) => format!("{}...", &text[..idx]),
        None => text.to_owned(),
    }
}

pub(crate) async fn resolve_active_model(
    client: &ModelClient,
    req: &mut Value,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let models = client
        .models(cancel)
        .await
        .map_err(|e| format!("PS5LM model server unreachable: {e}"))?;
    let ids: Vec<String> = models
        .get("data")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(Value::as_str))
                .map(str::trim)
                .filter(|id| !id.is_empty() && id.len() <= 200 && !id.chars().any(char::is_control))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let Some(first) = ids.first() else {
        return Err("No model is currently loaded in PS5LM. Load a model in PS5LM first.".to_owned());
    };
    let current = req
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if current.is_empty() || current == "auto" || !ids.iter().any(|id| id == current) {
        req["model"] = Value::String(first.clone());
    }
    Ok(())
}

pub(crate) fn tools_schema() -> Value {
    json!([
        {"type":"function","function":{"name":"computer_read_file","description":"Read workspace text file","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}},
        {"type":"function","function":{"name":"computer_list_files","description":"List workspace directory files","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}},
        {"type":"function","function":{"name":"computer_write_file","description":"Write workspace text file","parameters":{"type":"object","properties":{"path":{"type":"string"},"contents":{"type":"string"},"append":{"type":"boolean"}},"required":["path","contents"]}}},
        {"type":"function","function":{"name":"computer_run_command","description":"Run virtual workspace shell command","parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}},
        {"type":"function","function":{"name":"computer_web_fetch","description":"Fetch public HTTP/HTTPS web page to Virtual Computer","parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}
    ])
}

#[allow(clippy::too_many_arguments)]
async fn execute_tool_rounds(
    auth: &AuthState,
    model: &ModelClient,
    vc: &virtual_computer::VirtualComputerState,
    current_request: &mut Value,
    org: &str,
    owner: &str,
    bot: &str,
    conversation: &str,
    thread: &str,
    run: &str,
    reply: &str,
    cancel: &CancellationToken,
    total_answer: &mut String,
    start_round: usize,
) -> (bool, Option<Value>, Option<String>) {
    let mut failed = false;
    let mut terminal: Option<Value> = None;
    let mut failure_detail: Option<String> = None;
    for round in start_round..4usize {
        if cancel.is_cancelled() {
            failed = true;
            break;
        }
        let round_msg_id = if round == 0 {
            reply.to_owned()
        } else {
            format!("{reply}_{round}")
        };
        let (tx, mut rx) = mpsc::channel(32);
        let producer_cancel = cancel.clone();
        let req_clone = current_request.clone();
        let model_clone = model.clone();
        let t = thread.to_owned();
        let r = run.to_owned();
        let m = round_msg_id.clone();
        let task = tokio::spawn(async move {
            run_engine::stream_turn(model_clone, req_clone, &t, &r, &m, false, tx, producer_cancel).await
        });
        let mut stream_deltas = String::new();
        while let Some(event) = rx.recv().await {
            if event.get("type").and_then(Value::as_str) == Some("TEXT_MESSAGE_CONTENT") {
                if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                    if total_answer.len().saturating_add(stream_deltas.len()).saturating_add(delta.len())
                        > 1024 * 1024
                    {
                        failed = true;
                        cancel.cancel();
                        break;
                    }
                    stream_deltas.push_str(delta);
                }
            }
            if !append_event(auth, conversation, event, cancel).await {
                failed = true;
                cancel.cancel();
                break;
            }
        }
        if !stream_deltas.is_empty() {
            if !total_answer.is_empty() {
                total_answer.push('\n');
            }
            total_answer.push_str(&stream_deltas);
        }
        let turn = match task.await {
            Ok(Ok(turn)) => turn,
            Ok(Err(e)) => {
                failed = true;
                failure_detail = Some(e.to_string());
                break;
            }
            Err(_) => {
                failed = true;
                break;
            }
        };
        if turn.tool_calls.is_empty() {
            terminal = Some(json!({"type":"RUN_FINISHED","threadId":thread,"runId":run}));
            break;
        }

        let assistant_tool_calls: Vec<Value> = turn
            .tool_calls
            .iter()
            .map(|tc| json!({"id":tc.id,"type":"function","function":{"name":tc.name,"arguments":tc.arguments_json}}))
            .collect();
        if let Some(arr) = current_request.get_mut("messages").and_then(Value::as_array_mut) {
            arr.push(json!({
                "role": "assistant",
                "content": if turn.assistant_text.is_empty() { Value::Null } else { Value::String(turn.assistant_text.clone()) },
                "tool_calls": assistant_tool_calls
            }));
        }

        let mut interrupted = false;
        for tc in &turn.tool_calls {
            let args: Value = match serde_json::from_str::<Value>(&tc.arguments_json) {
                Ok(v) if v.is_object() => v,
                _ => json!({}),
            };
            let effect = match tc.name.as_str() {
                "computer_write_file" | "computer_run_command" => "write",
                _ => "read",
            };
            let scope = args
                .get("path")
                .or_else(|| args.get("url"))
                .or_else(|| args.get("command"))
                .and_then(Value::as_str)
                .unwrap_or("*");
            let eval_res = {
                let db = auth.db.clone();
                let org_c = org.to_owned();
                let own_c = owner.to_owned();
                let bot_c = bot.to_owned();
                let conv_c = conversation.to_owned();
                let name_c = tc.name.clone();
                let eff_c = effect.to_owned();
                let scope_c = scope.to_owned();
                tokio::task::spawn_blocking(move || {
                    db.try_with_connection(|c| {
                        approvals_api::evaluate_action(
                            c,
                            &approvals_api::ActionEvalRequest {
                                organization_id: &org_c,
                                actor_id: &own_c,
                                bot_id: &bot_c,
                                conversation_id: &conv_c,
                                tool_ref: &name_c,
                                effect: &eff_c,
                                scope: &scope_c,
                                user_explicitly_requested: false,
                                boundary_context: None,
                            },
                        )
                        .map_err(|_| StorageError::InvalidDatabase("policy evaluation error"))
                    })
                })
                .await
            };
            let outcome = match eval_res {
                Ok(Ok(o)) => o,
                _ => {
                    failed = true;
                    break;
                }
            };
            match outcome.decision {
                approvals_api::EvaluationDecision::Allow => {
                    let exec_res = vc
                        .execute_tool_for_owner(org, owner, bot, &tc.name, args.clone())
                        .await;
                    let content_str = match exec_res {
                        Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".into()),
                        Err(err) => json!({"error": err}).to_string(),
                    };
                    let res_msg_id = format!("tool_{}", tc.id);
                    if let Ok(ev) = run_engine::ag_ui_tool_result(&res_msg_id, &tc.id, &content_str) {
                        if !append_event(auth, conversation, ev, cancel).await {
                            failed = true;
                            break;
                        }
                    }
                    let llm_content = clip_chars(&content_str, 3500);
                    if let Some(arr) = current_request.get_mut("messages").and_then(Value::as_array_mut) {
                        arr.push(json!({"role":"tool","tool_call_id":tc.id,"content":llm_content}));
                    }
                }
                approvals_api::EvaluationDecision::Ask | approvals_api::EvaluationDecision::HandOff => {
                    let policy_json = outcome.to_policy_json();
                    let db = auth.db.clone();
                    let org_c = org.to_owned();
                    let own_c = owner.to_owned();
                    let bot_c = bot.to_owned();
                    let conv_c = conversation.to_owned();
                    let run_c = run.to_owned();
                    let thread_c = thread.to_owned();
                    let tc_id = tc.id.clone();
                    let tc_name = tc.name.clone();
                    let eff_c = effect.to_owned();
                    let scope_c = scope.to_owned();
                    let args_c = args.clone();
                    let pending = tokio::task::spawn_blocking(move || {
                        db.try_with_connection(|c| {
                            approvals_api::create_pending_approval(
                                c,
                                &approvals_api::CreatePendingApprovalRequest {
                                    organization_id: &org_c,
                                    actor_id: &own_c,
                                    bot_id: &bot_c,
                                    conversation_id: &conv_c,
                                    run_id: &run_c,
                                    tool_call_id: Some(&tc_id),
                                    tool_ref: &tc_name,
                                    effect: &eff_c,
                                    scope: &scope_c,
                                    thread_id: &thread_c,
                                    args: &args_c,
                                    target: None,
                                    account: None,
                                    policy: Some(&policy_json),
                                    ttl_seconds: None,
                                },
                            )
                            .map_err(|_| StorageError::InvalidDatabase("approval creation failed"))
                        })
                    })
                    .await;
                    if let Ok(Ok(app_rec)) = pending {
                        if let Ok(fin) = run_engine::ag_ui_interrupt_finished(
                            thread,
                            run,
                            &app_rec.id,
                            &tc.id,
                            Some(&outcome.reason),
                            json!({"approvalId": app_rec.id, "toolCallId": tc.id, "toolName": tc.name}),
                        ) {
                            terminal = Some(fin);
                        }
                    } else {
                        failed = true;
                    }
                    interrupted = true;
                    break;
                }
                approvals_api::EvaluationDecision::Deny => {
                    let db = auth.db.clone();
                    let org_c = org.to_owned();
                    let own_c = owner.to_owned();
                    let bot_c = bot.to_owned();
                    let conv_c = conversation.to_owned();
                    let att_id = format!("deny_{}", tc.id);
                    let action_val = json!({"tool":tc.name,"effect":effect,"scope":scope,"args":args});
                    let _ = tokio::task::spawn_blocking(move || {
                        db.try_with_connection(|c| {
                            let _ = governance::record_refusal(
                                c,
                                &governance::Action {
                                    organization_id: &org_c,
                                    actor_id: &own_c,
                                    bot_id: &bot_c,
                                    conversation_id: &conv_c,
                                    attempt_id: &att_id,
                                    canonical_action: &action_val,
                                },
                            );
                            Ok(())
                        })
                    })
                    .await;
                    let content_str = json!({"denied":true,"reason":outcome.reason}).to_string();
                    let res_msg_id = format!("tool_{}", tc.id);
                    if let Ok(ev) = run_engine::ag_ui_tool_result(&res_msg_id, &tc.id, &content_str) {
                        if !append_event(auth, conversation, ev, cancel).await {
                            failed = true;
                            break;
                        }
                    }
                    let llm_content = clip_chars(&content_str, 3500);
                    if let Some(arr) = current_request.get_mut("messages").and_then(Value::as_array_mut) {
                        arr.push(json!({"role":"tool","tool_call_id":tc.id,"content":llm_content}));
                    }
                }
            }
        }
        if failed || interrupted {
            break;
        }
    }
    (failed, terminal, failure_detail)
}

#[allow(clippy::too_many_arguments)]
async fn execute_followup_group_bot(
    auth: &AuthState,
    model: &ModelClient,
    model_id: &str,
    vc: &Option<virtual_computer::VirtualComputerState>,
    active: &Arc<Mutex<HashMap<String, CancellationToken>>>,
    org: &str,
    owner: &str,
    bot_id: &str,
    conversation: &str,
    thread: &str,
) {
    let db = auth.db.clone();
    let org_c = org.to_owned();
    let own_c = owner.to_owned();
    let bot_c = bot_id.to_owned();
    let conv_c = conversation.to_owned();
    let setup = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let instructions: Option<String> = tx
                .query_row(
                    "SELECT role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                    params![bot_c, org_c, own_c],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(instructions) = instructions else {
                return Ok(None);
            };
            let run = random_id()?;
            let reply = format!("assistant_{}", random_id()?);
            let user_msg_id = format!("group_{run}");
            let req_key = format!("group_{run}");
            let timestamp = now()?;
            tx.execute(
                "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','running',?5)",
                params![reply, conv_c, own_c, bot_c, timestamp],
            )?;
            tx.execute(
                "INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'running',?9)",
                params![run, conv_c, own_c, bot_c, user_msg_id, reply, req_key, vec![0u8; 32], timestamp],
            )?;
            let mut st = tx.prepare("SELECT id,role,bot_id,text FROM port_conversation_messages WHERE conversation_id=?1 AND status='completed' AND (role='person' OR text!='') ORDER BY rowid DESC LIMIT 8")?;
            let mut history = st
                .query_map(params![conv_c], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(st);
            history.reverse();
            let bot_name: String = tx
                .query_row(
                    "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                    params![bot_c, org_c, own_c],
                    |r| r.get(0),
                )
                .unwrap_or_else(|_| bot_c.clone());
            let mut transcript = String::new();
            let history_len = history.len();
            for (idx, (mid, role, bid, text)) in history.into_iter().enumerate() {
                let is_recent = idx + 2 >= history_len;
                let spoken = if is_recent { text } else { clip_chars(&text, 700) };
                if role == "person" {
                    transcript.push_str(&format!("User: {spoken}\n"));
                    if let Ok(mut att_st) = tx.prepare("SELECT filename, mime_type, size_bytes, extracted_text FROM port_attachments WHERE conversation_id=?1 AND message_id=?2 ORDER BY rowid ASC") {
                        if let Ok(rows) = att_st.query_map(params![conv_c, mid], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)?, r.get::<_,Option<String>>(3)?))) {
                            for att in rows.flatten() {
                                transcript.push_str(&format!("[Attached file: uploads/{} ({}, {} bytes)]\n", att.0, att.1, att.2));
                                if let Some(ext) = att.3.filter(|s| !s.trim().is_empty()) {
                                    let clipped = clip_chars(ext.trim(), if is_recent { 1200 } else { 300 });
                                    transcript.push_str(&format!("{clipped}\n"));
                                }
                            }
                        }
                    }
                } else {
                    let speaker = bid
                        .as_deref()
                        .and_then(|id| {
                            tx.query_row(
                                "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2",
                                params![id, org_c],
                                |r| r.get::<_, String>(0),
                            )
                            .ok()
                        })
                        .unwrap_or_else(|| "Teammate".to_owned());
                    transcript.push_str(&format!("[{speaker}]: {spoken}\n"));
                }
            }
            let messages = vec![
                json!({
                    "role": "system",
                    "content": format!(
                        "You are {bot_name} participating in a multi-bot group conversation.\n{instructions}\n\nIMPORTANT GROUP RULE: Only reply if your specialty/role genuinely adds value or was requested. If another teammate already answered adequately or this message isn't for you, output literally [PASS] and nothing else."
                    )
                }),
                json!({
                    "role": "user",
                    "content": format!("{transcript}\nRespond as {bot_name} if relevant to your role, or reply literally with [PASS].")
                }),
            ];
            tx.commit()?;
            Ok(Some((run, reply, messages)))
        })
    })
    .await;
    let Ok(Ok(Some((run, reply, messages)))) = setup else {
        return;
    };
    let request = json!({"model": model_id, "messages": messages, "n": 1});
    let cancel = CancellationToken::new();
    active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(run.clone(), cancel.clone());
    execute(
        auth.clone(),
        model.clone(),
        vc.clone(),
        request,
        org.to_owned(),
        owner.to_owned(),
        bot_id.to_owned(),
        conversation.to_owned(),
        thread.to_owned(),
        run.clone(),
        reply,
        cancel,
    )
    .await;
    active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&run);
}

/// Resumes a paused conversation turn after the person approves or denies a pending tool call.
pub(crate) fn spawn_approval_resume(s: RunState, org: String, actor: String, approval_id: String) {
    tokio::spawn(async move {
        let Ok(Ok(permit)) = tokio::time::timeout(
            Duration::from_secs(5),
            s.capacity.clone().acquire_owned(),
        )
        .await
        else {
            return;
        };
        let _permit = permit;
        let db = s.auth.db.clone();
        let app_c = approval_id.clone();
        let org_c = org.clone();
        let act_c = actor.clone();
        let row_res = tokio::task::spawn_blocking(move || {
            db.try_with_connection(|c| {
                let row: Option<(String, String, String, Option<String>, String, String, String, String, String)> = c
                    .query_row(
                        "SELECT bot_id, conversation_id, thread_id, tool_call_id, tool_ref, effect, scope, args_json, status
                           FROM port_approvals
                          WHERE id=?1 AND organization_id=?2 AND actor_id=?3",
                        params![app_c, org_c, act_c],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)),
                    )
                    .optional()?;
                Ok(row)
            })
        })
        .await;
        let Ok(Ok(Some((bot_id, conv_id, thread_id, tc_id_opt, tool_ref, effect, scope, args_json, status)))) = row_res else {
            return;
        };
        let args: Value = serde_json::from_str(&args_json).unwrap_or_else(|_| json!({}));
        let mut exec_error: Option<String> = None;
        let was_approved = status == "approved";
        let content_str = if was_approved {
            let db_c = s.auth.db.clone();
            let app_c = approval_id.clone();
            let org_c = org.clone();
            let act_c = actor.clone();
            let bot_c = bot_id.clone();
            let conv_c = conv_id.clone();
            let tool_c = tool_ref.clone();
            let eff_c = effect.clone();
            let scope_c = scope.clone();
            let args_c = args.clone();
            let consumed = tokio::task::spawn_blocking(move || {
                db_c.try_with_connection(|c| {
                    approvals_api::consume_approved_action(
                        c,
                        &approvals_api::ConsumeApprovalRequest {
                            approval_id: &app_c,
                            organization_id: &org_c,
                            actor_id: &act_c,
                            bot_id: &bot_c,
                            conversation_id: &conv_c,
                            tool_ref: &tool_c,
                            effect: &eff_c,
                            scope: &scope_c,
                            args: &args_c,
                        },
                    )
                    .map_err(|_| StorageError::InvalidDatabase("approval consume failed"))
                })
            })
            .await;
            if !matches!(consumed, Ok(Ok(_))) {
                return;
            }
            if let Some(vc) = s.virtual_computer.as_ref() {
                match vc
                    .execute_tool_for_owner(&org, &actor, &bot_id, &tool_ref, args.clone())
                    .await
                {
                    Ok(val) => serde_json::to_string(&val).unwrap_or_else(|_| "{}".into()),
                    Err(err) => {
                        exec_error = Some(err.clone());
                        json!({"error": err}).to_string()
                    }
                }
            } else {
                let err = "Virtual computer is not enabled".to_owned();
                exec_error = Some(err.clone());
                json!({"error": err}).to_string()
            }
        } else if status == "denied" {
            json!({"denied": true, "reason": "The user denied permission for this action."}).to_string()
        } else {
            return;
        };

        let tc_id = tc_id_opt.unwrap_or_else(|| format!("tc_{approval_id}"));
        let mut prep_out: Option<(String, String, Vec<Value>)> = None;
        for attempt in 0..40 {
            let db_r = s.auth.db.clone();
            let org_c = org.clone();
            let act_c = actor.clone();
            let bot_c = bot_id.clone();
            let conv_c = conv_id.clone();
            let app_c = approval_id.clone();
            let tc_c = tc_id.clone();
            let tool_c = tool_ref.clone();
            let args_str = args_json.clone();
            let content_c = content_str.clone();
            let res = tokio::task::spawn_blocking(move || {
                db_r.try_with_connection(|c| {
                    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    let instructions: Option<String> = tx
                        .query_row(
                            "SELECT role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                            params![bot_c, org_c, act_c],
                            |r| r.get(0),
                        )
                        .optional()?;
                    let Some(instructions) = instructions else {
                        return Ok(Ok(None));
                    };
                    let active: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM port_runs WHERE conversation_id=?1 AND status='running')",
                        params![conv_c],
                        |r| r.get(0),
                    )?;
                    if active {
                        return Ok(Err(()));
                    }
                    let run = random_id()?;
                    let reply = format!("assistant_{}", random_id()?);
                    let user_msg = format!("approval_{app_c}");
                    let req_key = format!("resume_{app_c}");
                    let timestamp = now()?;
                    tx.execute(
                        "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','running',?5)",
                        params![reply, conv_c, act_c, bot_c, timestamp],
                    )?;
                    tx.execute(
                        "INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'running',?9)",
                        params![run, conv_c, act_c, bot_c, user_msg, reply, req_key, vec![0u8; 32], timestamp],
                    )?;
                    let mut st = tx.prepare("SELECT role,text FROM port_conversation_messages WHERE conversation_id=?1 AND status='completed' AND text!='' AND (role='person' OR (role='bot' AND bot_id=?2)) ORDER BY rowid DESC LIMIT 8")?;
                    let mut history = st
                        .query_map(params![conv_c, bot_c], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    drop(st);
                    history.reverse();
                    let mut messages = vec![json!({"role":"system","content":instructions})];
                    let history_len = history.len();
                    for (idx, (role, text)) in history.into_iter().enumerate() {
                        let content = if idx + 2 >= history_len { text } else { clip_chars(&text, 900) };
                        messages.push(json!({"role":if role=="person"{"user"}else{"assistant"},"content":content}));
                    }
                    messages.push(json!({
                        "role": "assistant",
                        "content": Value::Null,
                        "tool_calls": [{"id": tc_c, "type": "function", "function": {"name": tool_c, "arguments": args_str}}]
                    }));
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": tc_c,
                        "content": content_c
                    }));
                    tx.commit()?;
                    Ok(Ok(Some((run, reply, messages))))
                })
            })
            .await;
            match res {
                Ok(Ok(Ok(Some(v)))) => {
                    prep_out = Some(v);
                    break;
                }
                Ok(Ok(Err(()))) if attempt < 39 => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                _ => break,
            }
        }

        let Some((run, reply, messages)) = prep_out else {
            if was_approved {
                let db_done = s.auth.db.clone();
                let err_msg = Some("Conversation already had an active run".to_owned());
                let _ = tokio::task::spawn_blocking(move || {
                    db_done.try_with_connection(|c| {
                        let _ = approvals_api::complete_approval_execution(
                            c,
                            &approvals_api::CompleteApprovalRequest {
                                approval_id: &approval_id,
                                organization_id: &org,
                                actor_id: &actor,
                                error: err_msg.as_deref(),
                            },
                        );
                        Ok(())
                    })
                })
                .await;
            }
            return;
        };
        let cancel = CancellationToken::new();
        let child = cancel.child_token();
        s.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(run.clone(), cancel.clone());
        let mut current_request = json!({"model": s.model_id, "messages": messages, "tools": tools_schema(), "n": 1});
        let mut model_err: Option<String> = None;
        if s.model_id == "auto" {
            if let Err(reason) = resolve_active_model(&s.model, &mut current_request, &child).await {
                model_err = Some(reason);
            }
        }
        let mut total_answer = String::new();
        let mut failed = model_err.is_some()
            || !append_event(
                &s.auth,
                &conv_id,
                json!({"type":"RUN_STARTED","threadId":thread_id,"runId":run}),
                &child,
            )
            .await;
        if !failed {
            if let Ok(ev) = run_engine::ag_ui_tool_result(&format!("tool_{tc_id}"), &tc_id, &content_str) {
                if !append_event(&s.auth, &conv_id, ev, &child).await {
                    failed = true;
                }
            }
        }
        let mut terminal: Option<Value> = None;
        let mut failure_detail = model_err;
        if !failed {
            if let Some(vc) = s.virtual_computer.as_ref() {
                (failed, terminal, failure_detail) = execute_tool_rounds(
                    &s.auth,
                    &s.model,
                    vc,
                    &mut current_request,
                    &org,
                    &actor,
                    &bot_id,
                    &conv_id,
                    &thread_id,
                    &run,
                    &reply,
                    &child,
                    &mut total_answer,
                    1,
                )
                .await;
            }
        }
        if cancel.is_cancelled() || terminal.is_none() {
            failed = true;
        }
        let db_done = s.auth.db.clone();
        let err_clone = exec_error;
        let _ = tokio::task::spawn_blocking(move || {
            db_done.try_with_connection(|c| {
                if was_approved {
                    let _ = approvals_api::complete_approval_execution(
                        c,
                        &approvals_api::CompleteApprovalRequest {
                            approval_id: &approval_id,
                            organization_id: &org,
                            actor_id: &actor,
                            error: err_clone.as_deref(),
                        },
                    );
                } else if let Ok(ts) = now() {
                    let _ = c.execute(
                        "UPDATE port_approvals SET status='completed', completed_at=?1 WHERE id=?2 AND status='denied'",
                        params![ts, approval_id],
                    );
                }
                Ok(())
            })
        })
        .await;
        finalize_run(
            &s.auth,
            &conv_id,
            &thread_id,
            &run,
            &reply,
            &total_answer,
            failed,
            &cancel,
            terminal,
            failure_detail.as_deref(),
        )
        .await;
        s.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&run);
    });
}

#[allow(clippy::too_many_arguments)]
async fn finalize_run(
    auth: &AuthState,
    conversation: &str,
    thread: &str,
    run: &str,
    reply: &str,
    answer: &str,
    failed: bool,
    external_cancel: &CancellationToken,
    terminal: Option<Value>,
    failure_detail: Option<&str>,
) {
    // Persist the final transcript, run state and terminal event in one transaction.
    // Retry transient in-process lock contention for a bounded period.
    for _ in 0..40 {
        let permit = match auth.db_jobs.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let db = auth.db.clone();
        let id = conversation.to_owned();
        let run_id = run.to_owned();
        let message_id = reply.to_owned();
        let detail_owned = failure_detail
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let body = if failed && answer.trim().is_empty() {
            detail_owned.clone().unwrap_or_default()
        } else {
            answer.to_owned()
        };
        let thread_id = thread.to_owned();
        let terminal_ref = terminal.clone();
        let event = if external_cancel.is_cancelled() {
            json!({"type":"RUN_ERROR","threadId":thread_id,"runId":run_id,"message":"Run stopped by user","code":"STOPPED"})
        } else if failed {
            json!({"type":"RUN_ERROR","threadId":thread_id,"runId":run_id,"message":detail_owned.unwrap_or_else(|| "Model run failed".to_owned())})
        } else {
            terminal_ref.clone().unwrap()
        };
        let result=tokio::task::spawn_blocking(move || {
            let _permit=permit;
            db.try_with_connection(|c| {
                let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let (count,total,last):(i64,i64,i64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(bytes),0),COALESCE(MAX(sequence),0) FROM port_run_events WHERE conversation_id=?1",params![id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
                let next=last.checked_add(1).ok_or(StorageError::InvalidDatabase("event sequence overflow"))?;
                let mut event=event; event["metadata"]=json!({"cpki_event_id":next.to_string()});
                let encoded=event.to_string();
                let fits=count<4096 && encoded.len()<=64*1024 && total.saturating_add(encoded.len() as i64)<=8*1024*1024;
                let final_status=if failed || !fits {"failed"} else {"completed"};
                let is_interrupt = terminal_ref
                    .as_ref()
                    .and_then(|t| t.get("outcome"))
                    .and_then(|o| o.get("type"))
                    .and_then(Value::as_str)
                    == Some("interrupt");
                let silent_pass = final_status == "completed" && !is_interrupt && is_silent_group_pass(&body);
                if silent_pass {
                    tx.execute("DELETE FROM port_conversation_messages WHERE conversation_id=?1 AND id=?2", params![id, message_id])?;
                } else {
                    tx.execute("UPDATE port_conversation_messages SET text=?3,status=?4 WHERE conversation_id=?1 AND id=?2",params![id,message_id,body,final_status])?;
                }
                tx.execute("UPDATE port_runs SET status=?2 WHERE id=?1",params![run_id,final_status])?;
                let notify_meta: Option<(String, String, Option<String>, String)> = if final_status == "completed" && !silent_pass && !body.trim().is_empty() {
                    let ts = crate::runs::now().unwrap_or(0);
                    tx.execute("UPDATE port_conversations SET last_message_at=MAX(COALESCE(last_message_at,0),?2) WHERE id=?1", params![id, ts])?;
                    tx.query_row(
                        "SELECT c.organization_id, c.owner_id, m.bot_id, strftime('%Y-%m-%dT%H:%M:%SZ', ?3, 'unixepoch') FROM port_conversations c LEFT JOIN port_conversation_messages m ON m.id=?2 WHERE c.id=?1",
                        params![id, message_id, ts],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    ).optional()?
                } else {
                    None
                };
                if fits { tx.execute("INSERT INTO port_run_events(conversation_id,sequence,event_json,bytes) VALUES(?1,?2,?3,?4)",params![id,next,encoded,encoded.len() as i64])?; }
                else { tx.execute("INSERT INTO port_metadata(key,value) VALUES(?1,'terminal event missing because journal is full') ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![format!("conversation_replay_gap:{id}")])?; }
                tx.commit()?; Ok(notify_meta)
            })
        }).await;
        match result {
            Ok(Ok(notify_meta)) => {
                crate::event_journal::notify_journal_change();
                if let Some((org_id, owner_id, bot_id, iso)) = notify_meta {
                    let first_line = answer.lines().next().unwrap_or("").trim().to_owned();
                    let summary_text = answer.split_whitespace().collect::<Vec<_>>().join(" ");
                    crate::realtime::notify_channel_activity(
                        &org_id,
                        &owner_id,
                        json!({
                            "channelId": conversation,
                            "lastMessage": summary_text,
                            "lastMessageAt": iso,
                            "lastMessageAgentId": bot_id,
                            "firstLine": first_line,
                        }),
                    );
                }
                return;
            }
            Ok(Err(StorageError::Busy)) => tokio::time::sleep(Duration::from_millis(50)).await,
            _ => {
                let _ = std::io::Write::write_all(
                    &mut std::io::stderr(),
                    b"Could not finalize model run; it will be marked failed on restart\n",
                );
                return;
            }
        }
    }
    let _ = std::io::Write::write_all(
        &mut std::io::stderr(),
        b"Could not finalize model run because storage remained busy; it will be marked failed on restart\n",
    );
}

async fn append_event(
    auth: &AuthState,
    conversation: &str,
    event: Value,
    cancel: &CancellationToken,
) -> bool {
    for _ in 0..40 {
        if cancel.is_cancelled() {
            return false;
        }
        let permit = match auth.db_jobs.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let db = auth.db.clone();
        let conversation = conversation.to_owned();
        let event = event.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            event_journal::append(&db, &conversation, event)
        })
        .await;
        match result {
            Ok(Ok(_)) => return true,
            Ok(Err(event_journal::JournalError::Storage(StorageError::Busy))) => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bots, conversations, local_auth, storage::Storage};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    #[test]
    fn idempotency_checks_both_existing_keys_and_message_ids() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE port_runs(owner_id TEXT, request_key TEXT, conversation_id TEXT, user_message_id TEXT, fingerprint BLOB); INSERT INTO port_runs VALUES('u','key-a','c','id-a',x'01'); INSERT INTO port_runs VALUES('u','key-b','c','id-b',x'02');").unwrap();
        assert_eq!(
            existing(&c, "u", "c", "id-a", "key-a", &[1]).unwrap(),
            Existing::Replay
        );
        assert_eq!(
            existing(&c, "u", "c", "id-a", "new-key", &[1]).unwrap(),
            Existing::Replay
        );
        assert_eq!(
            existing(&c, "u", "c", "id-a", "key-b", &[1]).unwrap(),
            Existing::Conflict
        );
        assert_eq!(
            existing(&c, "u", "c", "id-c", "key-c", &[3]).unwrap(),
            Existing::None
        );
    }

    #[test]
    fn recovery_marks_full_journal_as_incomplete_instead_of_silent_success() {
        let path =
            std::env::temp_dir().join(format!("openbot-recovery-{}.db", random_id().unwrap()));
        let db = Storage::open(&path).unwrap();
        db.try_with_connection(|c|{
            c.execute_batch("INSERT INTO auth_users(id,email,display_name,password_hash) VALUES('u','a@b','A','x'); INSERT INTO auth_organizations(id,slug,name) VALUES('o','o','O'); INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES('b','o','u','B','','help',0); INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES('c','o','u','t','[]','C',0); INSERT INTO port_conversation_messages(id,conversation_id,role,text,status,created_at) VALUES('a','c','bot','','running',0); INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES('r','c','u','b','m','a','k',x'01','running',0);")?;
            let tx=c.transaction()?; {let mut insert=tx.prepare("INSERT INTO port_run_events(conversation_id,sequence,event_json,bytes) VALUES('c',?1,'{}',2)")?; for sequence in 1..=event_journal::MAX_EVENTS {insert.execute(params![sequence])?;}} tx.commit()?; Ok(())
        }).unwrap();
        recover_interrupted(&db).unwrap();
        assert!(matches!(
            event_journal::replay(&db, "c", None, 128),
            Err(event_journal::JournalError::ReplayGap)
        ));
        let status = db
            .try_with_connection(|c| {
                Ok(
                    c.query_row("SELECT status FROM port_runs WHERE id='r'", [], |r| {
                        r.get::<_, String>(0)
                    })?,
                )
            })
            .unwrap();
        assert_eq!(status, "failed");
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn authenticated_message_runs_against_mock_and_persists_reply() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0; 8192];
                let _ = socket.read(&mut buf).await.unwrap();
                tokio::time::sleep(Duration::from_millis(500)).await;
                let body="data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello from mock\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";
                let reply=format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
                socket.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let path = std::env::temp_dir().join(format!("openbot-run-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let run = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap();
        let sdk_run = run.clone();
        let app = local_auth::router(auth.clone())
            .merge(bots::router(auth.clone()))
            .merge(conversations::router(auth))
            .merge(router(run));
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
        let request = |method: &str, path: &str, key: &str, body: String| {
            Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", &cookie)
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body))
                .unwrap()
        };
        let bots_path = "/api/v2/organizations/default/bots";
        let result=app.clone().oneshot(request("POST",bots_path,"bot-key",json!({"name":"Helper","title":"","roleDescription":"Be helpful","visibility":"private"}).to_string())).await.unwrap();
        assert_eq!(result.status(), StatusCode::CREATED);
        let bot: Value =
            serde_json::from_slice(&to_bytes(result.into_body(), 16384).await.unwrap()).unwrap();
        let bot_id = bot["bot"]["id"].as_str().unwrap();
        let result = app
            .clone()
            .oneshot(request(
                "POST",
                "/api/v2/organizations/default/conversations",
                "conversation-key",
                json!({"botIds":[bot_id]}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::CREATED);
        let conversation: Value =
            serde_json::from_slice(&to_bytes(result.into_body(), 16384).await.unwrap()).unwrap();
        let conversation_id = conversation["conversation"]["id"].as_str().unwrap();
        let messages =
            format!("/api/v2/organizations/default/conversations/{conversation_id}/messages");
        let payload = json!({"id":"message-1","text":"Hi","botId":bot_id}).to_string();
        let sent = app
            .clone()
            .oneshot(request("POST", &messages, "message-key", payload.clone()))
            .await
            .unwrap();
        assert_eq!(sent.status(), StatusCode::ACCEPTED);
        // The exact same accepted request can be retried while the only model
        // slot is occupied. A reused key for a changed message is a conflict.
        let mut retried = false;
        for _ in 0..20 {
            let response = app
                .clone()
                .oneshot(request("POST", &messages, "message-key", payload.clone()))
                .await
                .unwrap();
            if response.status() == StatusCode::ACCEPTED {
                let body: Value =
                    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                        .unwrap();
                assert_eq!(body["queued"], false);
                retried = true;
                break;
            }
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(retried, "retry was not recognized while run was active");
        let conflict = app
            .clone()
            .oneshot(request(
                "POST",
                &messages,
                "message-key",
                json!({"id":"other-message","text":"different","botId":bot_id}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let mut done = false;
        for _ in 0..100 {
            let status = db.try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT status FROM port_runs WHERE user_message_id='message-1'",
                    [],
                    |r| r.get::<_, String>(0),
                )?)
            });
            if matches!(status,Ok(ref s) if s=="completed") {
                done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(done, "mock run did not complete");
        let retry = app
            .clone()
            .oneshot(request("POST", &messages, "message-key", payload))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::ACCEPTED);
        let v: Value =
            serde_json::from_slice(&to_bytes(retry.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(v["queued"], false);
        let response = app
            .oneshot(request("GET", &messages, "", String::new()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let v: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
        assert!(v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["text"] == "Hello from mock" && m["status"] == "completed"));
        let events = event_journal::replay(&db, conversation_id, None, 128).unwrap();
        assert_eq!(events.last().unwrap()["type"], "RUN_FINISHED");
        let sdk_headers = request("POST", &messages, "sdk-key", String::new())
            .into_parts()
            .0
            .headers;
        let sdk_result = send_with_run_id(
            State(sdk_run.clone()),
            Path(("default".into(), conversation_id.into())),
            sdk_headers,
            Json(Input {
                id: "sdk-message".into(),
                text: "Hello".into(),
                bot_id: Some(bot_id.into()),
                ..Default::default()
            }),
            Some("sdk-run-id".into()),
        )
        .await;
        assert_eq!(sdk_result.status(), StatusCode::ACCEPTED);
        let mut sdk_done = false;
        for _ in 0..100 {
            if matches!(db.try_with_connection(|c|Ok(c.query_row("SELECT status FROM port_runs WHERE id='sdk-run-id'",[],|r|r.get::<_,String>(0))?)),Ok(ref s) if s=="completed")
            {
                sdk_done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(sdk_done, "canonical SDK run did not complete");
        let events = event_journal::replay(&db, conversation_id, None, 128).unwrap();
        assert!(events
            .iter()
            .any(|event| event["type"] == "RUN_STARTED" && event["runId"] == "sdk-run-id"));
        assert!(events
            .iter()
            .any(|event| event["type"] == "RUN_FINISHED" && event["runId"] == "sdk-run-id"));
        let collision_headers = request("POST", &messages, "other-sdk-key", String::new())
            .into_parts()
            .0
            .headers;
        let collision = send_with_run_id(
            State(sdk_run),
            Path(("default".into(), conversation_id.into())),
            collision_headers,
            Json(Input {
                id: "other-sdk-message".into(),
                text: "Other".into(),
                bot_id: Some(bot_id.into()),
                ..Default::default()
            }),
            Some("sdk-run-id".into()),
        )
        .await;
        assert_eq!(collision.status(), StatusCode::CONFLICT);
        db.try_with_connection(|c| {
            c.execute(
                "UPDATE port_runs SET status='running' WHERE user_message_id='message-1'",
                [],
            )?;
            c.execute(
                "UPDATE port_conversation_messages SET status='running' WHERE role='bot'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let restart_auth = AuthState::new(db.clone(), "http://example.test", None).unwrap();
        let _restarted =
            RunState::new(restart_auth, &format!("http://{addr}/v1"), "mock".into()).unwrap();
        let statuses = db
            .try_with_connection(|c| {
                Ok((
                    c.query_row(
                        "SELECT status FROM port_runs WHERE user_message_id='message-1'",
                        [],
                        |r| r.get::<_, String>(0),
                    )?,
                    c.query_row(
                        "SELECT status FROM port_conversation_messages WHERE role='bot'",
                        [],
                        |r| r.get::<_, String>(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!(statuses, ("failed".into(), "failed".into()));
        let recovered = event_journal::replay(&db, conversation_id, None, 128).unwrap();
        assert_eq!(recovered.last().unwrap()["type"], "RUN_ERROR");
        assert_eq!(
            recovered.last().unwrap()["message"],
            "Run interrupted by server restart"
        );
        mock.await.unwrap();
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod stop_tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn stop_requires_origin_and_cancels_only_the_matching_run() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let mock = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = ready_tx.send(());
            let _socket = socket;
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let path = std::env::temp_dir().join(format!("openbot-stop-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let state =
            RunState::new(auth.clone(), &format!("http://{address}/v1"), "mock".into()).unwrap();
        let app = local_auth::router(auth).merge(router(state));
        let setup=Request::builder().method("POST").uri("/api/port/auth/setup").header("host","example.test").header("origin","http://example.test").header("content-type","application/json").body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#)).unwrap();
        let response = app.clone().oneshot(setup).await.unwrap();
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        db.try_with_connection(|c|{c.execute_batch("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','help',0 FROM auth_users LIMIT 1; INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'thread','[\"bot\"]','Bot',0 FROM auth_users LIMIT 1;")?;Ok(())}).unwrap();
        let send = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/messages")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "message")
            .body(Body::from(r#"{"id":"m","text":"Hello","botId":"bot"}"#))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(send).await.unwrap().status(),
            StatusCode::ACCEPTED
        );
        tokio::time::timeout(Duration::from_secs(3), ready_rx)
            .await
            .unwrap()
            .unwrap();
        let request = |origin: &str, body: &'static str| {
            Request::builder()
                .method("POST")
                .uri("/api/copilotkit/agent/bot/stop/thread")
                .header("host", "example.test")
                .header("origin", origin)
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(request("http://evil.test", "{}"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let wrong = app
            .clone()
            .oneshot(request("http://example.test", r#"{"runId":"other"}"#))
            .await
            .unwrap();
        let v: Value =
            serde_json::from_slice(&to_bytes(wrong.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(v["stopped"], false);
        let stopped = app
            .clone()
            .oneshot(request("http://example.test", "{}"))
            .await
            .unwrap();
        let v: Value =
            serde_json::from_slice(&to_bytes(stopped.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(v["stopped"], true);
        let mut terminal = false;
        for _ in 0..100 {
            if let Ok(events) = event_journal::replay(&db, "conv", None, 128) {
                if events
                    .iter()
                    .any(|e| e["type"] == "RUN_ERROR" && e["code"] == "STOPPED")
                {
                    terminal = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(terminal, "stopped run did not persist terminal event");
        let status = db
            .try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT status FROM port_runs WHERE conversation_id='conv'",
                    [],
                    |r| r.get::<_, String>(0),
                )?)
            })
            .unwrap();
        assert_eq!(status, "failed");
        mock.abort();
        drop(app);
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn approval_resume_executes_tool_and_completes_turn_end_to_end() {
        let path =
            std::env::temp_dir().join(format!("openbot-resume-{}.db", random_id().unwrap()));
        let _ = std::fs::remove_file(&path);
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let ws_root =
            std::env::temp_dir().join(format!("openbot-resume-ws-{}", random_id().unwrap()));
        let _ = std::fs::remove_dir_all(&ws_root);
        std::fs::create_dir_all(&ws_root).unwrap();
        let vc = virtual_computer::VirtualComputerState::new(auth.clone(), ws_root.clone());
        let turn_no = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let turn_c = turn_no.clone();
        let mock_app = Router::new()
            .route(
                "/v1/models",
                axum::routing::get(|| async { axum::Json(json!({"data":[{"id":"mock"}]})) }),
            )
            .route(
                "/v1/chat/completions",
                post(move || {
                    let n = turn_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move {
                        let chunk = if n == 0 {
                            json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_wr_1","type":"function","function":{"name":"computer_write_file","arguments":"{\"path\":\"note.txt\",\"contents\":\"approved content\"}"}}]},"finish_reason":"tool_calls"}]})
                        } else {
                            json!({"choices":[{"index":0,"delta":{"content":"Done writing approved content."},"finish_reason":"stop"}]})
                        };
                        let body = format!("data: {chunk}\n\ndata: [DONE]\n\n");
                        Response::builder()
                            .header("content-type", "text/event-stream")
                            .body(Body::from(body))
                            .unwrap()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move { axum::serve(listener, mock_app).await.unwrap() });

        let state =
            RunState::new(auth.clone(), &format!("http://{address}/v1"), "mock".into())
                .unwrap()
                .with_virtual_computer(vc);
        let app = local_auth::router(auth.clone())
            .merge(router(state.clone()))
            .merge(approvals_api::router_with_runs(auth, Some(state.clone())));
        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let response = app.clone().oneshot(setup).await.unwrap();
        let cookie = response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','help',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'thread','[\"bot\"]','Bot',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_approval_rules(id,organization_id,scope_owner_id,bot_id,tool_ref,effect,scope,behaviour,created_by,created_at) SELECT 'rule_ask','default',id,'bot','computer_write_file','write','*','ask',id,0 FROM auth_users LIMIT 1;",
            )?;
            Ok(())
        })
        .unwrap();

        // 1. Send message -> hits HITL approval interrupt on computer_write_file
        let send = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/messages")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "m-ask")
            .body(Body::from(r#"{"id":"m1","text":"Write a note","botId":"bot"}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(send).await.unwrap().status(), StatusCode::ACCEPTED);

        let mut approval_id: Option<String> = None;
        for _ in 0..80 {
            if let Ok(events) = event_journal::replay(&db, "conv", None, 128) {
                for ev in &events {
                    if ev["type"] == "RUN_FINISHED" && ev["outcome"]["type"] == "interrupt" {
                        approval_id = ev["outcome"]["interrupts"][0]["id"].as_str().map(str::to_owned);
                    }
                }
                if approval_id.is_some() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let approval_id = approval_id.unwrap_or_else(|| {
            panic!(
                "expected interrupt approval_id; events = {:?}",
                event_journal::replay(&db, "conv", None, 128)
            )
        });

        // 2. Decide allow_once -> spawns tool execution + second model turn
        let decide = Request::builder()
            .method("POST")
            .uri(format!("/api/v2/organizations/default/people/me/approvals/{approval_id}/decide"))
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "dec-1")
            .body(Body::from(r#"{"decision":"allow_once"}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(decide).await.unwrap().status(), StatusCode::OK);

        let mut done_text = false;
        for _ in 0..120 {
            if let Ok(events) = event_journal::replay(&db, "conv", None, 128) {
                let has_text = events.iter().any(|e| {
                    e["type"] == "TEXT_MESSAGE_CONTENT"
                        && e["delta"].as_str().unwrap_or("").contains("Done writing approved content.")
                });
                let has_clean_finish = events
                    .iter()
                    .any(|e| e["type"] == "RUN_FINISHED" && e.get("outcome").is_none());
                if has_text && has_clean_finish {
                    done_text = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(done_text, "expected resumed turn assistant text");
        let app_status: String = db
            .try_with_connection(|c| {
                Ok(c.query_row(
                    "SELECT status FROM port_approvals WHERE id=?1",
                    params![approval_id],
                    |r| r.get::<_, String>(0),
                )?)
            })
            .unwrap();
        assert_eq!(app_status, "completed");

        mock.abort();
        drop(app);
        drop(state);
        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(ws_root);
    }

    #[tokio::test]
    async fn resolve_active_model_replaces_stale_and_errors_when_unloaded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        assert_eq!(clip_chars("hello", 10), "hello");
        assert_eq!(clip_chars("hello world", 5), "hello...");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            for body in [
                r#"{"data":[{"id":"qwen3.5-18b-a3b.gguf"}]}"#,
                r#"{"data":[{"id":"qwen3.5-18b-a3b.gguf"}]}"#,
                r#"{"data":[]}"#,
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await.unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let client = ModelClient::new(
            &format!("http://{addr}/v1"),
            Duration::from_secs(2),
            Duration::from_secs(5),
        )
        .unwrap();
        let cancel = CancellationToken::new();

        let mut req_auto = json!({"model": "auto"});
        resolve_active_model(&client, &mut req_auto, &cancel).await.unwrap();
        assert_eq!(req_auto["model"], "qwen3.5-18b-a3b.gguf");

        let mut req_stale = json!({"model": "PS5LM (Qwen3.5-9B)"});
        resolve_active_model(&client, &mut req_stale, &cancel).await.unwrap();
        assert_eq!(req_stale["model"], "qwen3.5-18b-a3b.gguf");

        let mut req_empty = json!({"model": "auto"});
        let err = resolve_active_model(&client, &mut req_empty, &cancel).await.unwrap_err();
        assert!(err.contains("No model is currently loaded"), "unexpected err: {err}");

        mock.await.unwrap();
    }
}
