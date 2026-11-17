//! Experimental, opt-in host model runs. Tools and WebSocket delivery are not implemented.
use crate::{
    approvals_api,
    context_manager,
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

const MAX_GROUP_TRANSCRIPT_CHARS: usize = 6000;
const MAX_DM_HISTORY_CHARS: usize = 7000;
const MAX_TOOL_RESULT_CHARS_FOR_LLM: usize = 3072;
const MAX_OLD_TOOL_RESULT_CHARS_FOR_LLM: usize = 400;
const OOM_RETRY_MAX_TOKENS: u64 = 512;

#[derive(Clone)]
pub struct RunState {
    pub(crate) auth: AuthState,
    pub(crate) model: ModelClient,
    pub(crate) model_id: String,
    capacity: Arc<Semaphore>,
    active: Arc<Mutex<HashMap<String, CancellationToken>>>,
    registration: Arc<tokio::sync::Mutex<()>>,
    virtual_computer: Option<virtual_computer::VirtualComputerState>,
    context_manager: context_manager::ContextManager,
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
        let context_manager = context_manager::ContextManager::new(url)?;
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
            context_manager,
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

    pub(crate) fn context_manager(&self) -> context_manager::ContextManager {
        self.context_manager.clone()
    }

    pub fn with_live_context_probe(mut self) -> Self {
        self.context_manager = self.context_manager.with_live_probe(true);
        self
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
    let t = text.trim_matches(|c: char| c.is_whitespace() || matches!(c, '*' | '_' | '`'));
    if t.is_empty() {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    for prefix in ["[pass]", "[no_reply]", "[silent]"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            let after_fmt = rest.trim_start_matches(|c| matches!(c, '*' | '_' | '`'));
            if after_fmt.is_empty()
                || after_fmt.chars().next().is_some_and(|c| {
                    c.is_whitespace()
                        || matches!(c, ':' | '.' | '!' | ',' | '-' | '\u{2013}' | '\u{2014}')
                })
            {
                return true;
            }
        }
    }
    false
}

fn find_phrase_ci_spans(haystack_lower: &str, needle_lower: &str) -> Vec<(usize, usize)> {
    let needle_lower = needle_lower.trim();
    if needle_lower.len() < 2 {
        return Vec::new();
    }
    let mut spans = Vec::new();
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
            spans.push((idx, after_idx));
        }
    }
    spans
}

fn contains_phrase_ci(haystack_lower: &str, needle_lower: &str) -> bool {
    !find_phrase_ci_spans(haystack_lower, needle_lower).is_empty()
}

fn select_lead_group_bot(bots: &[String], bot_names: &HashMap<String, String>) -> String {
    for keyword in ["commander", "coordinator", "lead"] {
        if let Some(id) = bots.iter().find(|id| {
            bot_names
                .get(*id)
                .is_some_and(|name| name.to_lowercase().contains(keyword))
        }) {
            return id.clone();
        }
    }
    bots.first().cloned().unwrap_or_default()
}

fn is_group_broadcast(text_lower: &str) -> bool {
    contains_phrase_ci(text_lower, "@all")
        || contains_phrase_ci(text_lower, "everyone")
        || contains_phrase_ci(text_lower, "all bots")
        || contains_phrase_ci(text_lower, "all of you")
}

struct GroupTurnPlan {
    bots: Vec<String>,
    is_broadcast: bool,
    lead_orchestration: bool,
}

fn extract_explicit_group_bot_mentions(
    lower: &str,
    bots: &[String],
    bot_names: &HashMap<String, String>,
) -> Vec<String> {
    let mut candidates: Vec<(&str, String)> = bots
        .iter()
        .filter_map(|id| {
            bot_names
                .get(id)
                .map(|n| (id.as_str(), normalize_hws_lower(n).trim().to_owned()))
        })
        .filter(|(_, name)| !name.is_empty())
        .collect();
    // Longest name first so "Backend Dev" beats "Dev".
    candidates.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let mut matched: Vec<String> = Vec::new();
    let mut push_unique = |id: &str| {
        if !matched.iter().any(|existing| existing == id) {
            matched.push(id.to_owned());
        }
    };

    // 1. Explicit @mentions anywhere in the message.
    for (idx, ch) in lower.char_indices() {
        if ch != '@' {
            continue;
        }
        let before_ok = lower[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        if !before_ok {
            continue;
        }
        let after_at = &lower[idx + 1..];
        for (bot_id, name_lower) in &candidates {
            if let Some(rest) = after_at.strip_prefix(name_lower.as_str()) {
                let after_ok = rest.chars().next().is_none_or(|c| !c.is_alphanumeric());
                if after_ok {
                    push_unique(bot_id);
                    break;
                }
            }
        }
    }

    // 2. Explicit leading vocative addressing ("Programmer, ...", "Hey Programmer, ...",
    //    "Programmer and UI Designer please ...").
    let mut s = lower.trim_start();
    for greeting in ["hello", "okay", "dear", "hey", "hi", "yo", "ok"] {
        if let Some(rest) = s.strip_prefix(greeting) {
            if rest.starts_with(',') || rest.chars().next().is_some_and(char::is_whitespace) {
                let after = rest.trim_start_matches(',').trim_start();
                if !after.is_empty() {
                    s = after;
                }
                break;
            }
        }
    }

    fn match_head<'a, 'b>(
        candidates: &[(&'a str, String)],
        input: &'b str,
    ) -> Option<(&'a str, &'b str)> {
        for (bot_id, name_lower) in candidates {
            if let Some(rest) = input.strip_prefix(name_lower.as_str()) {
                if rest.chars().next().is_none_or(|c| !c.is_alphanumeric()) {
                    return Some((*bot_id, rest));
                }
            }
        }
        None
    }

    let mut leading: Vec<&str> = Vec::new();
    let mut valid_leading = false;
    let mut cur = s;
    while let Some((bot_id, rest)) = match_head(&candidates, cur) {
        leading.push(bot_id);
        let after_ws = rest.trim_start();
        let next_after_sep = if let Some(r) = after_ws.strip_prefix(", and ") {
            Some(r.trim_start())
        } else if let Some(r) = after_ws.strip_prefix(", & ") {
            Some(r.trim_start())
        } else if let Some(r) = after_ws.strip_prefix("and ") {
            if rest.starts_with(char::is_whitespace) {
                Some(r.trim_start())
            } else {
                None
            }
        } else if let Some(r) = after_ws.strip_prefix('&') {
            Some(r.trim_start())
        } else if let Some(r) = after_ws.strip_prefix(',') {
            Some(r.trim_start())
        } else {
            None
        };
        if let Some(next_s) = next_after_sep {
            if match_head(&candidates, next_s).is_some() {
                cur = next_s;
                continue;
            }
        }
        valid_leading = after_ws.is_empty()
            || matches!(
                after_ws.chars().next(),
                Some(',' | ':' | '!' | '?' | '-' | '\u{2013}' | '\u{2014}')
            )
            || after_ws
                .strip_prefix("please")
                .is_some_and(|r| r.is_empty() || r.chars().next().is_some_and(|c| !c.is_alphanumeric()));
        break;
    }
    if valid_leading {
        for id in leading {
            push_unique(id);
        }
    }

    matched
}

fn plan_group_turn(
    bots: &[String],
    bot_names: &HashMap<String, String>,
    text: &str,
) -> GroupTurnPlan {
    if bots.len() <= 1 {
        return GroupTurnPlan {
            bots: bots.to_vec(),
            is_broadcast: false,
            lead_orchestration: false,
        };
    }
    let lower = normalize_hws_lower(text);
    if is_group_broadcast(&lower) {
        return GroupTurnPlan {
            bots: bots.to_vec(),
            is_broadcast: true,
            lead_orchestration: false,
        };
    }
    let matched = extract_explicit_group_bot_mentions(&lower, bots, bot_names);
    if !matched.is_empty() {
        GroupTurnPlan {
            bots: matched,
            is_broadcast: false,
            lead_orchestration: false,
        }
    } else {
        GroupTurnPlan {
            bots: vec![select_lead_group_bot(bots, bot_names)],
            is_broadcast: false,
            lead_orchestration: true,
        }
    }
}

fn select_group_turn_bots(
    bots: &[String],
    bot_names: &HashMap<String, String>,
    text: &str,
) -> Vec<String> {
    plan_group_turn(bots, bot_names, text).bots
}

fn normalize_hws_lower(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = false;
    for ch in text.chars() {
        if ch == ' ' || ch == '\t' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            prev_space = false;
            for lc in ch.to_lowercase() {
                out.push(lc);
            }
        }
    }
    out
}

fn is_numbered_list_marker_dot(before_dot: &str, after_dot: &str) -> bool {
    if !after_dot.chars().next().is_some_and(char::is_whitespace) {
        return false;
    }
    let without_digits = before_dot.trim_end_matches(|c: char| c.is_ascii_digit());
    if without_digits.len() == before_dot.len() {
        return false;
    }
    without_digits.is_empty()
        || without_digits
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace)
}

fn starts_with_numbered_list_marker(s: &str) -> bool {
    let rest = s.trim_start_matches(|c: char| c.is_ascii_digit());
    rest.len() < s.len()
        && rest
            .strip_prefix('.')
            .is_some_and(|after| after.starts_with(' ') || after.starts_with('\t'))
}

fn handoff_clause_end(tail: &str) -> usize {
    let bytes = tail.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let ch = tail[i..].chars().next().unwrap();
        let next_i = i + ch.len_utf8();
        if matches!(ch, '!' | '?') {
            return i;
        }
        if ch == '.' {
            let after = &tail[next_i..];
            if (after.is_empty() || after.chars().next().is_some_and(char::is_whitespace))
                && !is_numbered_list_marker_dot(&tail[..i], after)
            {
                return i;
            }
        }
        if ch == '\n' {
            let before = tail[..i].trim_end_matches(|c| c == ' ' || c == '\r');
            let after = tail[next_i..].trim_start_matches(' ');
            let continues_list = before.ends_with(':')
                || after.starts_with("- ")
                || after.starts_with("* ")
                || after.starts_with("• ")
                || starts_with_numbered_list_marker(after);
            if after.is_empty() || after.starts_with('\n') || !continues_list {
                return i;
            }
        }
        i = next_i;
    }
    tail.len()
}

fn parse_group_handoff(
    reply: &str,
    bots: &[String],
    bot_names: &HashMap<String, String>,
    lead_bot: &str,
) -> Vec<String> {
    if bots.len() <= 1 || reply.trim().is_empty() {
        return Vec::new();
    }
    const PHRASES: &[&str] = &[
        "pass it off to",
        "pass this off to",
        "pass off to",
        "pass it to",
        "pass this to",
        "pass to",
        "passing it off to",
        "passing this off to",
        "passing off to",
        "passing it to",
        "passing this to",
        "passing to",
        "passed it off to",
        "passed this off to",
        "passed off to",
        "passed it to",
        "passed this to",
        "passed to",
        "hand it off to",
        "hand this off to",
        "hand off to",
        "hand it to",
        "hand this to",
        "hand to",
        "handing it off to",
        "handing this off to",
        "handing off to",
        "handing it to",
        "handing this to",
        "handing to",
        "handed it off to",
        "handed this off to",
        "handed off to",
        "handed it to",
        "handed this to",
        "handed to",
        "delegate it to",
        "delegate this to",
        "delegate to",
        "delegating it to",
        "delegating this to",
        "delegating to",
        "delegated it to",
        "delegated this to",
        "delegated to",
        "route it to",
        "route this to",
        "route to",
        "routing it to",
        "routing this to",
        "routing to",
        "routed it to",
        "routed this to",
        "routed to",
        "assign it to",
        "assign this to",
        "assign to",
        "assigning it to",
        "assigning this to",
        "assigning to",
        "assigned it to",
        "assigned this to",
        "assigned to",
    ];
    let lower = normalize_hws_lower(reply);
    let mut directive_spans: Vec<(usize, usize, usize)> = Vec::new();
    for phrase in PHRASES {
        for (start, end) in find_phrase_ci_spans(&lower, phrase) {
            let tail = &lower[end..];
            let clause_end = end + handoff_clause_end(tail);
            directive_spans.push((start, end, clause_end));
        }
    }
    directive_spans.sort_by_key(|(start, _, _)| *start);

    let non_lead: Vec<(&str, String)> = bots
        .iter()
        .filter(|id| id.as_str() != lead_bot)
        .filter_map(|id| {
            bot_names
                .get(id)
                .map(|n| (id.as_str(), normalize_hws_lower(n)))
        })
        .filter(|(_, name)| name.trim().len() >= 2)
        .collect();

    let mut targets: Vec<String> = Vec::new();
    let mut last_directive_end = 0usize;
    for (dir_start, phrase_end, dir_end) in directive_spans {
        if dir_start < last_directive_end || dir_end <= phrase_end {
            continue;
        }
        last_directive_end = dir_end;
        let clause = &lower[phrase_end..dir_end];
        let mut matches: Vec<(usize, usize, &str)> = Vec::new();
        for (bot_id, name_lower) in &non_lead {
            for (m_start, m_end) in find_phrase_ci_spans(clause, name_lower) {
                matches.push((m_start, m_end, *bot_id));
            }
        }
        matches.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| (b.1 - b.0).cmp(&(a.1 - a.0))));
        let mut covered_end = 0usize;
        for (m_start, m_end, bot_id) in matches {
            if m_start < covered_end {
                continue;
            }
            covered_end = m_end;
            if !targets.iter().any(|existing| existing == bot_id) {
                targets.push(bot_id.to_owned());
            }
        }
    }
    targets
}

fn summarize_tool_args(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(trimmed) {
        for key in ["url", "path", "command"] {
            if let Some(val) = map.get(key).and_then(Value::as_str) {
                return format!("{key}=\"{}\"", clip_chars(val, 100));
            }
        }
    }
    clip_chars(trimmed, 100)
}

fn summarize_tool_result(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(Value::Object(mut map)) = serde_json::from_str::<Value>(trimmed) {
        if let Some(err) = map.get("error").and_then(Value::as_str) {
            return format!("ERROR: {}", clip_chars(err, 180));
        }
        if map.get("denied").and_then(Value::as_bool) == Some(true) {
            let reason = map
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("permission denied");
            return format!("DENIED: {}", clip_chars(reason, 180));
        }
        if let (Some(status), Some(url)) = (
            map.get("status").and_then(Value::as_u64),
            map.get("url").and_then(Value::as_str),
        ) {
            let title = map
                .get("title")
                .and_then(Value::as_str)
                .map(|t| format!(" title=\"{}\"", clip_chars(t, 80)))
                .unwrap_or_default();
            return format!("OK: status={status} url={}{title}", clip_chars(url, 100));
        }
        map.remove("htmlPreview");
        map.remove("html");
        let compact = Value::Object(map).to_string();
        return format!("OK: {}", clip_chars(&compact, 200));
    }
    clip_chars(trimmed, 200)
}

fn load_tool_summaries_by_message(
    tx: &rusqlite::Connection,
    conversation_id: &str,
) -> rusqlite::Result<HashMap<String, Vec<String>>> {
    use std::collections::HashSet;

    let mut run_to_msg: HashMap<String, String> = HashMap::new();
    {
        let mut run_st = tx.prepare(
            "SELECT id, assistant_message_id FROM port_runs WHERE conversation_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = run_st.query_map(params![conversation_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows.flatten() {
            run_to_msg.insert(row.0, row.1);
        }
    }
    if run_to_msg.is_empty() {
        return Ok(HashMap::new());
    }

    struct TcCall {
        msg_id: String,
        id: String,
        name: String,
        args: String,
    }

    let mut calls: Vec<TcCall> = Vec::new();
    let mut tc_idx: HashMap<String, usize> = HashMap::new();
    let mut results: HashMap<String, String> = HashMap::new();
    let mut interrupted: HashSet<String> = HashSet::new();

    {
        let mut ev_st = tx.prepare(
            "SELECT event_json FROM port_run_events WHERE conversation_id=?1 ORDER BY sequence ASC",
        )?;
        let mut current_run_id: Option<String> = None;
        let rows = ev_st.query_map(params![conversation_id], |r| r.get::<_, String>(0))?;
        for raw in rows.flatten() {
            let Ok(ev) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            match ev.get("type").and_then(Value::as_str).unwrap_or("") {
                "RUN_STARTED" => {
                    current_run_id = ev
                        .get("runId")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
                "TOOL_CALL_START" => {
                    if let (Some(rid), Some(tc_id), Some(tc_name)) = (
                        current_run_id.as_deref(),
                        ev.get("toolCallId").and_then(Value::as_str),
                        ev.get("toolCallName").and_then(Value::as_str),
                    ) {
                        if let Some(msg_id) = run_to_msg.get(rid) {
                            let idx = calls.len();
                            calls.push(TcCall {
                                msg_id: msg_id.clone(),
                                id: tc_id.to_owned(),
                                name: tc_name.to_owned(),
                                args: String::new(),
                            });
                            tc_idx.insert(tc_id.to_owned(), idx);
                        }
                    }
                }
                "TOOL_CALL_ARGS" => {
                    if let (Some(tc_id), Some(delta)) = (
                        ev.get("toolCallId").and_then(Value::as_str),
                        ev.get("delta").and_then(Value::as_str),
                    ) {
                        if let Some(&idx) = tc_idx.get(tc_id) {
                            calls[idx].args.push_str(delta);
                        }
                    }
                }
                "TOOL_CALL_RESULT" => {
                    if let (Some(tc_id), Some(content)) = (
                        ev.get("toolCallId").and_then(Value::as_str),
                        ev.get("content").and_then(Value::as_str),
                    ) {
                        results.insert(tc_id.to_owned(), content.to_owned());
                    }
                }
                "RUN_FINISHED" => {
                    if ev.get("outcome").and_then(|o| o.get("type")).and_then(Value::as_str)
                        == Some("interrupt")
                    {
                        if let Some(arr) = ev
                            .get("outcome")
                            .and_then(|o| o.get("interrupts"))
                            .and_then(Value::as_array)
                        {
                            for item in arr {
                                if let Some(tc_id) = item.get("toolCallId").and_then(Value::as_str)
                                {
                                    interrupted.insert(tc_id.to_owned());
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for tc in calls {
        let args_summary = summarize_tool_args(&tc.args);
        let outcome = if let Some(res_raw) = results.get(&tc.id) {
            summarize_tool_result(res_raw)
        } else if interrupted.contains(&tc.id) {
            "PAUSED (awaiting user approval)".to_owned()
        } else {
            "NO_RESULT (did not complete)".to_owned()
        };
        let line = format!("(History: executed {} with {} -> {})", tc.name, args_summary, outcome);
        out.entry(tc.msg_id).or_default().push(line);
    }
    Ok(out)
}

fn sanitize_legacy_tool_text(text: &str) -> String {
    let mut kept = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("[Tool call:")
            || trimmed.starts_with("✅ Status:")
            || trimmed.starts_with("Status: 200 OK")
        {
            continue;
        }
        kept.push(line);
    }
    kept.join("\n")
}

fn build_group_transcript(
    tx: &rusqlite::Connection,
    conversation_id: &str,
    org_id: &str,
    bot_names: Option<&HashMap<String, String>>,
    msg_clip: usize,
    att_recent_clip: usize,
    att_old_clip: usize,
) -> rusqlite::Result<String> {
    let tool_summaries = load_tool_summaries_by_message(tx, conversation_id)?;
    let mut st = tx.prepare(
        "SELECT id,role,bot_id,text,status FROM port_conversation_messages WHERE conversation_id=?1 AND status IN ('completed','waiting') ORDER BY rowid DESC LIMIT 10",
    )?;
    let mut history = st
        .query_map(params![conversation_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(st);
    history.reverse();
    history.retain(|(mid, role, _, text, status)| {
        role == "person"
            || status == "waiting"
            || !tool_summaries.get(mid).is_none_or(Vec::is_empty)
            || !is_silent_group_pass(text)
    });
    let history_len = history.len();
    let last_person_idx = history.iter().rposition(|(_, role, _, _, _)| role == "person");
    let mut entries: Vec<(bool, String)> = Vec::with_capacity(history_len);
    for (idx, (mid, role, bid, text, status)) in history.into_iter().enumerate() {
        let is_last_person = Some(idx) == last_person_idx;
        let is_recent = idx + 2 >= history_len;
        let clean_text = if role == "bot" {
            sanitize_legacy_tool_text(&text)
        } else {
            text
        };
        let spoken = if is_last_person {
            clean_text
        } else if idx + 1 == history_len {
            clip_chars(&clean_text, msg_clip.max(1200))
        } else {
            clip_chars(&clean_text, msg_clip)
        };
        let mut entry = String::new();
        if role == "person" {
            entry.push_str(&format!("User: {spoken}\n"));
            if let Ok(mut att_st) = tx.prepare(
                "SELECT filename, mime_type, size_bytes, extracted_text FROM port_attachments WHERE conversation_id=?1 AND message_id=?2 ORDER BY rowid ASC",
            ) {
                if let Ok(rows) = att_st.query_map(params![conversation_id, mid], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                }) {
                    for att in rows.flatten() {
                        entry.push_str(&format!(
                            "[Attached file: uploads/{} ({}, {} bytes)]\n",
                            att.0, att.1, att.2
                        ));
                        if let Some(ext) = att.3.filter(|s| !s.trim().is_empty()) {
                            let clipped = clip_chars(
                                ext.trim(),
                                if is_last_person || is_recent {
                                    att_recent_clip
                                } else {
                                    att_old_clip
                                },
                            );
                            entry.push_str(&format!(
                                "--- Content of {} ---\n{clipped}\n--- End of {} ---\n",
                                att.0, att.0
                            ));
                        }
                    }
                }
            }
        } else {
            let speaker = bid
                .as_deref()
                .and_then(|id| {
                    bot_names
                        .and_then(|map| map.get(id).cloned())
                        .or_else(|| {
                            tx.query_row(
                                "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2",
                                params![id, org_id],
                                |r| r.get::<_, String>(0),
                            )
                            .ok()
                        })
                })
                .unwrap_or_else(|| "Teammate".to_owned());
            let tools_note = tool_summaries
                .get(&mid)
                .map(|lines| lines.join(" "))
                .unwrap_or_default();
            if !tools_note.is_empty() && !spoken.trim().is_empty() {
                entry.push_str(&format!("[{speaker}]: {tools_note}\n{spoken}\n"));
            } else if !tools_note.is_empty() {
                entry.push_str(&format!("[{speaker}]: {tools_note}\n"));
            } else if status == "waiting" && spoken.trim().is_empty() {
                entry.push_str(&format!("[{speaker}]: [Waiting for user approval]\n"));
            } else {
                entry.push_str(&format!("[{speaker}]: {spoken}\n"));
            }
        }
        entries.push((is_last_person, entry));
    }

    let mut total_chars: usize = entries.iter().map(|(_, s)| s.chars().count()).sum();
    while total_chars > MAX_GROUP_TRANSCRIPT_CHARS && entries.len() > 1 {
        let drop_idx = (0..entries.len() - 1)
            .find(|&i| !entries[i].0)
            .or_else(|| (entries.len() > 1).then_some(0));
        let Some(idx) = drop_idx else {
            break;
        };
        if entries[idx].0 && entries.len() <= 2 {
            break;
        }
        let (_, removed) = entries.remove(idx);
        total_chars = total_chars.saturating_sub(removed.chars().count());
    }

    let mut transcript = String::with_capacity(total_chars.min(MAX_GROUP_TRANSCRIPT_CHARS));
    for (_, part) in entries {
        transcript.push_str(&part);
    }
    Ok(transcript)
}

fn build_dm_messages(
    tx: &rusqlite::Connection,
    conversation_id: &str,
    bot_id: &str,
    instructions: &str,
    include_attachments: bool,
) -> rusqlite::Result<Vec<Value>> {
    let tool_summaries = load_tool_summaries_by_message(tx, conversation_id)?;
    let mut st = tx.prepare(
        "SELECT id,role,bot_id,text,status FROM port_conversation_messages WHERE conversation_id=?1 AND status IN ('completed','waiting') AND (role='person' OR (role='bot' AND bot_id=?2)) ORDER BY rowid DESC LIMIT 10",
    )?;
    let mut history = st
        .query_map(params![conversation_id, bot_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(st);
    history.reverse();
    history.retain(|(mid, role, _, text, status)| {
        role == "person"
            || status == "waiting"
            || !tool_summaries.get(mid).is_none_or(Vec::is_empty)
            || !text.trim().is_empty()
    });
    let history_len = history.len();
    let last_person_idx = history.iter().rposition(|(_, role, _, _, _)| role == "person");
    let mut items: Vec<(bool, Value)> = Vec::with_capacity(history_len);
    for (idx, (mid, role, _bid, mut msg_text, status)) in history.into_iter().enumerate() {
        let is_last_person = Some(idx) == last_person_idx;
        let is_recent = idx + 2 >= history_len;
        if role == "bot" {
            msg_text = sanitize_legacy_tool_text(&msg_text);
        }
        if !is_last_person {
            let cap = if idx + 1 == history_len { 1200 } else { 600 };
            msg_text = clip_chars(&msg_text, cap);
        }
        if include_attachments && role == "person" {
            let mut att_st = tx.prepare(
                "SELECT filename, mime_type, size_bytes, extracted_text FROM port_attachments WHERE conversation_id=?1 AND message_id=?2 ORDER BY rowid ASC",
            )?;
            let atts = att_st
                .query_map(params![conversation_id, mid], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(att_st);
            if !atts.is_empty() {
                let max_att = if is_last_person || is_recent { 1800 } else { 400 };
                let mut note = String::new();
                for (fname, mime, sz, ext) in atts {
                    note.push_str(&format!(
                        "\n[Attached file: uploads/{fname} ({mime}, {sz} bytes)]"
                    ));
                    if let Some(t) = ext.filter(|s| !s.trim().is_empty()) {
                        let clipped = clip_chars(t.trim(), max_att);
                        note.push_str(&format!(
                            "\n--- Content of {fname} ---\n{clipped}\n--- End of {fname} ---"
                        ));
                    }
                }
                msg_text.push_str(&note);
            }
        }
        if role == "bot" {
            let tools_note = tool_summaries
                .get(&mid)
                .map(|lines| lines.join("\n"))
                .unwrap_or_default();
            if !tools_note.is_empty() && !msg_text.trim().is_empty() {
                msg_text = format!("{tools_note}\n{msg_text}");
            } else if !tools_note.is_empty() {
                msg_text = tools_note;
            } else if status == "waiting" && msg_text.trim().is_empty() {
                msg_text = "[Waiting for user approval]".to_owned();
            }
        }
        let role_str = if role == "person" { "user" } else { "assistant" };
        items.push((is_last_person, json!({"role": role_str, "content": msg_text})));
    }

    let msg_len = |v: &Value| -> usize {
        v.get("content")
            .and_then(Value::as_str)
            .map(|s| s.chars().count())
            .unwrap_or(0)
    };
    let mut total_chars: usize = items.iter().map(|(_, v)| msg_len(v)).sum();
    while total_chars > MAX_DM_HISTORY_CHARS && items.len() > 1 {
        let drop_idx = (0..items.len() - 1).find(|&i| !items[i].0);
        let Some(idx) = drop_idx else {
            break;
        };
        let (_, removed) = items.remove(idx);
        total_chars = total_chars.saturating_sub(msg_len(&removed));
    }

    let mut messages = Vec::with_capacity(items.len() + 1);
    messages.push(json!({"role":"system","content":instructions}));
    messages.extend(items.into_iter().map(|(_, v)| v));
    Ok(messages)
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
    let ctx_mgr = s.context_manager.clone();
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
        let _ = execute(
            auth,
            model,
            vc,
            ctx_mgr,
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
    #[serde(default, alias = "interrupt_active")]
    pub(crate) interrupt_active: bool,
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
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(|c| {
            let row: Option<Option<String>> = c
                .query_row(
                    "SELECT COALESCE(
                        (SELECT id FROM port_runs r WHERE r.conversation_id=c.id AND r.bot_id=?1 AND r.status='running' AND (?5 IS NULL OR r.id=?5) LIMIT 1),
                        CASE WHEN ?5 IS NULL THEN (SELECT id FROM port_runs r WHERE r.conversation_id=c.id AND r.status='running' LIMIT 1) ELSE NULL END
                     )
                       FROM port_conversations c
                       JOIN port_bots b ON b.id=?1 AND b.organization_id=c.organization_id AND b.owner_id=c.owner_id
                      WHERE c.thread_id=?2 AND c.organization_id=?3 AND c.owner_id=?4 AND c.deleted=0",
                    params![bot, thread, actor.organization, actor.id, scope.run_id],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(row)
        })
    })
    .await;
    let run = match result {
        Ok(Ok(Some(v))) => v,
        Ok(Ok(None)) => return problem(StatusCode::NOT_FOUND, "Thread or bot not found"),
        _ => return problem(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    };
    let mut stopped = run
        .as_ref()
        .and_then(|id| s.active.lock().ok().and_then(|map| map.get(id).cloned()))
        .is_some_and(|token| {
            token.cancel();
            true
        });
    if !stopped {
        if let Some(stuck_run_id) = run.as_ref() {
            // If a DB run row is marked 'running' while absent from `s.active` and `capacity` is free,
            // unstick it so the thread does not remain permanently blocked.
            if let Ok(_free_permit) = s.capacity.clone().try_acquire_owned() {
                if let Ok(db_p) = s.auth.db_jobs.clone().try_acquire_owned() {
                    let db_c = s.auth.db.clone();
                    let rid = stuck_run_id.clone();
                    let cleaned = tokio::task::spawn_blocking(move || {
                        let _p = db_p;
                        db_c.try_with_connection(|c| {
                            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                            let conv_id: Option<String> = tx
                                .query_row(
                                    "SELECT conversation_id FROM port_runs WHERE id=?1 AND status='running'",
                                    params![rid],
                                    |r| r.get(0),
                                )
                                .optional()?;
                            let n = tx.execute(
                                "UPDATE port_runs SET status='failed' WHERE id=?1 AND status='running'",
                                params![rid],
                            )?;
                            if let Some(cid) = conv_id {
                                tx.execute(
                                    "UPDATE port_conversation_messages SET status='failed' WHERE conversation_id=?1 AND status IN ('running', 'queued')",
                                    params![cid],
                                )?;
                            }
                            tx.commit()?;
                            Ok(n > 0)
                        })
                    })
                    .await;
                    if matches!(cleaned, Ok(Ok(true))) {
                        stopped = true;
                    }
                }
            }
        }
    }
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
    if input.interrupt_active {
        if let Ok(db_p) = s.auth.db_jobs.clone().try_acquire_owned() {
            let db_c = s.auth.db.clone();
            let conv_c = conversation.clone();
            let org_c = actor.organization.clone();
            let own_c = actor.id.clone();
            let msg_c = input.id.clone();
            let key_c = key.clone();
            let fp_c = fingerprint.clone();
            let pre = tokio::task::spawn_blocking(move || {
                let _p = db_p;
                db_c.try_with_connection(|c| {
                    let exists: bool = c.query_row(
                        "SELECT EXISTS(SELECT 1 FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0)",
                        params![conv_c, org_c, own_c],
                        |r| r.get(0),
                    )?;
                    if !exists {
                        return Ok(json!({"status":"skip"}));
                    }
                    match existing(c, &own_c, &conv_c, &msg_c, &key_c, &fp_c)? {
                        Existing::Replay => return Ok(json!({"status":"replay"})),
                        Existing::Conflict => return Ok(json!({"status":"conflict"})),
                        Existing::None => {}
                    }
                    let mut stmt = c.prepare(
                        "SELECT id FROM port_runs WHERE conversation_id=?1 AND status='running'",
                    )?;
                    let ids: Vec<String> = stmt
                        .query_map(params![conv_c], |r| r.get(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(json!({"status":"ok","running":ids}))
                })
            })
            .await;
            if let Ok(Ok(val)) = pre {
                match val["status"].as_str() {
                    Some("replay") => return accepted(&input.id, false),
                    Some("conflict") => {
                        return problem(StatusCode::CONFLICT, "Message or idempotency key conflict");
                    }
                    Some("ok") => {
                        if let Some(ids) = val["running"].as_array() {
                            let map = s.active.lock().unwrap_or_else(|e| e.into_inner());
                            for id_val in ids {
                                if let Some(rid) = id_val.as_str() {
                                    if let Some(token) = map.get(rid) {
                                        token.cancel();
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let permit = if input.interrupt_active {
        let mut acquired = None;
        for attempt in 0..40usize {
            match s.capacity.clone().try_acquire_owned() {
                Ok(p) => {
                    acquired = Some(p);
                    break;
                }
                Err(_) if attempt < 39 => {
                    if let Ok(db_p) = s.auth.db_jobs.clone().try_acquire_owned() {
                        let db_c = s.auth.db.clone();
                        let conv_c = conversation.clone();
                        if let Ok(Ok(ids)) = tokio::task::spawn_blocking(move || {
                            let _p = db_p;
                            db_c.try_with_connection(|c| {
                                let mut stmt = c.prepare(
                                    "SELECT id FROM port_runs WHERE conversation_id=?1 AND status='running'",
                                )?;
                                let rows = stmt
                                    .query_map(params![conv_c], |r| r.get::<_, String>(0))?
                                    .collect::<rusqlite::Result<Vec<_>>>()?;
                                Ok(rows)
                            })
                        })
                        .await
                        {
                            let map = s.active.lock().unwrap_or_else(|e| e.into_inner());
                            for rid in &ids {
                                if let Some(token) = map.get(rid) {
                                    token.cancel();
                                }
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(_) => break,
            }
        }
        match acquired {
            Some(p) => p,
            None => {
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
        }
    } else {
        match s.capacity.clone().try_acquire_owned() {
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
    let interrupt_active = input.interrupt_active;
    let active_for_cleanup = s.active.clone();
    let result=tokio::task::spawn_blocking(move||{let _p=db_permit;db.try_with_connection(|c|{
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let conv:Option<(String,String)>=tx.query_row("SELECT thread_id,bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",params![conversation_id,org_id,owner],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((thread,bot_json))=conv else{return Ok(json!({"result":"missing"}))};
        let bots:Vec<String>=serde_json::from_str(&bot_json).map_err(|_|StorageError::InvalidDatabase("invalid bot list"))?;
        if bots.is_empty(){return Ok(json!({"result":"missing"}))}
        let mut bot_names: HashMap<String, String> = HashMap::new();
        let mut bot_roles: HashMap<String, String> = HashMap::new();
        for b in &bots {
            if let Ok(Some((name, role))) = tx.query_row(
                "SELECT name, role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![b, org_id, owner],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            ).optional() {
                bot_names.insert(b.clone(), name);
                bot_roles.insert(b.clone(), role);
            }
        }
        let (turn_bots, is_broadcast, lead_orchestration) = match &bot_override {
            Some(b)=>{if !bots.contains(b){return Ok(json!({"result":"missing"}))} (vec![b.clone()], false, false)}
            None=>{
                let plan = plan_group_turn(&bots, &bot_names, &text);
                (plan.bots, plan.is_broadcast, plan.lead_orchestration)
            }
        };
        let bot_id=turn_bots[0].clone();
        let instructions:Option<String>=tx.query_row("SELECT role_description FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",params![bot_id,org_id,owner],|r|r.get(0)).optional()?;
        let Some(instructions)=instructions else{return Ok(json!({"result":"missing"}))};
        match existing(&tx,&owner,&conversation_id,&message_id,&key,&fingerprint)? { Existing::Replay=>return Ok(json!({"result":"replay"})), Existing::Conflict=>return Ok(json!({"result":"conflict"})), Existing::None=>{} }
        tx.execute(
            "DELETE FROM port_metadata WHERE key=?1",
            params![format!("conversation_replay_gap:{conversation_id}")],
        )?;
        let running_ids: Vec<String> = {
            let mut stmt = tx.prepare("SELECT id FROM port_runs WHERE conversation_id=?1 AND status='running'")?;
            let rows = stmt
                .query_map(params![conversation_id], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            rows
        };
        if !running_ids.is_empty() {
            let can_clear = interrupt_active || {
                let map = active_for_cleanup.lock().unwrap_or_else(|e| e.into_inner());
                running_ids.iter().all(|rid| !map.contains_key(rid))
            };
            if can_clear {
                tx.execute(
                    "UPDATE port_runs SET status='failed' WHERE conversation_id=?1 AND status='running'",
                    params![conversation_id],
                )?;
                tx.execute(
                    "UPDATE port_conversation_messages SET status='failed' WHERE conversation_id=?1 AND status IN ('running', 'queued')",
                    params![conversation_id],
                )?;
                let mut map = active_for_cleanup.lock().unwrap_or_else(|e| e.into_inner());
                for rid in &running_ids {
                    if let Some(tok) = map.remove(rid) {
                        tok.cancel();
                    }
                }
            } else {
                return Ok(json!({"result":"busy"}));
            }
        }
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
        let messages = if bots.len() > 1 {
            let self_name = bot_names.get(&bot_id).map(String::as_str).unwrap_or(&bot_id);
            let team = bots
                .iter()
                .map(|b| bot_names.get(b).map(String::as_str).unwrap_or(b.as_str()))
                .collect::<Vec<_>>()
                .join(", ");
            let sys = if lead_orchestration {
                let mut roster = Vec::new();
                for b in &bots {
                    if b == &bot_id {
                        continue;
                    }
                    if let Some(name) = bot_names.get(b) {
                        let desc = bot_roles
                            .get(b)
                            .map(|r| r.split_whitespace().collect::<Vec<_>>().join(" "))
                            .filter(|s| !s.is_empty())
                            .map(|s| clip_chars(&s, 160))
                            .unwrap_or_else(|| "General teammate".to_owned());
                        roster.push(format!("- {name}: {desc}"));
                    }
                }
                let roster_block = if roster.is_empty() {
                    "- (no other teammates)".to_owned()
                } else {
                    roster.join("\n")
                };
                format!(
                    "You are {self_name}, the team lead in a group conversation with: {team}.\n{instructions}\n\n\
                     TEAM ROSTER (specialists you can delegate to):\n{roster_block}\n\n\
                     ROUTING RULES:\n\
                     - If a specialist (or multiple specialists) in the team owns the request, do NOT answer or solve the task yourself! Output ONLY a short handoff line naming them, e.g.:\n  \
                       Doing it — passing this to <ExactBotName>.\n  \
                       or for multiple specialists:\n  \
                       Passing this to <BotA> and <BotB>.\n  \
                       Only the teammate(s) you name will handle it.\n\
                     - Only answer directly yourself if it is a general question/task for {self_name} or no specialist fits (in which case no other bots will be called).\n\
                     Respond as {self_name} following the routing rules above."
                )
            } else if is_broadcast {
                format!(
                    "You are {self_name} in a multi-bot group conversation with: {team}.\n{instructions}\n\n\
                     IMPORTANT GROUP RULE: Only reply if your specialty/role genuinely adds value or was requested. If another teammate already answered adequately or this message isn't for you, output literally [PASS] and nothing else.\n\
                     Respond as {self_name} if relevant to your role, or reply literally with [PASS]."
                )
            } else {
                format!(
                    "You are {self_name} in a group conversation with: {team}.\n{instructions}\n\n\
                     You were addressed directly for this turn. Respond directly as {self_name} without outputting [PASS]."
                )
            };
            let transcript = build_group_transcript(
                &tx,
                &conversation_id,
                &org_id,
                Some(&bot_names),
                900,
                1800,
                400,
            )?;
            let user_prompt = transcript.trim_end().to_owned();
            vec![
                json!({"role":"system","content":sys}),
                json!({"role":"user","content":user_prompt}),
            ]
        } else {
            build_dm_messages(&tx, &conversation_id, &bot_id, &instructions, true)?
        };
        let mut prequeued_extra: Vec<(String, String)> = Vec::new();
        if !lead_orchestration && turn_bots.len() > 1 {
            for extra_bot in &turn_bots[1..] {
                let qid = format!("assistant_{}", random_id()?);
                tx.execute(
                    "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','queued',?5)",
                    params![qid, conversation_id, owner, extra_bot, timestamp],
                )?;
                prequeued_extra.push((extra_bot.clone(), qid));
            }
        }
        let stage_bots = if lead_orchestration {
            bots.clone()
        } else {
            turn_bots.clone()
        };
        tx.commit()?;
        Ok(json!({
            "result":"started",
            "thread":thread,
            "run":run,
            "reply":reply,
            "bot":bot_id,
            "prequeuedExtra": prequeued_extra,
            "groupBots":bots,
            "botNames":bot_names,
            "leadOrchestration":lead_orchestration,
            "isBroadcast":is_broadcast,
            "stageBots":stage_bots,
            "messages":messages,
            "stagedFiles": attached_files.into_iter().map(|(name, _, _, data, _)| (name, data)).collect::<Vec<_>>()
        }))
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
            let target_bots: Vec<String> = data
                .get("stageBots")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                .unwrap_or_else(|| vec![data["bot"].as_str().unwrap_or("").to_owned()]);
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
    let prequeued_extra: Vec<(String, String)> = data["prequeuedExtra"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|pair| {
                    Some((
                        pair.get(0)?.as_str()?.to_owned(),
                        pair.get(1)?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let group_bots: Vec<String> = data["groupBots"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let bot_names_map: HashMap<String, String> = data["botNames"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let lead_orchestration = data["leadOrchestration"].as_bool().unwrap_or(false);
    let is_broadcast = data["isBroadcast"].as_bool().unwrap_or(false);
    let model = s.model.clone();
    let model_id = s.model_id.clone();
    let request = json!({"model":model_id.clone(),"messages":data["messages"],"n":1});
    let cancellation = CancellationToken::new();
    let active = s.active.clone();
    let vc = s.virtual_computer.clone();
    let ctx_mgr = s.context_manager.clone();
    active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(run.clone(), cancellation.clone());
    drop(registration_guard);
    tokio::spawn(async move {
        let _permit = permit;
        let handoff_ctx = if lead_orchestration {
            Some(GroupHandoffContext::LeadDelegate {
                owner_id: owner_run.clone(),
                group_bots: group_bots.clone(),
                bot_names: bot_names_map.clone(),
                lead_bot: bot_run.clone(),
            })
        } else {
            None
        };
        let outcome = execute_with_handoff(
            s.auth.clone(),
            model.clone(),
            vc.clone(),
            ctx_mgr.clone(),
            request,
            org_run.clone(),
            owner_run.clone(),
            bot_run.clone(),
            conversation.clone(),
            thread.clone(),
            run.clone(),
            reply,
            cancellation,
            handoff_ctx,
        )
        .await;
        active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&run);
        if lead_orchestration {
            if outcome.completed && !outcome.queued_followups.is_empty() {
                run_queued_followups(
                    &s.auth,
                    &model,
                    &model_id,
                    &vc,
                    &ctx_mgr,
                    &active,
                    &org_run,
                    &owner_run,
                    &conversation,
                    &thread,
                    &outcome.queued_followups,
                )
                .await;
            }
        } else if !prequeued_extra.is_empty() {
            if outcome.completed {
                let mode = if is_broadcast {
                    GroupFollowupMode::Broadcast
                } else {
                    GroupFollowupMode::Delegated
                };
                let followups: Vec<QueuedFollowup> = prequeued_extra
                    .into_iter()
                    .map(|(bid, mid)| QueuedFollowup {
                        bot_id: bid,
                        message_id: mid,
                        mode,
                    })
                    .collect();
                run_queued_followups(
                    &s.auth,
                    &model,
                    &model_id,
                    &vc,
                    &ctx_mgr,
                    &active,
                    &org_run,
                    &owner_run,
                    &conversation,
                    &thread,
                    &followups,
                )
                .await;
            } else {
                let ids: Vec<String> = prequeued_extra.into_iter().map(|(_, mid)| mid).collect();
                cleanup_unstarted_queued_messages(&s.auth.db, &conversation, &ids).await;
            }
        }
    });
    accepted(&input.id, true)
}

const VC_TOOL_GROUNDING_PROMPT: &str = "TOOL USE RULES: You have Virtual Computer tools (computer_web_fetch, computer_read_file, computer_write_file, computer_list_files, computer_run_command). When asked to open, visit, or fetch a URL or website, you MUST invoke computer_web_fetch with a full https:// URL. When asked to read, write, list, or run workspace files or commands, you MUST invoke the corresponding workspace tool. For computer_write_file, keep each file concise or write large files in smaller chunks using append: true so tool arguments do not hit the output/context limit. NEVER write fake '[Tool call: ...]', '(History: ...)', or 'Status: 200 OK' text instead of calling a tool; invoke the real function tool call via tool_calls. NEVER claim you opened, fetched, read, wrote, or ran anything without an actual successful tool call in this conversation; if a tool fails or is denied, report the exact error or denial.";

fn append_vc_tool_grounding(request: &mut Value) {
    if let Some(msgs) = request.get_mut("messages").and_then(Value::as_array_mut) {
        if let Some(sys) = msgs
            .first_mut()
            .filter(|m| m.get("role").and_then(Value::as_str) == Some("system"))
        {
            if let Some(prev) = sys.get("content").and_then(Value::as_str) {
                if !prev.contains("TOOL USE RULES:") {
                    sys["content"] = Value::String(format!("{prev}\n\n{VC_TOOL_GROUNDING_PROMPT}"));
                }
            }
        }
    }
}

async fn apply_model_choice(
    auth: &AuthState,
    org: &str,
    owner: &str,
    conversation: &str,
    current_request: &mut Value,
) {
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
                let api_eff = if eff == "off" { "none" } else { eff };
                current_request["reasoning_effort"] = Value::String(api_eff.to_owned());
                if eff == "off" || eff == "none" {
                    current_request["chat_template_kwargs"] = json!({"enable_thinking": false});
                }
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
                    if let Some(sys) = msgs
                        .first_mut()
                        .filter(|m| m.get("role").and_then(Value::as_str) == Some("system"))
                    {
                        if let Some(prev) = sys.get("content").and_then(Value::as_str) {
                            sys["content"] = Value::String(format!("{prev}\n{hint}"));
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct QueuedFollowup {
    bot_id: String,
    message_id: String,
    mode: GroupFollowupMode,
}

#[derive(Clone)]
enum GroupHandoffContext {
    LeadDelegate {
        owner_id: String,
        group_bots: Vec<String>,
        bot_names: HashMap<String, String>,
        lead_bot: String,
    },
    PreplannedFollowups {
        owner_id: String,
        followups: Vec<(String, GroupFollowupMode)>,
    },
}

struct RunOutcome {
    completed: bool,
    queued_followups: Vec<QueuedFollowup>,
}

async fn cleanup_unstarted_queued_messages(
    db: &Arc<Storage>,
    conversation_id: &str,
    message_ids: &[String],
) {
    if message_ids.is_empty() {
        return;
    }
    let db_c = db.clone();
    let conv_c = conversation_id.to_owned();
    let ids = message_ids.to_vec();
    let _ = tokio::task::spawn_blocking(move || {
        db_c.try_with_connection(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for mid in ids {
                tx.execute(
                    "DELETE FROM port_conversation_messages WHERE conversation_id=?1 AND id=?2 AND status='queued'",
                    params![conv_c, mid],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
    })
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_queued_followups(
    auth: &AuthState,
    model: &ModelClient,
    model_id: &str,
    vc: &Option<virtual_computer::VirtualComputerState>,
    context_manager: &context_manager::ContextManager,
    active: &Arc<Mutex<HashMap<String, CancellationToken>>>,
    org: &str,
    owner: &str,
    conversation: &str,
    thread: &str,
    followups: &[QueuedFollowup],
) {
    for (idx, item) in followups.iter().enumerate() {
        let ok = execute_followup_group_bot(
            auth,
            model,
            model_id,
            vc,
            context_manager,
            active,
            org,
            owner,
            &item.bot_id,
            conversation,
            thread,
            item.mode,
            Some(&item.message_id),
        )
        .await;
        if !ok {
            let remaining: Vec<String> = followups[idx + 1..]
                .iter()
                .map(|f| f.message_id.clone())
                .collect();
            cleanup_unstarted_queued_messages(&auth.db, conversation, &remaining).await;
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    auth: AuthState,
    model: ModelClient,
    vc: Option<virtual_computer::VirtualComputerState>,
    context_manager: context_manager::ContextManager,
    request: Value,
    org: String,
    owner: String,
    bot: String,
    conversation: String,
    thread: String,
    run: String,
    reply: String,
    external_cancel: CancellationToken,
) -> RunOutcome {
    execute_with_handoff(
        auth,
        model,
        vc,
        context_manager,
        request,
        org,
        owner,
        bot,
        conversation,
        thread,
        run,
        reply,
        external_cancel,
        None,
    )
    .await
}

fn merge_compaction(
    acc: &mut Option<context_manager::CompactionResult>,
    next: context_manager::CompactionResult,
) {
    if !next.compacted {
        return;
    }
    match acc {
        Some(existing) => {
            existing.after_tokens = next.after_tokens;
            existing.dropped_turns = existing.dropped_turns.saturating_add(next.dropped_turns);
            existing.summarized_messages = existing
                .summarized_messages
                .saturating_add(next.summarized_messages);
        }
        None => *acc = Some(next),
    }
}

async fn preflight_compact_and_record(
    context: &context_manager::ContextManager,
    conversation: &str,
    request: &mut Value,
    run_compaction: &mut Option<context_manager::CompactionResult>,
) {
    let (compaction, _server) = context.preflight_compact(request).await;
    merge_compaction(run_compaction, compaction);
    let breakdown = context_manager::estimate_request_tokens(request);
    context.record_conversation_state(conversation, breakdown, run_compaction.as_ref());
}

fn record_oom_compaction(
    context: &context_manager::ContextManager,
    conversation: &str,
    before_tokens: u64,
    request: &Value,
    run_compaction: &mut Option<context_manager::CompactionResult>,
) {
    let breakdown = context_manager::estimate_request_tokens(request);
    let oom_compaction = context_manager::CompactionResult {
        compacted: true,
        before_tokens,
        after_tokens: breakdown.total_tokens,
        threshold_tokens: before_tokens,
        context_limit: before_tokens,
        dropped_turns: 1,
        summarized_messages: 1,
    };
    merge_compaction(run_compaction, oom_compaction);
    context.record_conversation_state(conversation, breakdown, run_compaction.as_ref());
}

#[allow(clippy::too_many_arguments)]
async fn execute_with_handoff(
    auth: AuthState,
    model: ModelClient,
    vc: Option<virtual_computer::VirtualComputerState>,
    context_manager: context_manager::ContextManager,
    request: Value,
    org: String,
    owner: String,
    bot: String,
    conversation: String,
    thread: String,
    run: String,
    reply: String,
    external_cancel: CancellationToken,
    handoff_ctx: Option<GroupHandoffContext>,
) -> RunOutcome {
    let cancel = external_cancel.child_token();
    let mut current_request = request;
    let configured_model = current_request
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_owned();
    if vc.is_some() {
        append_vc_tool_grounding(&mut current_request);
    }
    apply_model_choice(&auth, &org, &owner, &conversation, &mut current_request).await;
    let selected_model = current_request
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if configured_model == "auto" || selected_model.is_empty() || selected_model == "auto" {
        if let Err(reason) = resolve_active_model(&model, &mut current_request, &cancel).await {
            return finalize_run(
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
                handoff_ctx.as_ref(),
            )
            .await;
        }
    }

    if vc.is_none() {
        let mut answer = String::new();
        let mut failed = false;
        let mut failure_detail: Option<String> = None;
        let mut terminal = None;
        let mut emitted_run_started = false;
        let mut emitted_text_start = false;
        let mut run_compaction: Option<context_manager::CompactionResult> = None;
        preflight_compact_and_record(
            &context_manager,
            &conversation,
            &mut current_request,
            &mut run_compaction,
        )
        .await;

        for attempt in 0..2usize {
            let producer_cancel = cancel.clone();
            let (tx, mut rx) = mpsc::channel(16);
            let t = thread.clone();
            let r = run.clone();
            let m = reply.clone();
            let req_clone = current_request.clone();
            let model_clone = model.clone();
            let task = tokio::spawn(async move {
                run_engine::stream_text(model_clone, req_clone, &t, &r, &m, tx, producer_cancel)
                    .await
            });
            let mut emitted_content_this_attempt = false;
            failed = false;
            failure_detail = None;
            terminal = None;

            while let Some(event) = rx.recv().await {
                let etype = event.get("type").and_then(Value::as_str);
                if etype == Some("RUN_STARTED") {
                    if emitted_run_started {
                        continue;
                    }
                    emitted_run_started = true;
                } else if etype == Some("TEXT_MESSAGE_START") {
                    if emitted_text_start {
                        continue;
                    }
                    emitted_text_start = true;
                } else if etype == Some("RUN_FINISHED") {
                    terminal = Some(event);
                    continue;
                }
                if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                    emitted_content_this_attempt = true;
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
                Ok(Ok(())) => break,
                Ok(Err(e)) => {
                    if attempt == 0
                        && !failed
                        && !emitted_content_this_attempt
                        && !cancel.is_cancelled()
                        && e.is_oom_or_context_error()
                    {
                        let before_tokens =
                            context_manager::estimate_request_tokens(&current_request).total_tokens;
                        compact_request_for_oom(&mut current_request);
                        record_oom_compaction(
                            &context_manager,
                            &conversation,
                            before_tokens,
                            &current_request,
                            &mut run_compaction,
                        );
                        continue;
                    }
                    failed = true;
                    failure_detail = Some(e.to_string());
                    break;
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        if external_cancel.is_cancelled() || terminal.is_none() {
            failed = true;
        }
        return finalize_run(
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
            handoff_ctx.as_ref(),
        )
        .await;
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
            &context_manager,
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
            &[],
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
        handoff_ctx.as_ref(),
    )
    .await
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

fn compact_tools_schema() -> Value {
    json!([
        {"type":"function","function":{"name":"computer_read_file","description":"Read file","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}},
        {"type":"function","function":{"name":"computer_list_files","description":"List dir","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}},
        {"type":"function","function":{"name":"computer_write_file","description":"Write file","parameters":{"type":"object","properties":{"path":{"type":"string"},"contents":{"type":"string"},"append":{"type":"boolean"}},"required":["path","contents"]}}},
        {"type":"function","function":{"name":"computer_run_command","description":"Run cmd","parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}},
        {"type":"function","function":{"name":"computer_web_fetch","description":"Fetch URL","parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}
    ])
}

fn compact_oversized_user_content(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    if text.contains('\n') {
        let prefix = "...[earlier context compacted]\n";
        let budget = max_chars.saturating_sub(prefix.chars().count());
        let mut kept_rev: Vec<&str> = Vec::new();
        let mut used = 0usize;
        for line in text.lines().rev() {
            let line_chars = line.chars().count() + 1;
            if used + line_chars > budget {
                break;
            }
            used += line_chars;
            kept_rev.push(line);
        }
        if !kept_rev.is_empty() {
            kept_rev.reverse();
            return format!("{prefix}{}", kept_rev.join("\n"));
        }
    }
    clip_chars(text, max_chars)
}

fn trim_older_tool_outputs(request: &mut Value) {
    let Some(msgs) = request.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    let Some(last_tc_idx) = msgs
        .iter()
        .rposition(|m| m.get("role").and_then(Value::as_str) == Some("assistant") && m.get("tool_calls").is_some())
    else {
        return;
    };
    for msg in msgs[..last_tc_idx].iter_mut() {
        if msg.get("role").and_then(Value::as_str) == Some("tool") {
            if let Some(text) = msg.get("content").and_then(Value::as_str).map(str::to_owned) {
                if text.chars().count() > MAX_OLD_TOOL_RESULT_CHARS_FOR_LLM {
                    msg["content"] = Value::String(clip_chars(&text, MAX_OLD_TOOL_RESULT_CHARS_FOR_LLM));
                }
            }
        }
    }
}

pub(crate) fn compact_request_for_oom(request: &mut Value) {
    let capped_max = request
        .get("max_tokens")
        .and_then(Value::as_u64)
        .map(|v| v.min(OOM_RETRY_MAX_TOKENS))
        .unwrap_or(OOM_RETRY_MAX_TOKENS);
    request["max_tokens"] = json!(capped_max);

    if request.get("tools").is_some() {
        request["tools"] = compact_tools_schema();
    }

    let Some(msgs) = request.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };
    if msgs.is_empty() {
        return;
    }

    let has_system = msgs[0].get("role").and_then(Value::as_str) == Some("system");
    let mut compacted: Vec<Value> = Vec::with_capacity(5);
    if has_system {
        let mut sys = msgs[0].clone();
        if let Some(s) = sys.get("content").and_then(Value::as_str).map(str::to_owned) {
            if s.chars().count() > 1600 {
                sys["content"] = Value::String(clip_chars(&s, 1600));
            }
        }
        compacted.push(sys);
    }

    let tail = if has_system { &msgs[1..] } else { &msgs[..] };
    if !tail.is_empty() {
        let last_user_idx = tail
            .iter()
            .rposition(|m| m.get("role").and_then(Value::as_str) == Some("user"));
        let keep_from = match last_user_idx {
            Some(u_idx) if u_idx + 1 < tail.len() => {
                // Active tool-call turn: keep from latest user message onward (preserves tool_call/tool pairing).
                u_idx
            }
            Some(u_idx) => {
                let candidate = u_idx.saturating_sub(1);
                let two_chars: usize = tail[candidate..]
                    .iter()
                    .filter_map(|m| m.get("content").and_then(Value::as_str))
                    .map(|s| s.chars().count())
                    .sum();
                if two_chars <= 3200 {
                    candidate
                } else {
                    u_idx
                }
            }
            None => tail.len().saturating_sub(2),
        };
        let last_kept_user_rel = tail[keep_from..]
            .iter()
            .rposition(|m| m.get("role").and_then(Value::as_str) == Some("user"));

        for (rel_idx, orig) in tail[keep_from..].iter().enumerate() {
            let mut m = orig.clone();
            let role = m.get("role").and_then(Value::as_str).unwrap_or("");
            if let Some(text) = m.get("content").and_then(Value::as_str).map(str::to_owned) {
                let clipped = match role {
                    "tool" => clip_chars(&text, 1024),
                    "assistant" => clip_chars(&text, 600),
                    "user" if Some(rel_idx) == last_kept_user_rel => {
                        compact_oversized_user_content(&text, 2400)
                    }
                    "user" => clip_chars(&text, 600),
                    _ => clip_chars(&text, 800),
                };
                m["content"] = Value::String(clipped);
            }
            compacted.push(m);
        }
    }

    *msgs = compacted;
}

#[derive(Clone)]
struct ExecutedToolSummary {
    tool_name: String,
    scope: String,
    ok: bool,
    error: Option<String>,
}

fn summarize_executed_tools(tools: &[ExecutedToolSummary]) -> String {
    let start = tools.len().saturating_sub(5);
    let parts: Vec<String> = tools[start..]
        .iter()
        .map(|t| {
            let target = clip_chars(t.scope.trim(), 80);
            if t.ok {
                match t.tool_name.as_str() {
                    "computer_write_file" => format!("saved `{target}`"),
                    "computer_read_file" => format!("read `{target}`"),
                    "computer_list_files" => format!("listed `{target}`"),
                    "computer_run_command" => format!("ran `{target}`"),
                    "computer_web_fetch" | "computer_navigate" => format!("fetched `{target}`"),
                    other => format!("ran `{other}`"),
                }
            } else {
                let err = t
                    .error
                    .as_deref()
                    .map(|e| clip_chars(e.trim(), 80))
                    .unwrap_or_else(|| "failed".to_owned());
                match t.tool_name.as_str() {
                    "computer_write_file" => format!("failed to save `{target}` ({err})"),
                    "computer_read_file" => format!("failed to read `{target}` ({err})"),
                    "computer_list_files" => format!("failed to list `{target}` ({err})"),
                    "computer_run_command" => format!("command `{target}` failed ({err})"),
                    "computer_web_fetch" | "computer_navigate" => {
                        format!("failed to fetch `{target}` ({err})")
                    }
                    other => format!("`{other}` failed ({err})"),
                }
            }
        })
        .collect();
    if parts.is_empty() {
        "Done.".to_owned()
    } else {
        format!("Done — {}.", parts.join(", "))
    }
}

#[allow(clippy::too_many_arguments)]
fn looks_like_hallucinated_tool_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("[tool call:")
        || lower.contains("computer_web_fetch(")
        || lower.contains("computer_write_file(")
        || lower.contains("computer_run_command(")
        || lower.contains("computer_read_file(")
        || (lower.contains("✅ status: 200") && lower.contains("http"))
}

async fn execute_tool_rounds(
    auth: &AuthState,
    model: &ModelClient,
    vc: &virtual_computer::VirtualComputerState,
    context_manager: &context_manager::ContextManager,
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
    initial_executed: &[ExecutedToolSummary],
) -> (bool, Option<Value>, Option<String>) {
    let mut failed = false;
    let mut terminal: Option<Value> = None;
    let mut failure_detail: Option<String> = None;
    let mut oom_retried = false;
    let mut run_compaction: Option<context_manager::CompactionResult> = None;
    let mut executed_tools: Vec<ExecutedToolSummary> = initial_executed.to_vec();
    let mut round = start_round;
    while round <= 4usize {
        if cancel.is_cancelled() {
            failed = true;
            break;
        }
        if round > 0 {
            trim_older_tool_outputs(current_request);
        }
        let is_synthesis_round = round == 4usize;
        if is_synthesis_round {
            if let Some(obj) = current_request.as_object_mut() {
                obj.remove("tools");
                obj.remove("tool_choice");
            }
        } else if round > 1 {
            if let Some(obj) = current_request.as_object_mut() {
                obj.remove("tool_choice");
            }
        }
        preflight_compact_and_record(
            context_manager,
            conversation,
            current_request,
            &mut run_compaction,
        )
        .await;
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
        let mut emitted_round_output = false;
        while let Some(event) = rx.recv().await {
            emitted_round_output = true;
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
                if !oom_retried
                    && !failed
                    && !emitted_round_output
                    && !cancel.is_cancelled()
                    && e.is_oom_or_context_error()
                {
                    oom_retried = true;
                    let before_tokens =
                        context_manager::estimate_request_tokens(current_request).total_tokens;
                    compact_request_for_oom(current_request);
                    record_oom_compaction(
                        context_manager,
                        conversation,
                        before_tokens,
                        current_request,
                        &mut run_compaction,
                    );
                    continue;
                }
                failed = true;
                failure_detail = Some(e.to_string());
                break;
            }
            Err(_) => {
                failed = true;
                break;
            }
        };
        if round == 0
            && !is_synthesis_round
            && turn.tool_calls.is_empty()
            && executed_tools.is_empty()
            && looks_like_hallucinated_tool_text(&stream_deltas)
            && current_request.get("tools").is_some()
        {
            if let Some(arr) = current_request.get_mut("messages").and_then(Value::as_array_mut) {
                arr.push(json!({"role":"assistant","content":stream_deltas}));
                arr.push(json!({
                    "role":"user",
                    "content":"System correction: You wrote fake tool-call text instead of calling a tool. Do NOT write '[Tool call: ...]'. Call the real function tool right now using tool_calls."
                }));
            }
            total_answer.clear();
            current_request["tool_choice"] = json!("required");
            round += 1;
            continue;
        }
        if is_synthesis_round || turn.tool_calls.is_empty() {
            if !turn.truncated_tool_call_ids.is_empty() {
                let note = "Output reached the model's context/token limit before the tool call could finish. Please try generating it in smaller parts or chunks.";
                let note_msg_id = format!("{round_msg_id}_trunc");
                let note_text = if total_answer.is_empty() {
                    note.to_owned()
                } else {
                    format!("\n\n{note}")
                };
                if total_answer.len().saturating_add(note_text.len()) <= 1024 * 1024 {
                    let _ = append_event(
                        auth,
                        conversation,
                        json!({"type":"TEXT_MESSAGE_START","messageId":note_msg_id,"role":"assistant"}),
                        cancel,
                    )
                    .await;
                    let _ = append_event(
                        auth,
                        conversation,
                        json!({"type":"TEXT_MESSAGE_CONTENT","messageId":note_msg_id,"delta":note_text}),
                        cancel,
                    )
                    .await;
                    let _ = append_event(
                        auth,
                        conversation,
                        json!({"type":"TEXT_MESSAGE_END","messageId":note_msg_id}),
                        cancel,
                    )
                    .await;
                    total_answer.push_str(&note_text);
                }
            } else if !executed_tools.is_empty()
                && (total_answer.trim().is_empty() || is_silent_group_pass(total_answer))
            {
                let summary = summarize_executed_tools(&executed_tools);
                let summary_msg_id = format!("{round_msg_id}_summary");
                let was_empty = total_answer.trim().is_empty();
                if was_empty {
                    let _ = append_event(
                        auth,
                        conversation,
                        json!({"type":"TEXT_MESSAGE_START","messageId":summary_msg_id,"role":"assistant"}),
                        cancel,
                    )
                    .await;
                    let _ = append_event(
                        auth,
                        conversation,
                        json!({"type":"TEXT_MESSAGE_CONTENT","messageId":summary_msg_id,"delta":summary}),
                        cancel,
                    )
                    .await;
                    let _ = append_event(
                        auth,
                        conversation,
                        json!({"type":"TEXT_MESSAGE_END","messageId":summary_msg_id}),
                        cancel,
                    )
                    .await;
                }
                *total_answer = summary;
            }
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
                "computer_write_file" | "computer_run_command" | "computer_click"
                | "computer_type" | "computer_key" => "write",
                _ => "read",
            };
            let scope = approvals_api::extract_tool_scope(&args);
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
                    let allow_all_web = outcome.source == "turbo_mode";
                    let exec_res = vc
                        .execute_tool_for_owner_with_policy(
                            org,
                            owner,
                            bot,
                            &tc.name,
                            args.clone(),
                            allow_all_web,
                        )
                        .await;
                    let (tool_ok, tool_err, content_str) = match exec_res {
                        Ok(val) => {
                            let err_msg = val
                                .get("error")
                                .and_then(Value::as_str)
                                .map(str::to_owned);
                            let ok_flag = err_msg.is_none()
                                && val.get("ok").and_then(Value::as_bool) != Some(false);
                            (
                                ok_flag,
                                err_msg,
                                serde_json::to_string(&val).unwrap_or_else(|_| "{}".into()),
                            )
                        }
                        Err(err) => (false, Some(err.clone()), json!({"error": err}).to_string()),
                    };
                    executed_tools.push(ExecutedToolSummary {
                        tool_name: tc.name.clone(),
                        scope: scope.clone(),
                        ok: tool_ok,
                        error: tool_err,
                    });
                    let res_msg_id = format!("tool_{}", tc.id);
                    if let Ok(ev) = run_engine::ag_ui_tool_result(&res_msg_id, &tc.id, &content_str) {
                        if !append_event(auth, conversation, ev, cancel).await {
                            failed = true;
                            break;
                        }
                    }
                    let llm_content = clip_chars(&content_str, MAX_TOOL_RESULT_CHARS_FOR_LLM);
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
                    executed_tools.push(ExecutedToolSummary {
                        tool_name: tc.name.clone(),
                        scope: scope.clone(),
                        ok: false,
                        error: Some(outcome.reason.clone()),
                    });
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
                    let llm_content = clip_chars(&content_str, MAX_TOOL_RESULT_CHARS_FOR_LLM);
                    if let Some(arr) = current_request.get_mut("messages").and_then(Value::as_array_mut) {
                        arr.push(json!({"role":"tool","tool_call_id":tc.id,"content":llm_content}));
                    }
                }
            }
        }
        if failed || interrupted {
            break;
        }
        round += 1;
    }
    (failed, terminal, failure_detail)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupFollowupMode {
    Broadcast,
    Delegated,
    LeadClosing,
}

#[allow(clippy::too_many_arguments)]
async fn execute_followup_group_bot(
    auth: &AuthState,
    model: &ModelClient,
    model_id: &str,
    vc: &Option<virtual_computer::VirtualComputerState>,
    context_manager: &context_manager::ContextManager,
    active: &Arc<Mutex<HashMap<String, CancellationToken>>>,
    org: &str,
    owner: &str,
    bot_id: &str,
    conversation: &str,
    thread: &str,
    mode: GroupFollowupMode,
    queued_message_id: Option<&str>,
) -> bool {
    let db = auth.db.clone();
    let org_c = org.to_owned();
    let own_c = owner.to_owned();
    let bot_c = bot_id.to_owned();
    let conv_c = conversation.to_owned();
    let queued_c = queued_message_id.map(str::to_owned);
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
            let timestamp = now()?;
            let reply = if let Some(qid) = queued_c {
                let updated = tx.execute(
                    "UPDATE port_conversation_messages SET status='running', created_at=?3 WHERE conversation_id=?1 AND id=?2 AND status='queued'",
                    params![conv_c, qid, timestamp],
                )?;
                if updated == 0 {
                    tx.execute(
                        "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','running',?5)",
                        params![qid, conv_c, own_c, bot_c, timestamp],
                    )?;
                }
                qid
            } else {
                let fresh = format!("assistant_{}", random_id()?);
                tx.execute(
                    "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','running',?5)",
                    params![fresh, conv_c, own_c, bot_c, timestamp],
                )?;
                fresh
            };
            let user_msg_id = format!("group_{run}");
            let req_key = format!("group_{run}");
            tx.execute(
                "INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'running',?9)",
                params![run, conv_c, own_c, bot_c, user_msg_id, reply, req_key, vec![0u8; 32], timestamp],
            )?;
            let bot_name: String = tx
                .query_row(
                    "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                    params![bot_c, org_c, own_c],
                    |r| r.get(0),
                )
                .unwrap_or_else(|_| bot_c.clone());
            let transcript =
                build_group_transcript(&tx, &conv_c, &org_c, None, 700, 1200, 300)?;
            let sys_content = match mode {
                GroupFollowupMode::Broadcast => format!(
                    "You are {bot_name} participating in a multi-bot group conversation.\n{instructions}\n\n\
                     IMPORTANT GROUP RULE: Only reply if your specialty/role genuinely adds value or was requested. If another teammate already answered adequately or this message isn't for you, output literally [PASS] and nothing else.\n\
                     Respond as {bot_name} if relevant to your role, or reply literally with [PASS]."
                ),
                GroupFollowupMode::Delegated => format!(
                    "You are {bot_name} in a multi-bot group conversation.\n{instructions}\n\n\
                     DELEGATED TASK RULE: You were specifically delegated/requested to handle this request. Answer directly using your specialty without repeating other teammates' work, and do NOT output [PASS].\n\
                     This request was delegated to you. Respond directly as {bot_name} without adding [PASS]."
                ),
                GroupFollowupMode::LeadClosing => format!(
                    "You are {bot_name}, the team lead in a multi-bot group conversation.\n{instructions}\n\n\
                     CLOSING RULE: Your delegated teammates have finished their assigned parts. Briefly confirm that all delegated tasks are done in 1-2 short sentences without repeating their outputs. Do NOT output [PASS] and do NOT delegate again.\n\
                     Your teammates have finished their assigned parts. Briefly confirm all delegated tasks are done as {bot_name} without repeating their outputs."
                ),
            };
            let user_content = transcript.trim_end().to_owned();
            let messages = vec![
                json!({
                    "role": "system",
                    "content": sys_content
                }),
                json!({
                    "role": "user",
                    "content": user_content
                }),
            ];
            tx.commit()?;
            Ok(Some((run, reply, messages)))
        })
    })
    .await;
    let Ok(Ok(Some((run, reply, messages)))) = setup else {
        return false;
    };
    let request = json!({"model": model_id, "messages": messages, "n": 1});
    let cancel = CancellationToken::new();
    active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(run.clone(), cancel.clone());
    let outcome = execute(
        auth.clone(),
        model.clone(),
        vc.clone(),
        context_manager.clone(),
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
    outcome.completed
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
                let row: Option<(String, String, String, String, Option<String>, String, String, String, String, String)> = c
                    .query_row(
                        "SELECT bot_id, conversation_id, thread_id, run_id, tool_call_id, tool_ref, effect, scope, args_json, status
                           FROM port_approvals
                          WHERE id=?1 AND organization_id=?2 AND actor_id=?3",
                        params![app_c, org_c, act_c],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
                    )
                    .optional()?;
                Ok(row)
            })
        })
        .await;
        let Ok(Ok(Some((bot_id, conv_id, thread_id, orig_run_id, tc_id_opt, tool_ref, effect, scope, args_json, status)))) = row_res else {
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
                let db_turbo = s.auth.db.clone();
                let org_turbo = org.clone();
                let allow_turbo_web = tokio::task::spawn_blocking(move || {
                    db_turbo
                        .try_with_connection(|c| {
                            let mode: Option<String> = c
                                .query_row(
                                    "SELECT execution_mode FROM port_approval_settings WHERE organization_id=?1",
                                    params![org_turbo],
                                    |r| r.get(0),
                                )
                                .optional()?;
                            Ok(mode.as_deref() == Some("turbo"))
                        })
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false);
                match vc
                    .execute_tool_for_owner_with_policy(
                        &org,
                        &actor,
                        &bot_id,
                        &tool_ref,
                        args.clone(),
                        allow_turbo_web,
                    )
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
        let mut prep_out: Option<(String, String, Vec<Value>, Option<GroupHandoffContext>)> = None;
        for attempt in 0..40 {
            let db_r = s.auth.db.clone();
            let org_c = org.clone();
            let act_c = actor.clone();
            let bot_c = bot_id.clone();
            let conv_c = conv_id.clone();
            let orig_run_c = orig_run_id.clone();
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
                    if let Some(orig_msg_id) = tx
                        .query_row(
                            "SELECT assistant_message_id FROM port_runs WHERE id=?1 AND conversation_id=?2",
                            params![orig_run_c, conv_c],
                            |r| r.get::<_, String>(0),
                        )
                        .optional()?
                    {
                        tx.execute(
                            "UPDATE port_conversation_messages SET status='completed' WHERE conversation_id=?1 AND id=?2 AND status='waiting'",
                            params![conv_c, orig_msg_id],
                        )?;
                    }
                    let bot_json: Option<String> = tx
                        .query_row(
                            "SELECT bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",
                            params![conv_c, org_c, act_c],
                            |r| r.get(0),
                        )
                        .optional()?;
                    let bots: Vec<String> = bot_json
                        .as_deref()
                        .and_then(|raw| serde_json::from_str(raw).ok())
                        .unwrap_or_default();

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

                    let mut resume_handoff: Option<GroupHandoffContext> = None;
                    let mut messages = if bots.len() > 1 {
                        let mut bot_names: HashMap<String, String> = HashMap::new();
                        for b in &bots {
                            if let Some(name) = tx
                                .query_row(
                                    "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                                    params![b, org_c, act_c],
                                    |r| r.get::<_, String>(0),
                                )
                                .optional()?
                            {
                                bot_names.insert(b.clone(), name);
                            }
                        }
                        let self_name = bot_names.get(&bot_c).map(String::as_str).unwrap_or(&bot_c);
                        let team = bots
                            .iter()
                            .map(|b| bot_names.get(b).map(String::as_str).unwrap_or(b.as_str()))
                            .collect::<Vec<_>>()
                            .join(", ");
                        let sys = format!(
                            "You are {self_name} in a multi-bot group conversation with: {team}.\n{instructions}\n\n\
                             You are resuming after a tool permission decision. Use the tool result to continue or finish your response directly as {self_name}. Do NOT output [PASS]."
                        );
                        let transcript = build_group_transcript(
                            &tx,
                            &conv_c,
                            &org_c,
                            Some(&bot_names),
                            900,
                            1800,
                            400,
                        )?;

                        let last_person: Option<(i64, String)> = tx
                            .query_row(
                                "SELECT rowid, text FROM port_conversation_messages WHERE conversation_id=?1 AND role='person' ORDER BY rowid DESC LIMIT 1",
                                params![conv_c],
                                |r| Ok((r.get(0)?, r.get(1)?)),
                            )
                            .optional()?;
                        if let Some((person_rowid, person_text)) = last_person {
                            let lead_bot = select_lead_group_bot(&bots, &bot_names);
                            let lead_handoff_text: Option<String> = if bot_c != lead_bot {
                                tx.query_row(
                                    "SELECT text FROM port_conversation_messages WHERE conversation_id=?1 AND role='bot' AND bot_id=?2 AND rowid>?3 AND status='completed' ORDER BY rowid ASC LIMIT 1",
                                    params![conv_c, lead_bot, person_rowid],
                                    |r| r.get(0),
                                )
                                .optional()?
                            } else {
                                None
                            };
                            if let Some(lead_txt) = lead_handoff_text {
                                let targets = parse_group_handoff(&lead_txt, &bots, &bot_names, &lead_bot);
                                if let Some(pos) = targets.iter().position(|b| b == &bot_c) {
                                    let mut followups: Vec<(String, GroupFollowupMode)> = targets[pos + 1..]
                                        .iter()
                                        .map(|b| (b.clone(), GroupFollowupMode::Delegated))
                                        .collect();
                                    if targets.len() >= 2 {
                                        followups.push((lead_bot.clone(), GroupFollowupMode::LeadClosing));
                                    }
                                    if !followups.is_empty() {
                                        resume_handoff = Some(GroupHandoffContext::PreplannedFollowups {
                                            owner_id: act_c.clone(),
                                            followups,
                                        });
                                    }
                                }
                            } else {
                                let plan = plan_group_turn(&bots, &bot_names, &person_text);
                                if plan.is_broadcast || !plan.lead_orchestration {
                                    if let Some(pos) = plan.bots.iter().position(|b| b == &bot_c) {
                                        let mode = if plan.is_broadcast {
                                            GroupFollowupMode::Broadcast
                                        } else {
                                            GroupFollowupMode::Delegated
                                        };
                                        let followups: Vec<(String, GroupFollowupMode)> = plan.bots[pos + 1..]
                                            .iter()
                                            .map(|b| (b.clone(), mode))
                                            .collect();
                                        if !followups.is_empty() {
                                            resume_handoff = Some(GroupHandoffContext::PreplannedFollowups {
                                                owner_id: act_c.clone(),
                                                followups,
                                            });
                                        }
                                    }
                                } else if bot_c == lead_bot {
                                    resume_handoff = Some(GroupHandoffContext::LeadDelegate {
                                        owner_id: act_c.clone(),
                                        group_bots: bots.clone(),
                                        bot_names: bot_names.clone(),
                                        lead_bot,
                                    });
                                }
                            }
                        }

                        vec![
                            json!({"role": "system", "content": sys}),
                            json!({"role": "user", "content": transcript.trim_end()}),
                        ]
                    } else {
                        build_dm_messages(&tx, &conv_c, &bot_c, &instructions, false)?
                    };
                    messages.push(json!({
                        "role": "assistant",
                        "content": Value::Null,
                        "tool_calls": [{"id": tc_c, "type": "function", "function": {"name": tool_c, "arguments": args_str}}]
                    }));
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": tc_c,
                        "content": clip_chars(&content_c, MAX_TOOL_RESULT_CHARS_FOR_LLM)
                    }));
                    tx.commit()?;
                    Ok(Ok(Some((run, reply, messages, resume_handoff))))
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

        let Some((run, reply, messages, resume_handoff)) = prep_out else {
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
        if s.virtual_computer.is_some() {
            append_vc_tool_grounding(&mut current_request);
        }
        apply_model_choice(&s.auth, &org, &actor, &conv_id, &mut current_request).await;
        let selected_model = current_request
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        let mut model_err: Option<String> = None;
        if s.model_id == "auto" || selected_model.is_empty() || selected_model == "auto" {
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
                let initial = if was_approved {
                    vec![ExecutedToolSummary {
                        tool_name: tool_ref.clone(),
                        scope: scope.clone(),
                        ok: exec_error.is_none(),
                        error: exec_error.clone(),
                    }]
                } else {
                    Vec::new()
                };
                (failed, terminal, failure_detail) = execute_tool_rounds(
                    &s.auth,
                    &s.model,
                    vc,
                    &s.context_manager,
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
                    &initial,
                )
                .await;
            }
        }
        if cancel.is_cancelled() || terminal.is_none() {
            failed = true;
        }
        let db_done = s.auth.db.clone();
        let err_clone = exec_error;
        let org_followup = org.clone();
        let actor_followup = actor.clone();
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
        let outcome = finalize_run(
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
            resume_handoff.as_ref(),
        )
        .await;
        s.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&run);
        if outcome.completed && !outcome.queued_followups.is_empty() {
            run_queued_followups(
                &s.auth,
                &s.model,
                &s.model_id,
                &s.virtual_computer,
                &s.context_manager,
                &s.active,
                &org_followup,
                &actor_followup,
                &conv_id,
                &thread_id,
                &outcome.queued_followups,
            )
            .await;
        }
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
    handoff_ctx: Option<&GroupHandoffContext>,
) -> RunOutcome {
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
        let handoff_owned = handoff_ctx.cloned();
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
                let fits = count < event_journal::MAX_EVENTS
                    && encoded.len() <= event_journal::MAX_EVENT_BYTES
                    && total.saturating_add(encoded.len() as i64) <= event_journal::MAX_TOTAL_BYTES;
                let final_status=if failed || !fits {"failed"} else {"completed"};
                let is_interrupt = terminal_ref
                    .as_ref()
                    .and_then(|t| t.get("outcome"))
                    .and_then(|o| o.get("type"))
                    .and_then(Value::as_str)
                    == Some("interrupt");
                let msg_status = if final_status == "failed" {
                    "failed"
                } else if is_interrupt {
                    "waiting"
                } else {
                    "completed"
                };
                let silent_pass = final_status == "completed" && !is_interrupt && is_silent_group_pass(&body);
                if silent_pass {
                    tx.execute("DELETE FROM port_conversation_messages WHERE conversation_id=?1 AND id=?2", params![id, message_id])?;
                } else {
                    tx.execute("UPDATE port_conversation_messages SET text=?3,status=?4 WHERE conversation_id=?1 AND id=?2",params![id,message_id,body,msg_status])?;
                }
                tx.execute("UPDATE port_runs SET status=?2 WHERE id=?1",params![run_id,final_status])?;
                if final_status == "failed" || is_interrupt {
                    tx.execute(
                        "DELETE FROM port_conversation_messages WHERE conversation_id=?1 AND status='queued'",
                        params![id],
                    )?;
                }
                let mut queued_followups: Vec<QueuedFollowup> = Vec::new();
                if final_status == "completed" && !is_interrupt {
                    if let Some(ctx) = handoff_owned {
                        let ts_q = crate::runs::now().unwrap_or(0);
                        match ctx {
                            GroupHandoffContext::LeadDelegate { owner_id, group_bots, bot_names, lead_bot } => {
                                let targets = parse_group_handoff(&body, &group_bots, &bot_names, &lead_bot);
                                for target in &targets {
                                    let qid = format!("assistant_{}", random_id()?);
                                    tx.execute(
                                        "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','queued',?5)",
                                        params![qid, id, owner_id, target, ts_q],
                                    )?;
                                    queued_followups.push(QueuedFollowup {
                                        bot_id: target.clone(),
                                        message_id: qid,
                                        mode: GroupFollowupMode::Delegated,
                                    });
                                }
                                if targets.len() >= 2 {
                                    let qid = format!("assistant_{}", random_id()?);
                                    tx.execute(
                                        "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','queued',?5)",
                                        params![qid, id, owner_id, lead_bot, ts_q],
                                    )?;
                                    queued_followups.push(QueuedFollowup {
                                        bot_id: lead_bot,
                                        message_id: qid,
                                        mode: GroupFollowupMode::LeadClosing,
                                    });
                                }
                            }
                            GroupHandoffContext::PreplannedFollowups { owner_id, followups } => {
                                for (target, mode) in followups {
                                    let qid = format!("assistant_{}", random_id()?);
                                    tx.execute(
                                        "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,?2,'bot',?3,?4,'','queued',?5)",
                                        params![qid, id, owner_id, target, ts_q],
                                    )?;
                                    queued_followups.push(QueuedFollowup {
                                        bot_id: target,
                                        message_id: qid,
                                        mode,
                                    });
                                }
                            }
                        }
                    }
                }
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
                if fits {
                    tx.execute("INSERT INTO port_run_events(conversation_id,sequence,event_json,bytes) VALUES(?1,?2,?3,?4)",params![id,next,encoded,encoded.len() as i64])?;
                    tx.execute("DELETE FROM port_metadata WHERE key=?1", params![format!("conversation_replay_gap:{id}")])?;
                }
                else { tx.execute("INSERT INTO port_metadata(key,value) VALUES(?1,'terminal event missing because journal is full') ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![format!("conversation_replay_gap:{id}")])?; }
                tx.commit()?;
                Ok((notify_meta, final_status == "completed" && !is_interrupt, queued_followups))
            })
        }).await;
        match result {
            Ok(Ok((notify_meta, completed_ok, queued_followups))) => {
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
                return RunOutcome {
                    completed: completed_ok && !external_cancel.is_cancelled(),
                    queued_followups,
                };
            }
            Ok(Err(StorageError::Busy)) => tokio::time::sleep(Duration::from_millis(50)).await,
            _ => {
                let _ = std::io::Write::write_all(
                    &mut std::io::stderr(),
                    b"Could not finalize model run; it will be marked failed on restart\n",
                );
                return RunOutcome {
                    completed: false,
                    queued_followups: Vec::new(),
                };
            }
        }
    }
    let _ = std::io::Write::write_all(
        &mut std::io::stderr(),
        b"Could not finalize model run because storage remained busy; it will be marked failed on restart\n",
    );
    RunOutcome {
        completed: false,
        queued_followups: Vec::new(),
    }
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

    #[test]
    fn silent_group_pass_handles_prefixes_formatting_and_explanations() {
        assert!(is_silent_group_pass(""));
        assert!(is_silent_group_pass("   \n\t  "));
        assert!(is_silent_group_pass("[PASS]"));
        assert!(is_silent_group_pass("[pass]"));
        assert!(is_silent_group_pass("**[PASS]**"));
        assert!(is_silent_group_pass("`[Pass]`"));
        assert!(is_silent_group_pass("_[SILENT]_"));
        assert!(is_silent_group_pass("[PASS]\nBecause Commander already answered."));
        assert!(is_silent_group_pass("**[PASS]**\nNothing to add here."));
        assert!(is_silent_group_pass("[Pass]: already handled"));
        assert!(is_silent_group_pass("[PASS] - skipping"));
        assert!(is_silent_group_pass("[PASS]—skip"));
        assert!(is_silent_group_pass("[PASS]!"));
        assert!(is_silent_group_pass("[PASS]."));
        assert!(is_silent_group_pass("[NO_REPLY]\nNot my area."));
        assert!(is_silent_group_pass("[SILENT]: ok"));

        assert!(!is_silent_group_pass("[PASSING] all tests"));
        assert!(!is_silent_group_pass("[PASS]word"));
        assert!(!is_silent_group_pass("Here is the fix. Do not output [PASS]."));
        assert!(!is_silent_group_pass("Passing this to Programmer."));
    }

    #[test]
    fn lead_selection_and_turn_routing_eliminate_unneeded_bots() {
        let bots = vec![
            "b_prog".to_owned(),
            "b_des".to_owned(),
            "b_cmd".to_owned(),
        ];
        let mut names = HashMap::new();
        names.insert("b_prog".to_owned(), "Programmer".to_owned());
        names.insert("b_des".to_owned(), "UI Designer".to_owned());
        names.insert("b_cmd".to_owned(), "Commander".to_owned());

        assert_eq!(select_lead_group_bot(&bots, &names), "b_cmd");

        let mut coord_names = names.clone();
        coord_names.insert("b_cmd".to_owned(), "Team Coordinator".to_owned());
        assert_eq!(select_lead_group_bot(&bots, &coord_names), "b_cmd");

        let mut lead_names = names.clone();
        lead_names.insert("b_des".to_owned(), "Design Lead".to_owned());
        lead_names.insert("b_cmd".to_owned(), "Reviewer".to_owned());
        assert_eq!(select_lead_group_bot(&bots, &lead_names), "b_des");

        let mut plain_names = HashMap::new();
        plain_names.insert("b_prog".to_owned(), "Programmer".to_owned());
        plain_names.insert("b_des".to_owned(), "Designer".to_owned());
        assert_eq!(
            select_lead_group_bot(&["b_prog".to_owned(), "b_des".to_owned()], &plain_names),
            "b_prog"
        );

        // Unaddressed user message -> ONLY lead bot
        assert_eq!(
            select_group_turn_bots(&bots, &names, "Build a login endpoint"),
            vec!["b_cmd"]
        );
        // Explicit name mention -> ONLY mentioned bot(s)
        assert_eq!(
            select_group_turn_bots(&bots, &names, "Hey Programmer, refactor this"),
            vec!["b_prog"]
        );
        assert_eq!(
            select_group_turn_bots(&bots, &names, "Programmer and UI Designer please align"),
            vec!["b_prog", "b_des"]
        );
        // Explicit broadcast -> all bots in order
        assert_eq!(
            select_group_turn_bots(&bots, &names, "@all please introduce yourselves"),
            bots
        );
        assert_eq!(
            select_group_turn_bots(&bots, &names, "Hey everyone, status check"),
            bots
        );
        assert_eq!(
            select_group_turn_bots(&bots, &names, "All bots chime in"),
            bots
        );
        // Single bot group -> returns that single bot
        assert_eq!(
            select_group_turn_bots(&["b_prog".to_owned()], &names, "Hello"),
            vec!["b_prog"]
        );
    }

    #[test]
    fn parse_group_handoff_detects_zero_one_and_multiple_targets_without_false_positives() {
        let bots = vec![
            "b_cmd".to_owned(),
            "b_dev".to_owned(),
            "b_bdev".to_owned(),
            "b_des".to_owned(),
            "b_qa".to_owned(),
        ];
        let mut names = HashMap::new();
        names.insert("b_cmd".to_owned(), "Commander".to_owned());
        names.insert("b_dev".to_owned(), "Dev".to_owned());
        names.insert("b_bdev".to_owned(), "Backend Dev".to_owned());
        names.insert("b_des".to_owned(), "Designer".to_owned());
        names.insert("b_qa".to_owned(), "QA".to_owned());

        // 0 targets: direct answers & non-handoff mentions
        assert!(parse_group_handoff("The capital of France is Paris.", &bots, &names, "b_cmd").is_empty());
        assert!(parse_group_handoff(
            "Here is the answer. Note that Backend Dev does not need to run.",
            &bots,
            &names,
            "b_cmd"
        ).is_empty());
        assert!(parse_group_handoff(
            "Avoid routing this to the wrong port. Also Designer already knows.",
            &bots,
            &names,
            "b_cmd"
        ).is_empty());
        assert!(parse_group_handoff(
            "Passing this to Commander directly.",
            &bots,
            &names,
            "b_cmd"
        ).is_empty());

        // 1 target (and longest-match prevents "Backend Dev" from also matching "Dev")
        assert_eq!(
            parse_group_handoff(
                "Doing it — passing this to Backend Dev.",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_bdev"]
        );
        assert_eq!(
            parse_group_handoff("Handing it off to @Designer!", &bots, &names, "b_cmd"),
            vec!["b_des"]
        );

        // 2+ targets in mention order, deduped, across multiple directive variants
        assert_eq!(
            parse_group_handoff(
                "Passing this to Designer and Backend Dev.",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_des", "b_bdev"]
        );
        assert_eq!(
            parse_group_handoff(
                "Delegating to QA, Backend Dev, and QA.",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_qa", "b_bdev"]
        );
        assert_eq!(
            parse_group_handoff(
                "Routing this to:\n- Designer\n- Dev",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_des", "b_dev"]
        );
        assert_eq!(
            parse_group_handoff(
                "Assigning this to Backend Dev. Handing off to QA.",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_bdev", "b_qa"]
        );
    }

    #[test]
    fn parse_group_handoff_supports_non_ing_verbs_and_numbered_lists() {
        let bots = vec![
            "b_cmd".to_owned(),
            "b_prog".to_owned(),
            "b_des".to_owned(),
            "b_bdev".to_owned(),
            "b_ideas".to_owned(),
            "b_prompt".to_owned(),
        ];
        let mut names = HashMap::new();
        names.insert("b_cmd".to_owned(), "Commander".to_owned());
        names.insert("b_prog".to_owned(), "Programmer Home".to_owned());
        names.insert("b_des".to_owned(), "Designer".to_owned());
        names.insert("b_bdev".to_owned(), "Backend Dev".to_owned());
        names.insert("b_ideas".to_owned(), "Ideas Home".to_owned());
        names.insert("b_prompt".to_owned(), "Prompter Home".to_owned());

        // Non-ing (base & past) verb forms
        assert_eq!(
            parse_group_handoff(
                "I'll pass this to Programmer Home.",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_prog"]
        );
        assert_eq!(
            parse_group_handoff("Pass it to Designer.", &bots, &names, "b_cmd"),
            vec!["b_des"]
        );
        assert_eq!(
            parse_group_handoff("Passed to Backend Dev.", &bots, &names, "b_cmd"),
            vec!["b_bdev"]
        );
        assert_eq!(
            parse_group_handoff("Hand this off to Designer.", &bots, &names, "b_cmd"),
            vec!["b_des"]
        );
        assert_eq!(
            parse_group_handoff("Handed off to Backend Dev.", &bots, &names, "b_cmd"),
            vec!["b_bdev"]
        );
        assert_eq!(
            parse_group_handoff("Delegate to Ideas Home.", &bots, &names, "b_cmd"),
            vec!["b_ideas"]
        );
        assert_eq!(
            parse_group_handoff("Delegated this to Prompter Home.", &bots, &names, "b_cmd"),
            vec!["b_prompt"]
        );
        assert_eq!(
            parse_group_handoff("Route to Backend Dev.", &bots, &names, "b_cmd"),
            vec!["b_bdev"]
        );
        assert_eq!(
            parse_group_handoff("Routed it to Designer.", &bots, &names, "b_cmd"),
            vec!["b_des"]
        );
        assert_eq!(
            parse_group_handoff("Assign to Programmer Home.", &bots, &names, "b_cmd"),
            vec!["b_prog"]
        );
        assert_eq!(
            parse_group_handoff("Assigned this to Ideas Home.", &bots, &names, "b_cmd"),
            vec!["b_ideas"]
        );

        // Numbered lists (with and without trailing commentary)
        assert_eq!(
            parse_group_handoff(
                "Passing this to:\n1. Designer\n2. Backend Dev",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_des", "b_bdev"]
        );
        assert_eq!(
            parse_group_handoff(
                "Passing this to:\n1. Ideas Home\n2. Prompter Home\n\nDesigner does not need to reply.",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_ideas", "b_prompt"]
        );
        assert_eq!(
            parse_group_handoff(
                "Delegate to\n1. Designer\n2. Backend Dev",
                &bots,
                &names,
                "b_cmd"
            ),
            vec!["b_des", "b_bdev"]
        );
    }

    #[tokio::test]
    async fn group_orchestration_end_to_end_direct_single_multi_mention_and_broadcast() {
        use crate::{bots, conversations};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn read_http_body(socket: &mut tokio::net::TcpStream) -> String {
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let mut header_end = None;
            let mut content_len = 0usize;
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if header_end.is_none() {
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let headers_str = String::from_utf8_lossy(&raw[..pos]);
                        for line in headers_str.lines() {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    content_len = v.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
                if let Some(h_end) = header_end {
                    if raw.len() >= h_end + content_len {
                        let body = &raw[h_end..h_end + content_len];
                        return String::from_utf8_lossy(body).into_owned();
                    }
                }
            }
            String::new()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured_requests = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured_ref = captured_requests.clone();
        let mock = tokio::spawn(async move {
            // Expected total model calls across the 5 scenarios:
            // 1. Direct answer (Commander): 1 call
            // 2. Single delegation (Commander -> Programmer): 2 calls
            // 3. Multi delegation (Commander -> Programmer -> Designer -> Commander closing): 4 calls
            // 4. Explicit mention ("Programmer, ..."): 1 call
            // 5. @all broadcast (4 bots): 4 calls
            // Total: 12 calls
            let replies = [
                "Direct Commander answer: 42.",
                "Doing it — passing this to Programmer.",
                "Implemented the Rust handler.",
                "Passing this to Programmer and Designer.",
                "Backend API done.",
                "UI mockup done.",
                "All delegated tasks are complete.",
                "Programmer direct reply with context.",
                "Commander broadcast reply.",
                "[PASS]\nBecause Commander already answered.",
                "Designer broadcast reply.",
                "[NO_REPLY]\nNot needed.",
            ];
            for answer in replies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let body_str = read_http_body(&mut socket).await;
                let req_json: Value = serde_json::from_str(&body_str).unwrap_or(Value::Null);
                captured_ref
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(req_json);
                let sse = format!(
                    "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}},\"finish_reason\":null}}]}}\n\ndata: {{\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\ndata: [DONE]\n\n",
                    json!(answer)
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse.len(),
                    sse
                );
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let path = std::env::temp_dir().join(format!("openbot-group-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let run = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap();
        let app = local_auth::router(auth.clone())
            .merge(bots::router(auth.clone()))
            .merge(conversations::router(auth))
            .merge(router(run));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let setup_res = app.clone().oneshot(setup).await.unwrap();
        assert_eq!(setup_res.status(), StatusCode::NO_CONTENT);
        let cookie = setup_res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let make_req = |method: &str, uri: &str, key: &str, body: String| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("cookie", &cookie)
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body))
                .unwrap()
        };

        let mut bot_ids = Vec::new();
        for (idx, (name, role)) in [
            ("Programmer", "Writes Rust backend code"),
            ("Commander", "Leads the team and routes tasks"),
            ("Designer", "Designs UI and UX"),
            ("QA", "Tests edge cases"),
        ]
        .into_iter()
        .enumerate()
        {
            let res = app
                .clone()
                .oneshot(make_req(
                    "POST",
                    "/api/v2/organizations/default/bots",
                    &format!("bot-{idx}"),
                    json!({"name": name, "title": "", "roleDescription": role, "visibility": "private"}).to_string(),
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::CREATED);
            let v: Value =
                serde_json::from_slice(&to_bytes(res.into_body(), 16384).await.unwrap()).unwrap();
            bot_ids.push(v["bot"]["id"].as_str().unwrap().to_owned());
        }
        let (prog_id, cmd_id, des_id, _qa_id) = (
            bot_ids[0].clone(),
            bot_ids[1].clone(),
            bot_ids[2].clone(),
            bot_ids[3].clone(),
        );

        let conv_res = app
            .clone()
            .oneshot(make_req(
                "POST",
                "/api/v2/organizations/default/conversations",
                "conv-grp",
                json!({"botIds": bot_ids, "group": true}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(conv_res.status(), StatusCode::CREATED);
        let conv_v: Value =
            serde_json::from_slice(&to_bytes(conv_res.into_body(), 16384).await.unwrap()).unwrap();
        let conv_id = conv_v["conversation"]["id"].as_str().unwrap().to_owned();
        let messages_uri = format!("/api/v2/organizations/default/conversations/{conv_id}/messages");

        let wait_idle = |expected_runs: i64| {
            let db = db.clone();
            let conv_id = conv_id.clone();
            async move {
                for _ in 0..200 {
                    let (running, total) = db
                        .try_with_connection(|c| {
                            let running: i64 = c.query_row(
                                "SELECT COUNT(*) FROM port_runs WHERE conversation_id=?1 AND status='running'",
                                params![conv_id],
                                |r| r.get(0),
                            )?;
                            let total: i64 = c.query_row(
                                "SELECT COUNT(*) FROM port_runs WHERE conversation_id=?1",
                                params![conv_id],
                                |r| r.get(0),
                            )?;
                            Ok((running, total))
                        })
                        .unwrap();
                    if running == 0 && total >= expected_runs {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                panic!("timed out waiting for {expected_runs} completed runs");
            }
        };

        // 1. Direct answer by Commander (0 targets) -> 1 run total
        let r1 = app
            .clone()
            .oneshot(make_req(
                "POST",
                &messages_uri,
                "k1",
                json!({"id":"m1","text":"What is the meaning of life?"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::ACCEPTED);
        wait_idle(1).await;

        // 2. Single-agent delegation (Commander -> Programmer, NO closing turn) -> +2 = 3 runs total
        let r2 = app
            .clone()
            .oneshot(make_req(
                "POST",
                &messages_uri,
                "k2",
                json!({"id":"m2","text":"Write a Rust function"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::ACCEPTED);
        wait_idle(3).await;

        // 3. Multi-agent delegation (Commander -> Programmer -> Designer -> Commander closing) -> +4 = 7 runs total
        let r3 = app
            .clone()
            .oneshot(make_req(
                "POST",
                &messages_uri,
                "k3",
                json!({"id":"m3","text":"Build the backend and UI"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(r3.status(), StatusCode::ACCEPTED);
        wait_idle(7).await;

        // 4. Explicit name mention ("Programmer, ...") -> +1 = 8 runs total
        let r4 = app
            .clone()
            .oneshot(make_req(
                "POST",
                &messages_uri,
                "k4",
                json!({"id":"m4","text":"Programmer, summarize your API"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(r4.status(), StatusCode::ACCEPTED);
        wait_idle(8).await;

        // 5. Explicit @all broadcast -> +4 = 12 runs total (2 bots emit [PASS]/[NO_REPLY] with explanations)
        let r5 = app
            .clone()
            .oneshot(make_req(
                "POST",
                &messages_uri,
                "k5",
                json!({"id":"m5","text":"@all quick status?"}).to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(r5.status(), StatusCode::ACCEPTED);
        wait_idle(12).await;

        // Small pause so the final spawned task drops/finishes before asserting
        mock.await.unwrap();

        // Verify exact sequence of bot_ids executed in port_runs
        let run_bots: Vec<String> = db
            .try_with_connection(|c| {
                let mut st = c.prepare("SELECT bot_id FROM port_runs WHERE conversation_id=?1 ORDER BY rowid ASC")?;
                let rows = st.query_map(params![conv_id], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .unwrap();
        assert_eq!(
            run_bots,
            vec![
                cmd_id.clone(), // 1. Direct Commander
                cmd_id.clone(), prog_id.clone(), // 2. Single delegation
                cmd_id.clone(), prog_id.clone(), des_id.clone(), cmd_id.clone(), // 3. Multi delegation + closing
                prog_id.clone(), // 4. Explicit mention
                prog_id.clone(), cmd_id.clone(), des_id.clone(), _qa_id.clone(), // 5. @all broadcast in bots order
            ]
        );

        // Verify Commander's initial prompt included team roster and routing rules,
        // and Programmer's explicit mention turn received shared group transcript ([Designer]: UI mockup done.)
        let reqs = captured_requests.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(reqs.len(), 12);
        let cmd_sys = reqs[0]["messages"][0]["content"].as_str().unwrap();
        assert!(cmd_sys.contains("TEAM ROSTER"));
        assert!(cmd_sys.contains("Programmer: Writes Rust backend code"));
        let prog_mention_user = reqs[7]["messages"][1]["content"].as_str().unwrap();
        assert!(
            prog_mention_user.contains("[Designer]: UI mockup done.")
                && prog_mention_user.contains("[Commander]: All delegated tasks are complete."),
            "shared group transcript missing teammate turns: {prog_mention_user}"
        );

        // Verify GET /messages excludes [PASS]\n... and [NO_REPLY]\n... leaks
        let listed = app
            .oneshot(make_req("GET", &messages_uri, "", String::new()))
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed_v: Value =
            serde_json::from_slice(&to_bytes(listed.into_body(), 32768).await.unwrap()).unwrap();
        let texts: Vec<&str> = listed_v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["text"].as_str().unwrap())
            .collect();
        assert!(!texts.iter().any(|t| t.contains("[PASS]") || t.contains("[NO_REPLY]")));
        assert!(texts.contains(&"Direct Commander answer: 42."));
        assert!(texts.contains(&"Implemented the Rust handler."));
        assert!(texts.contains(&"All delegated tasks are complete."));
        assert!(texts.contains(&"Programmer direct reply with context."));
        assert!(texts.contains(&"Designer broadcast reply."));

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn history_builders_cap_old_messages_while_preserving_latest_user_prompt() {
        let path =
            std::env::temp_dir().join(format!("openbot-hist-cap-{}.db", random_id().unwrap()));
        let db = Storage::open(&path).unwrap();
        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO auth_users(id,email,display_name,password_hash) VALUES('u','a@b','A','x');
                 INSERT INTO auth_organizations(id,slug,name) VALUES('o','o','O');
                 INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES('b1','o','u','Commander','','help',0),('b2','o','u','Browser','','browse',0);
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES('c','o','u','t','[\"b1\",\"b2\"]','G',0);",
            )?;
            let big = "OLD_CHUNK_".repeat(300); // 3000 chars each
            for i in 0..6 {
                let role = if i % 2 == 0 { "person" } else { "bot" };
                let bot = if role == "bot" { Some("b1") } else { None };
                c.execute(
                    "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES(?1,'c',?2,'u',?3,?4,'completed',?5)",
                    params![format!("m{i}"), role, bot, format!("msg{i}:{big}"), i as i64],
                )?;
            }
            c.execute(
                "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES('m_last','c','person','u',NULL,'LATEST_USER_PROMPT: opening youtube for you !','completed',99)",
                [],
            )?;
            let transcript = build_group_transcript(c, "c", "o", None, 700, 1200, 300)?;
            assert!(
                transcript.chars().count() <= MAX_GROUP_TRANSCRIPT_CHARS,
                "group transcript exceeded cap: {}",
                transcript.chars().count()
            );
            assert!(transcript.contains("LATEST_USER_PROMPT: opening youtube for you !"));

            let dm_msgs = build_dm_messages(c, "c", "b1", "System prompt", false)?;
            let total_dm_chars: usize = dm_msgs[1..]
                .iter()
                .filter_map(|m| m.get("content").and_then(Value::as_str))
                .map(|s| s.chars().count())
                .sum();
            assert!(
                total_dm_chars <= MAX_DM_HISTORY_CHARS,
                "DM history exceeded cap: {total_dm_chars}"
            );
            assert_eq!(
                dm_msgs.last().unwrap()["content"],
                "LATEST_USER_PROMPT: opening youtube for you !"
            );
            Ok(())
        })
        .unwrap();
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn oom_bad_alloc_compacts_and_recovers_once_in_stream_text_and_tool_runs() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn read_http_body(socket: &mut tokio::net::TcpStream) -> String {
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let mut header_end = None;
            let mut content_len = 0usize;
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if header_end.is_none() {
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let headers_str = String::from_utf8_lossy(&raw[..pos]);
                        for line in headers_str.lines() {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    content_len = v.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
                if let Some(h_end) = header_end {
                    if raw.len() >= h_end + content_len {
                        let body = &raw[h_end..h_end + content_len];
                        return String::from_utf8_lossy(body).into_owned();
                    }
                }
            }
            String::new()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured_ref = captured.clone();
        let mock = tokio::spawn(async move {
            // 1. DM stream_text: OOM bad_alloc -> retry succeeds
            // 2. VC stream_turn: OOM Internal Memory / context size -> retry succeeds
            // 3. VC stream_turn: OOM bad_alloc -> retry STILL OOM -> surfaces clear PS5LM error
            let responses = [
                "data: {\"error\":{\"message\":\"decode() failed std::bad_alloc\"}}\n\ndata: [DONE]\n\n",
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Recovered DM!\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
                "data: {\"error\":{\"message\":\"Internal Memory exceeded context size\"}}\n\ndata: [DONE]\n\n",
                "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Recovered tool turn!\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
                "data: {\"error\":{\"message\":\"decode() failed std::bad_alloc\"}}\n\ndata: [DONE]\n\n",
                "data: {\"error\":{\"message\":\"decode() failed std::bad_alloc\"}}\n\ndata: [DONE]\n\n",
            ];
            for sse in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let body_str = read_http_body(&mut socket).await;
                let req_json: Value = serde_json::from_str(&body_str).unwrap_or(Value::Null);
                captured_ref
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(req_json);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse.len(),
                    sse
                );
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let path = std::env::temp_dir().join(format!("openbot-oom-retry-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let ws_root = std::env::temp_dir().join(format!("openbot-oom-ws-{}", random_id().unwrap()));
        let _ = std::fs::remove_dir_all(&ws_root);
        std::fs::create_dir_all(&ws_root).unwrap();
        let vc = virtual_computer::VirtualComputerState::new(auth.clone(), ws_root.clone());

        let state_no_vc =
            RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap();
        let state_vc =
            RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into())
                .unwrap()
                .with_virtual_computer(vc);

        let app_no_vc = local_auth::router(auth.clone()).merge(router(state_no_vc));
        let app_vc = local_auth::router(auth.clone()).merge(router(state_vc));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let setup_res = app_no_vc.clone().oneshot(setup).await.unwrap();
        let cookie = setup_res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','Be helpful.',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv_dm','default',id,'t_dm','[\"bot\"]','DM',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv_vc','default',id,'t_vc','[\"bot\"]','VC',0 FROM auth_users LIMIT 1;",
            )?;
            // Seed 6 prior history messages in both conversations so compaction has work to drop
            for conv in ["conv_dm", "conv_vc"] {
                for i in 0..6 {
                    let role = if i % 2 == 0 { "person" } else { "bot" };
                    let bid = if role == "bot" { Some("bot") } else { None };
                    c.execute(
                        "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) SELECT ?1,?2,?3,id,?4,?5,'completed',?6 FROM auth_users LIMIT 1",
                        params![format!("{conv}_old_{i}"), conv, role, bid, format!("History_{i}_{}", "x".repeat(400)), i as i64],
                    )?;
                }
            }
            Ok(())
        })
        .unwrap();

        let send_msg = |app: Router, conv: &str, id: &str, key: &str, text: &str| {
            let uri = format!("/api/v2/organizations/default/conversations/{conv}/messages");
            let req = Request::builder()
                .method("POST")
                .uri(uri)
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(json!({"id":id,"text":text,"botId":"bot"}).to_string()))
                .unwrap();
            async move { app.oneshot(req).await.unwrap() }
        };

        let wait_run = |msg_id: &str| {
            let db = db.clone();
            let msg_id = msg_id.to_owned();
            async move {
                for _ in 0..120 {
                    if let Ok(status) = db.try_with_connection(|c| {
                        Ok(c.query_row(
                            "SELECT status FROM port_runs WHERE user_message_id=?1",
                            params![msg_id],
                            |r| r.get::<_, String>(0),
                        )?)
                    }) {
                        if status == "completed" || status == "failed" {
                            return status;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                panic!("timed out waiting for run {msg_id}");
            }
        };

        // 1. stream_text OOM recovery
        assert_eq!(
            send_msg(app_no_vc, "conv_dm", "dm_1", "k_dm_1", "opening youtube for you !").await.status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(wait_run("dm_1").await, "completed");
        let dm_events = event_journal::replay(&db, "conv_dm", None, 128).unwrap();
        assert_eq!(dm_events.iter().filter(|e| e["type"] == "RUN_STARTED").count(), 1);
        assert_eq!(dm_events.iter().filter(|e| e["type"] == "TEXT_MESSAGE_START").count(), 1);
        assert!(dm_events.iter().any(|e| e["type"] == "TEXT_MESSAGE_CONTENT" && e["delta"] == "Recovered DM!"));
        assert_eq!(dm_events.last().unwrap()["type"], "RUN_FINISHED");

        // 2. stream_turn (VC) OOM recovery
        assert_eq!(
            send_msg(app_vc.clone(), "conv_vc", "vc_1", "k_vc_1", "opening youtube for you !").await.status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(wait_run("vc_1").await, "completed");
        let vc_events = event_journal::replay(&db, "conv_vc", None, 128).unwrap();
        assert!(vc_events.iter().any(|e| e["type"] == "TEXT_MESSAGE_CONTENT" && e["delta"] == "Recovered tool turn!"));

        // 3. Persistent OOM after single retry surfaces clear PS5LM error message
        assert_eq!(
            send_msg(app_vc, "conv_vc", "vc_2", "k_vc_2", "still too huge").await.status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(wait_run("vc_2").await, "failed");
        let vc_events_after = event_journal::replay(&db, "conv_vc", None, 128).unwrap();
        let last_err = vc_events_after.last().unwrap();
        assert_eq!(last_err["type"], "RUN_ERROR");
        assert!(
            last_err["message"]
                .as_str()
                .unwrap_or("")
                .contains("PS5LM ran out of memory (std::bad_alloc)"),
            "unexpected error message: {last_err}"
        );

        mock.await.unwrap();
        let reqs = captured.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(reqs.len(), 6);
        // Attempt 1 had 8 messages (system + 6 history + latest user); Retry had <= 3 compacted messages & max_tokens 512
        assert!(reqs[0]["messages"].as_array().unwrap().len() > 3);
        assert!(reqs[1]["messages"].as_array().unwrap().len() <= 3);
        assert_eq!(reqs[1]["max_tokens"], 512);
        assert_eq!(reqs[3]["max_tokens"], 512);
        assert!(reqs[3]["messages"].as_array().unwrap().len() <= 3);

        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(ws_root);
    }

    #[test]
    fn plan_group_turn_requires_at_mention_or_explicit_addressing() {
        let bots = vec![
            "b_cmd".to_owned(),
            "b_dev".to_owned(),
            "b_qa".to_owned(),
            "b_test".to_owned(),
        ];
        let mut names = HashMap::new();
        names.insert("b_cmd".to_owned(), "Commander".to_owned());
        names.insert("b_dev".to_owned(), "Dev".to_owned());
        names.insert("b_qa".to_owned(), "QA".to_owned());
        names.insert("b_test".to_owned(), "Test".to_owned());

        // Plain words in sentence must NOT bypass Commander
        assert_eq!(select_group_turn_bots(&bots, &names, "Can you test this endpoint?"), vec!["b_cmd"]);
        assert_eq!(select_group_turn_bots(&bots, &names, "Write a dev script for me"), vec!["b_cmd"]);
        assert_eq!(select_group_turn_bots(&bots, &names, "Check QA status on staging"), vec!["b_cmd"]);
        assert_eq!(select_group_turn_bots(&bots, &names, "Test this URL right now"), vec!["b_cmd"]);
        assert_eq!(select_group_turn_bots(&bots, &names, "Dev environment is broken"), vec!["b_cmd"]);

        // Explicit @mentions and explicit vocative addressing DO target directly
        assert_eq!(select_group_turn_bots(&bots, &names, "Ask @Dev to check"), vec!["b_dev"]);
        assert_eq!(select_group_turn_bots(&bots, &names, "@QA and @Test please verify"), vec!["b_qa", "b_test"]);
        assert_eq!(select_group_turn_bots(&bots, &names, "Dev, write a script"), vec!["b_dev"]);
        assert_eq!(select_group_turn_bots(&bots, &names, "Hey QA, check this"), vec!["b_qa"]);
    }

    #[test]
    fn history_builders_include_tool_calls_and_empty_text_turns() {
        let path =
            std::env::temp_dir().join(format!("openbot-hist-tools-{}.db", random_id().unwrap()));
        let db = Storage::open(&path).unwrap();
        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO auth_users(id,email,display_name,password_hash) VALUES('u','a@b','A','x');
                 INSERT INTO auth_organizations(id,slug,name) VALUES('o','o','O');
                 INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES('b1','o','u','Commander','','help',0),('b2','o','u','Browser','','browse',0);
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES('c','o','u','t','[\"b1\",\"b2\"]','G',0);
                 INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES('u1','c','person','u',NULL,'open youtube.com','completed',1);
                 INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES('a1','c','bot','u','b2','','completed',2);
                 INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES('a2','c','bot','u','b2','','waiting',3);
                 INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES('r1','c','u','b2','u1','a1','k1',x'01','completed',2);
                 INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES('r2','c','u','b2','u2','a2','k2',x'02','completed',3);",
            )?;
            let evs = [
                json!({"type":"RUN_STARTED","threadId":"t","runId":"r1"}),
                json!({"type":"TOOL_CALL_START","toolCallId":"tc1","toolCallName":"computer_web_fetch","parentMessageId":"a1"}),
                json!({"type":"TOOL_CALL_ARGS","toolCallId":"tc1","delta":"{\"url\":\"https://www.youtube.com\"}"}),
                json!({"type":"TOOL_CALL_END","toolCallId":"tc1"}),
                json!({"type":"TOOL_CALL_RESULT","messageId":"tool_tc1","toolCallId":"tc1","role":"tool","content":"{\"error\":\"resolved IP address is forbidden by SSRF policy\"}"}),
                json!({"type":"RUN_FINISHED","threadId":"t","runId":"r1"}),
                json!({"type":"RUN_STARTED","threadId":"t","runId":"r2"}),
                json!({"type":"TOOL_CALL_START","toolCallId":"tc2","toolCallName":"computer_web_fetch","parentMessageId":"a2"}),
                json!({"type":"TOOL_CALL_ARGS","toolCallId":"tc2","delta":"{\"url\":\"https://example.com\"}"}),
                json!({"type":"TOOL_CALL_END","toolCallId":"tc2"}),
                json!({"type":"RUN_FINISHED","threadId":"t","runId":"r2","outcome":{"type":"interrupt","interrupts":[{"id":"app1","toolCallId":"tc2"}]}}),
            ];
            for (idx, ev) in evs.iter().enumerate() {
                let s = ev.to_string();
                c.execute(
                    "INSERT INTO port_run_events(conversation_id,sequence,event_json,bytes) VALUES('c',?1,?2,?3)",
                    params![(idx + 1) as i64, s, s.len() as i64],
                )?;
            }

            let transcript = build_group_transcript(c, "c", "o", None, 700, 1200, 300)?;
            assert!(
                transcript.contains("computer_web_fetch")
                    && !transcript.contains("[Tool call:")
                    && transcript.contains("ERROR: resolved IP address is forbidden by SSRF policy")
                    && transcript.contains("PAUSED (awaiting user approval)"),
                "unexpected group transcript: {transcript}"
            );

            let dm = build_dm_messages(c, "c", "b2", "System", false)?;
            let joined = dm
                .iter()
                .filter_map(|m| m.get("content").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                joined.contains("computer_web_fetch")
                    && !joined.contains("[Tool call:")
                    && joined.contains("ERROR: resolved IP address is forbidden by SSRF policy")
                    && joined.contains("PAUSED (awaiting user approval)"),
                "unexpected DM history: {joined}"
            );
            assert!(looks_like_hallucinated_tool_text(
                "Here is the page:\n[Tool call: computer_web_fetch(url=\"https://www.google.com\")] -> fetched\n✅ Status: 200 OK"
            ));
            let cleaned = sanitize_legacy_tool_text(
                "Summary below:\n[Tool call: computer_web_fetch(url=\"https://www.google.com\")]\n✅ Status: 200 OK\nActual note",
            );
            assert_eq!(cleaned, "Summary below:\nActual note");
            Ok(())
        })
        .unwrap();
        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn reasoning_off_and_vc_grounding_and_clean_user_prompts_are_sent() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured_ref = captured.clone();
        let mock = tokio::spawn(async move {
            for reply in [
                "Fetched example.com",
                "Passing this to Browser.",
                "Opened example.com in Browser.",
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let mut header_end = None;
                let mut content_len = 0usize;
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            for line in String::from_utf8_lossy(&raw[..pos]).lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(h_end) = header_end {
                        if raw.len() >= h_end + content_len {
                            let req_json: Value = serde_json::from_slice(&raw[h_end..h_end + content_len]).unwrap();
                            captured_ref.lock().unwrap().push(req_json);
                            break;
                        }
                    }
                }
                let sse = format!(
                    "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":{}}},\"finish_reason\":null}}]}}\n\ndata: {{\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\ndata: [DONE]\n\n",
                    json!(reply)
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse.len(),
                    sse
                );
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let path = std::env::temp_dir().join(format!("openbot-prompts-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let ws_root = std::env::temp_dir().join(format!("openbot-prompts-ws-{}", random_id().unwrap()));
        std::fs::create_dir_all(&ws_root).unwrap();
        let vc = virtual_computer::VirtualComputerState::new(auth.clone(), ws_root.clone());
        let state = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into())
            .unwrap()
            .with_virtual_computer(vc);
        let app = local_auth::router(auth.clone()).merge(router(state));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let setup_res = app.clone().oneshot(setup).await.unwrap();
        let cookie = setup_res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        db.try_with_connection(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS port_compat_kv (scope TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
                 INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'b_cmd','default',id,'Commander','','Lead',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'b_brw','default',id,'Browser','','Web browser',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'c_dm','default',id,'t_dm','[\"b_brw\"]','DM',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'c_grp','default',id,'t_grp','[\"b_cmd\",\"b_brw\"]','Grp',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_compat_kv(scope,value,updated_at) SELECT 'model_choice:default:'||id||':c_dm','{\"effort\":\"off\"}',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_compat_kv(scope,value,updated_at) SELECT 'model_choice:default:'||id||':c_grp','{\"effort\":\"off\"}',0 FROM auth_users LIMIT 1;",
            )?;
            Ok(())
        })
        .unwrap();

        let send = |conv: &str, id: &str, key: &str, bot: Option<&str>, text: &str| {
            let mut body = json!({"id": id, "text": text});
            if let Some(b) = bot {
                body["botId"] = json!(b);
            }
            Request::builder()
                .method("POST")
                .uri(format!("/api/v2/organizations/default/conversations/{conv}/messages"))
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body.to_string()))
                .unwrap()
        };

        assert_eq!(app.clone().oneshot(send("c_dm", "u_dm", "k_dm", Some("b_brw"), "open example.com")).await.unwrap().status(), StatusCode::ACCEPTED);
        for _ in 0..100 {
            let done: i64 = db.try_with_connection(|c| Ok(c.query_row("SELECT COUNT(*) FROM port_runs WHERE conversation_id='c_dm' AND status='completed'", [], |r| r.get(0))?)).unwrap();
            if done == 1 { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(app.clone().oneshot(send("c_grp", "u_grp", "k_grp", None, "open example.com")).await.unwrap().status(), StatusCode::ACCEPTED);
        for _ in 0..100 {
            let done: i64 = db.try_with_connection(|c| Ok(c.query_row("SELECT COUNT(*) FROM port_runs WHERE conversation_id='c_grp' AND status='completed'", [], |r| r.get(0))?)).unwrap();
            if done == 2 { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        mock.await.unwrap();
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 3);
        for req in reqs.iter() {
            assert_eq!(req["reasoning_effort"], "none");
            assert_eq!(req["chat_template_kwargs"]["enable_thinking"], false);
            let sys = req["messages"][0]["content"].as_str().unwrap();
            assert!(sys.contains("computer_web_fetch"), "missing VC grounding in system: {sys}");
        }
        // Group user messages must NOT have trailing "Respond as ..." / "This request was delegated..."
        let grp_lead_user = reqs[1]["messages"][1]["content"].as_str().unwrap();
        assert!(!grp_lead_user.contains("Respond as"));
        assert!(grp_lead_user.ends_with("User: open example.com"));
        let grp_brw_user = reqs[2]["messages"][1]["content"].as_str().unwrap();
        assert!(!grp_brw_user.contains("This request was delegated"));
        assert!(!grp_brw_user.contains("Respond directly"));

        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(ws_root);
    }

    #[tokio::test]
    async fn execute_tool_rounds_runs_synthesis_turn_after_four_tool_rounds() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured_ref = captured.clone();
        let mock = tokio::spawn(async move {
            for round in 0..5usize {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                let mut header_end = None;
                let mut content_len = 0usize;
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 { break; }
                    raw.extend_from_slice(&buf[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            for line in String::from_utf8_lossy(&raw[..pos]).lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(h_end) = header_end {
                        if raw.len() >= h_end + content_len {
                            let req_json: Value = serde_json::from_slice(&raw[h_end..h_end + content_len]).unwrap();
                            captured_ref.lock().unwrap().push(req_json);
                            break;
                        }
                    }
                }
                let chunk = if round < 4 {
                    json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":format!("tc_{round}"),"type":"function","function":{"name":"computer_list_files","arguments":"{}"}}]},"finish_reason":"tool_calls"}]})
                } else {
                    json!({"choices":[{"index":0,"delta":{"content":"Synthesized final answer after 4 tool rounds."},"finish_reason":"stop"}]})
                };
                let sse = format!("data: {chunk}\n\ndata: [DONE]\n\n");
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", sse.len(), sse);
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let path = std::env::temp_dir().join(format!("openbot-4rounds-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        let ws_root = std::env::temp_dir().join(format!("openbot-4rounds-ws-{}", random_id().unwrap()));
        std::fs::create_dir_all(&ws_root).unwrap();
        let vc = virtual_computer::VirtualComputerState::new(auth.clone(), ws_root.clone());
        let state = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap().with_virtual_computer(vc);
        let app = local_auth::router(auth.clone()).merge(router(state));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let cookie = app.clone().oneshot(setup).await.unwrap().headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();
        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','help',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'t','[\"bot\"]','DM',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_approval_rules(id,organization_id,scope_owner_id,bot_id,tool_ref,effect,scope,behaviour,created_by,created_at) SELECT 'r_allow','default',id,'bot','computer_list_files','read','*','allow',id,0 FROM auth_users LIMIT 1;",
            )?;
            Ok(())
        }).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/messages")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "k-4r")
            .body(Body::from(r#"{"id":"m1","text":"list files repeatedly","botId":"bot"}"#))
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::ACCEPTED);

        let mut final_status = String::new();
        for _ in 0..120 {
            if let Ok(s) = db.try_with_connection(|c| Ok(c.query_row("SELECT status FROM port_runs WHERE user_message_id='m1'", [], |r| r.get::<_, String>(0))?)) {
                final_status = s;
                if final_status != "running" { break; }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(final_status, "completed");
        mock.await.unwrap();
        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 5);
        assert!(reqs[3].get("tools").is_some());
        assert!(reqs[4].get("tools").is_none(), "synthesis turn must omit tools");
        let events = event_journal::replay(&db, "conv", None, 128).unwrap();
        assert_eq!(events.last().unwrap()["type"], "RUN_FINISHED");

        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(ws_root);
    }

    #[tokio::test]
    async fn group_approval_resume_uses_group_context_transitions_waiting_and_continues_orchestration() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured_ref = captured.clone();
        let mock = tokio::spawn(async move {
            // 1. Lead delegates to Browser and Writer
            // 2. Browser calls computer_write_file -> HITL interrupt
            // 3. Browser resumes after approval -> finishes
            // 4. Writer runs delegated followup -> finishes
            // 5. Lead closing runs -> finishes
            for step in 0..5usize {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                let mut header_end = None;
                let mut content_len = 0usize;
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 { break; }
                    raw.extend_from_slice(&buf[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            for line in String::from_utf8_lossy(&raw[..pos]).lines() {
                                if let Some((k, v)) = line.split_once(':') {
                                    if k.trim().eq_ignore_ascii_case("content-length") {
                                        content_len = v.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(h_end) = header_end {
                        if raw.len() >= h_end + content_len {
                            let req_json: Value = serde_json::from_slice(&raw[h_end..h_end + content_len]).unwrap();
                            captured_ref.lock().unwrap().push(req_json);
                            break;
                        }
                    }
                }
                let chunk = match step {
                    0 => json!({"choices":[{"index":0,"delta":{"content":"Passing this to Browser and Writer."},"finish_reason":"stop"}]}),
                    1 => json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"tc_grp_1","type":"function","function":{"name":"computer_write_file","arguments":"{\"path\":\"out.txt\",\"contents\":\"hi\"}"}}]},"finish_reason":"tool_calls"}]}),
                    2 => json!({"choices":[{"index":0,"delta":{"content":"Browser wrote out.txt."},"finish_reason":"stop"}]}),
                    3 => json!({"choices":[{"index":0,"delta":{"content":"Writer summarized out.txt."},"finish_reason":"stop"}]}),
                    _ => json!({"choices":[{"index":0,"delta":{"content":"All delegated tasks complete."},"finish_reason":"stop"}]}),
                };
                let sse = format!("data: {chunk}\n\ndata: [DONE]\n\n");
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", sse.len(), sse);
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let path = std::env::temp_dir().join(format!("openbot-grp-resume-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        let ws_root = std::env::temp_dir().join(format!("openbot-grp-resume-ws-{}", random_id().unwrap()));
        std::fs::create_dir_all(&ws_root).unwrap();
        let vc = virtual_computer::VirtualComputerState::new(auth.clone(), ws_root.clone());
        let state = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap().with_virtual_computer(vc);
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
        let cookie = app.clone().oneshot(setup).await.unwrap().headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();
        db.try_with_connection(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS port_compat_kv (scope TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
                 INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'b_cmd','default',id,'Commander','','Lead',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'b_brw','default',id,'Browser','','Browser',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'b_wrt','default',id,'Writer','','Writer',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'c_grp','default',id,'t_grp','[\"b_cmd\",\"b_brw\",\"b_wrt\"]','Team',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_approval_rules(id,organization_id,scope_owner_id,bot_id,tool_ref,effect,scope,behaviour,created_by,created_at) SELECT 'r_ask','default',id,'b_brw','computer_write_file','write','*','ask',id,0 FROM auth_users LIMIT 1;",
            )?;
            Ok(())
        }).unwrap();

        let send = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/c_grp/messages")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "k-grp-ask")
            .body(Body::from(r#"{"id":"m1","text":"write and summarize"}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(send).await.unwrap().status(), StatusCode::ACCEPTED);

        let mut approval_id: Option<String> = None;
        for _ in 0..100 {
            if let Ok(events) = event_journal::replay(&db, "c_grp", None, 128) {
                for ev in &events {
                    if ev["type"] == "RUN_FINISHED" && ev["outcome"]["type"] == "interrupt" {
                        approval_id = ev["outcome"]["interrupts"][0]["id"].as_str().map(str::to_owned);
                    }
                }
                if approval_id.is_some() { break; }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let approval_id = approval_id.expect("expected group interrupt approval");
        // While waiting for approval, Browser's message status must be 'waiting' (not 'completed')
        // and no orphaned 'queued' messages should remain.
        let (waiting_count, queued_count): (i64, i64) = db.try_with_connection(|c| {
            let w: i64 = c.query_row("SELECT COUNT(*) FROM port_conversation_messages WHERE conversation_id='c_grp' AND bot_id='b_brw' AND status='waiting'", [], |r| r.get(0))?;
            let q: i64 = c.query_row("SELECT COUNT(*) FROM port_conversation_messages WHERE conversation_id='c_grp' AND status='queued'", [], |r| r.get(0))?;
            Ok((w, q))
        }).unwrap();
        assert_eq!(waiting_count, 1);
        assert_eq!(queued_count, 0);

        let decide = Request::builder()
            .method("POST")
            .uri(format!("/api/v2/organizations/default/people/me/approvals/{approval_id}/decide"))
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "k-grp-dec")
            .body(Body::from(r#"{"decision":"allow_once"}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(decide).await.unwrap().status(), StatusCode::OK);

        for _ in 0..160 {
            let (running, total): (i64, i64) = db.try_with_connection(|c| {
                let r: i64 = c.query_row("SELECT COUNT(*) FROM port_runs WHERE conversation_id='c_grp' AND status='running'", [], |r| r.get(0))?;
                let t: i64 = c.query_row("SELECT COUNT(*) FROM port_runs WHERE conversation_id='c_grp'", [], |r| r.get(0))?;
                Ok((r, t))
            }).unwrap();
            if running == 0 && total >= 5 { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        mock.await.unwrap();

        let (still_waiting, run_bots): (i64, Vec<String>) = db.try_with_connection(|c| {
            let sw: i64 = c.query_row("SELECT COUNT(*) FROM port_conversation_messages WHERE conversation_id='c_grp' AND status='waiting'", [], |r| r.get(0))?;
            let mut st = c.prepare("SELECT bot_id FROM port_runs WHERE conversation_id='c_grp' ORDER BY rowid ASC")?;
            let bots = st.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((sw, bots))
        }).unwrap();
        assert_eq!(still_waiting, 0, "waiting status should clear after resume");
        assert_eq!(run_bots, vec!["b_cmd", "b_brw", "b_brw", "b_wrt", "b_cmd"]);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 5);
        // Browser's resumed request (#2) must include group team context & group transcript
        let resume_sys = reqs[2]["messages"][0]["content"].as_str().unwrap();
        assert!(resume_sys.contains("multi-bot group conversation"), "expected group sys prompt: {resume_sys}");
        let resume_user = reqs[2]["messages"][1]["content"].as_str().unwrap();
        assert!(resume_user.contains("[Commander]: Passing this to Browser and Writer."), "expected group transcript: {resume_user}");

        drop(app);
        drop(state);
        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(ws_root);
    }

    #[tokio::test]
    async fn finalize_run_inserts_queued_specialists_atomically_on_lead_delegation() {
        let path = std::env::temp_dir().join(format!("openbot-handoff-race-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO auth_users(id,email,display_name,password_hash) VALUES('u','a@b','A','x');
                 INSERT INTO auth_organizations(id,slug,name) VALUES('o','o','O');
                 INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) VALUES('b_cmd','o','u','Commander','','Lead',0),('b_brw','o','u','Browser','','Web',0);
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) VALUES('c','o','u','t','[\"b_cmd\",\"b_brw\"]','G',0);
                 INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) VALUES('a_lead','c','bot','u','b_cmd','','running',1);
                 INSERT INTO port_runs(id,conversation_id,owner_id,bot_id,user_message_id,assistant_message_id,request_key,fingerprint,status,created_at) VALUES('r_lead','c','u','b_cmd','u1','a_lead','k1',x'01','running',1);",
            )?;
            Ok(())
        }).unwrap();

        let mut names = HashMap::new();
        names.insert("b_cmd".to_owned(), "Commander".to_owned());
        names.insert("b_brw".to_owned(), "Browser".to_owned());
        let ctx = GroupHandoffContext::LeadDelegate {
            owner_id: "u".to_owned(),
            group_bots: vec!["b_cmd".to_owned(), "b_brw".to_owned()],
            bot_names: names,
            lead_bot: "b_cmd".to_owned(),
        };
        let cancel = CancellationToken::new();
        let outcome = finalize_run(
            &auth,
            "c",
            "t",
            "r_lead",
            "a_lead",
            "Passing this to Browser.",
            false,
            &cancel,
            Some(json!({"type":"RUN_FINISHED","threadId":"t","runId":"r_lead"})),
            None,
            Some(&ctx),
        )
        .await;
        assert!(outcome.completed);
        assert_eq!(outcome.queued_followups.len(), 1);
        assert_eq!(outcome.queued_followups[0].bot_id, "b_brw");

        let rows: Vec<(String, String, String)> = db.try_with_connection(|c| {
            let mut st = c.prepare("SELECT id, bot_id, status FROM port_conversation_messages WHERE conversation_id='c' ORDER BY rowid ASC")?;
            let out = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(out)
        }).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("a_lead".to_owned(), "b_cmd".to_owned(), "completed".to_owned()));
        assert_eq!(rows[1].1, "b_brw");
        assert_eq!(rows[1].2, "queued");

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn truncated_tool_call_on_length_is_dropped_without_broken_execution() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let chunk = json!({
                "choices": [{
                    "index": 0,
                    "delta": {
                        "tool_calls": [{
                            "index": 0,
                            "id": "tc_trunc_write",
                            "type": "function",
                            "function": {
                                "name": "computer_write_file",
                                "arguments": "{\"path\":\"huge.py\",\"contents\":\"print(1)\\n"
                            }
                        }]
                    },
                    "finish_reason": "length"
                }]
            });
            let sse = format!("data: {chunk}\n\ndata: [DONE]\n\n");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                sse.len(),
                sse
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
        });

        let path = std::env::temp_dir().join(format!("openbot-trunc-tc-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        let ws_root = std::env::temp_dir().join(format!("openbot-trunc-tc-ws-{}", random_id().unwrap()));
        std::fs::create_dir_all(&ws_root).unwrap();
        let vc = virtual_computer::VirtualComputerState::new(auth.clone(), ws_root.clone());
        let state = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap().with_virtual_computer(vc);
        let app = local_auth::router(auth.clone()).merge(router(state));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let cookie = app.clone().oneshot(setup).await.unwrap().headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();
        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','help',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'t','[\"bot\"]','DM',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_approval_rules(id,organization_id,scope_owner_id,bot_id,tool_ref,effect,scope,behaviour,created_by,created_at) SELECT 'r_allow','default',id,'bot','computer_write_file','write','*','allow',id,0 FROM auth_users LIMIT 1;",
            )?;
            Ok(())
        }).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/messages")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "k-trunc")
            .body(Body::from(r#"{"id":"m1","text":"write 5000 lines","botId":"bot"}"#))
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::ACCEPTED);

        let mut status = String::new();
        for _ in 0..120 {
            if let Ok(s) = db.try_with_connection(|c| Ok(c.query_row("SELECT status FROM port_runs WHERE user_message_id='m1'", [], |r| r.get::<_, String>(0))?)) {
                status = s;
                if status != "running" { break; }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(status, "completed");
        mock.await.unwrap();

        let msg_text: String = db.try_with_connection(|c| {
            Ok(c.query_row("SELECT text FROM port_conversation_messages WHERE conversation_id='conv' AND role='bot'", [], |r| r.get(0))?)
        }).unwrap();
        assert!(msg_text.contains("context/token limit"), "unexpected msg_text: {msg_text}");
        let events = event_journal::replay(&db, "conv", None, 128).unwrap();
        assert!(!events.iter().any(|e| e["type"] == "TOOL_CALL_END" && e["toolCallId"] == "tc_trunc_write"));
        assert!(!events.iter().any(|e| e["type"] == "TOOL_CALL_RESULT" && e["toolCallId"] == "tc_trunc_write"));
        assert!(!ws_root.join("default").join("bot").join("huge.py").exists());

        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(ws_root);
    }

    #[tokio::test]
    async fn preflight_auto_compaction_triggers_before_sending_and_records_context_snapshot() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured_requests = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured_c = captured_requests.clone();

        let mock = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let mut header_end = None;
                let mut content_len = 0usize;
                while let Ok(n) = socket.read(&mut tmp).await {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if header_end.is_none() {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = Some(pos + 4);
                            let headers = String::from_utf8_lossy(&buf[..pos]);
                            for line in headers.lines() {
                                if let Some(val) = line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")) {
                                    content_len = val.trim().parse().unwrap_or(0);
                                }
                            }
                        }
                    }
                    if let Some(end) = header_end {
                        if buf.len() >= end + content_len {
                            break;
                        }
                    }
                }
                let raw = String::from_utf8_lossy(&buf);
                let first_line = raw.lines().next().unwrap_or("");
                if first_line.starts_with("GET /props ") {
                    let body = r#"{"default_generation_settings":{"n_ctx":1024},"model_alias":"mock-8k","is_sleeping":false}"#;
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    socket.write_all(resp.as_bytes()).await.unwrap();
                } else if first_line.starts_with("GET /slots ") {
                    let body = r#"[{"id":0,"n_ctx":1024,"is_processing":false}]"#;
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    socket.write_all(resp.as_bytes()).await.unwrap();
                } else if first_line.starts_with("POST /v1/chat/completions ") {
                    if let Some(end) = header_end {
                        if let Ok(req_json) = serde_json::from_slice::<Value>(&buf[end..end + content_len]) {
                            captured_c.lock().unwrap().push(req_json);
                        }
                    }
                    let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"Compacted ok\"},\"finish_reason\":null}]}\r\n\r\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\r\n\r\ndata: [DONE]\r\n\r\n";
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{sse}", sse.len());
                    socket.write_all(resp.as_bytes()).await.unwrap();
                    break;
                }
            }
        });

        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).unwrap();
        let path = std::env::temp_dir().join(format!("openbot-runs-ctx-{:x}.db", u64::from_le_bytes(rand)));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        let run_state = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock-8k".into())
            .unwrap()
            .with_live_context_probe();
        let app = crate::local_auth::router(auth.clone())
            .merge(crate::compat_routes::router_with_context(auth.clone(), run_state.context_manager()))
            .merge(router(run_state.clone()));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"a long secure password"}"#))
            .unwrap();
        let cookie = app.clone().oneshot(setup).await.unwrap().headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();
        let old_turn = "history token ".repeat(40); // ~560 chars each (under per-msg 600 cap)
        db.try_with_connection(|c| {
            c.execute(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','You are helpful.',0 FROM auth_users LIMIT 1",
                [],
            )?;
            c.execute(
                "INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'t','[\"bot\"]','DM',0 FROM auth_users LIMIT 1",
                [],
            )?;
            for idx in 1..=8 {
                let role = if idx % 2 == 1 { "person" } else { "bot" };
                let bid = if role == "bot" { Some("bot") } else { None };
                let mid = format!("old_{idx}");
                let text = format!("Turn {idx}: {old_turn}");
                c.execute(
                    "INSERT INTO port_conversation_messages(id,conversation_id,role,person_id,bot_id,text,status,created_at) SELECT ?1,'conv',?2,id,?3,?4,'completed',?5 FROM auth_users LIMIT 1",
                    params![mid, role, bid, text, idx],
                )?;
            }
            Ok(())
        }).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/messages")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "k-ctx")
            .body(Body::from(r#"{"id":"m_latest","text":"Reply cleanly","botId":"bot"}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::ACCEPTED);

        let mut status = String::new();
        for _ in 0..120 {
            if let Ok(s) = db.try_with_connection(|c| Ok(c.query_row("SELECT status FROM port_runs WHERE user_message_id='m_latest'", [], |r| r.get::<_, String>(0))?)) {
                status = s;
                if status != "running" { break; }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(status, "completed");
        mock.await.unwrap();

        let sent = captured_requests.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let sent_msgs = sent[0]["messages"].as_array().unwrap();
        assert!(sent_msgs.iter().any(|m| {
            m["role"] == "system"
                && m["content"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("[Compacted conversation context summary]"))
        }));
        assert!(sent_msgs.iter().any(|m| m["role"] == "user" && m["content"] == "Reply cleanly"));

        let ctx_res = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v2/organizations/default/conversations/conv/context")
                    .header("host", "example.test")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ctx_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(ctx_res.into_body(), 64 * 1024).await.unwrap();
        let snap: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(snap["context_limit"], 1024);
        assert_eq!(snap["compacted"], true);
        assert!(snap["compacted_before_tokens"].as_u64().unwrap() > 768);
        assert!(snap["used_tokens"].as_u64().unwrap() <= 768);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn stale_replay_gap_clears_on_fresh_send_and_finalize_uses_max_events() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Recovered after gap\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
        });

        let path = std::env::temp_dir().join(format!("openbot-gap-clear-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        let state = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap();
        let app = local_auth::router(auth.clone()).merge(router(state));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let cookie = app.clone().oneshot(setup).await.unwrap().headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();

        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','help',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'t','[\"bot\"]','DM',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_metadata(key,value) VALUES('conversation_replay_gap:conv','stale gap');",
            )?;
            Ok(())
        }).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/messages")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "k-gap-clear")
            .body(Body::from(r#"{"id":"m1","text":"hello after gap","botId":"bot"}"#))
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::ACCEPTED);

        let mut status = String::new();
        for _ in 0..120 {
            if let Ok(s) = db.try_with_connection(|c| Ok(c.query_row("SELECT status FROM port_runs WHERE user_message_id='m1'", [], |r| r.get::<_, String>(0))?)) {
                status = s;
                if status != "running" { break; }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(status, "completed");
        mock.await.unwrap();

        let gap_exists: bool = db.try_with_connection(|c| {
            Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM port_metadata WHERE key='conversation_replay_gap:conv')", [], |r| r.get(0))?)
        }).unwrap();
        assert!(!gap_exists);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn empty_model_reply_after_tool_execution_emits_tool_summary() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = tokio::spawn(async move {
            for round in 0..2usize {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap();
                let chunk = if round == 0 {
                    json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"tc_write","type":"function","function":{"name":"computer_write_file","arguments":"{\"path\":\"hello.txt\",\"contents\":\"hi\"}"}}]},"finish_reason":"tool_calls"}]})
                } else {
                    json!({"choices":[{"index":0,"delta":{"content":""},"finish_reason":"stop"}]})
                };
                let sse = format!("data: {chunk}\n\ndata: [DONE]\n\n");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse.len(),
                    sse
                );
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let path = std::env::temp_dir().join(format!("openbot-empty-summary-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        let ws_root = std::env::temp_dir().join(format!("openbot-empty-summary-ws-{}", random_id().unwrap()));
        std::fs::create_dir_all(&ws_root).unwrap();
        let vc = virtual_computer::VirtualComputerState::new(auth.clone(), ws_root.clone());
        let state = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into())
            .unwrap()
            .with_virtual_computer(vc);
        let app = local_auth::router(auth.clone()).merge(router(state));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let cookie = app.clone().oneshot(setup).await.unwrap().headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();

        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Programmer','','Write files.',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'t','[\"bot\"]','DM',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_approval_settings(organization_id,enforce_auto_review,custom_rules_enabled,host_commands_cap,action_kinds_json,execution_mode) VALUES('default',0,1,'ask','{}','turbo') ON CONFLICT(organization_id) DO UPDATE SET execution_mode='turbo';",
            )?;
            Ok(())
        }).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v2/organizations/default/conversations/conv/messages")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .header("idempotency-key", "k-empty-sum")
            .body(Body::from(r#"{"id":"m1","text":"Write hello.txt","botId":"bot"}"#))
            .unwrap();
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::ACCEPTED);

        let mut status = String::new();
        for _ in 0..120 {
            if let Ok(s) = db.try_with_connection(|c| Ok(c.query_row("SELECT status FROM port_runs WHERE user_message_id='m1'", [], |r| r.get::<_, String>(0))?)) {
                status = s;
                if status != "running" { break; }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(status, "completed");
        mock.await.unwrap();

        let reply_text: String = db.try_with_connection(|c| {
            Ok(c.query_row(
                "SELECT text FROM port_conversation_messages WHERE conversation_id='conv' AND role='bot' ORDER BY rowid DESC LIMIT 1",
                [],
                |r| r.get(0),
            )?)
        }).unwrap();
        assert!(reply_text.contains("saved `hello.txt`"), "unexpected reply: {reply_text}");

        drop(db);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(ws_root);
    }

    #[tokio::test]
    async fn interrupt_active_cancels_busy_or_stuck_run_and_runs_immediately() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
        let hold_tx = Arc::new(Mutex::new(Some(hold_tx)));
        let mock = tokio::spawn(async move {
            // Connection 1: hang in a separate task until released (simulates slow/stuck active run).
            let (mut s1, _) = listener.accept().await.unwrap();
            let hold_task = tokio::spawn(async move {
                let mut b1 = [0u8; 4096];
                let _ = s1.read(&mut b1).await;
                let _ = hold_rx.await;
                drop(s1);
            });

            // Connection 2: fast reply for instant-send message.
            let (mut s2, _) = listener.accept().await.unwrap();
            let mut b2 = [0u8; 4096];
            let _ = s2.read(&mut b2).await;
            let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Instant reply!\"},\"finish_reason\":null}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            s2.write_all(resp.as_bytes()).await.unwrap();
            let _ = hold_task.await;
        });

        let path = std::env::temp_dir().join(format!("openbot-instant-{}.db", random_id().unwrap()));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        let state = RunState::new(auth.clone(), &format!("http://{addr}/v1"), "mock".into()).unwrap();
        let app = local_auth::router(auth.clone()).merge(router(state));

        let setup = Request::builder()
            .method("POST")
            .uri("/api/port/auth/setup")
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#))
            .unwrap();
        let cookie = app.clone().oneshot(setup).await.unwrap().headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();

        db.try_with_connection(|c| {
            c.execute_batch(
                "INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot','default',id,'Bot','','help',0 FROM auth_users LIMIT 1;
                 INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'conv','default',id,'t','[\"bot\"]','DM',0 FROM auth_users LIMIT 1;",
            )?;
            Ok(())
        }).unwrap();

        // Start run 1 (hangs).
        let r1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/organizations/default/conversations/conv/messages")
                    .header("host", "example.test")
                    .header("origin", "http://example.test")
                    .header("cookie", &cookie)
                    .header("content-type", "application/json")
                    .header("idempotency-key", "k-inst-1")
                    .body(Body::from(r#"{"id":"m1","text":"slow message"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::ACCEPTED);
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Without interruptActive, normal send returns 409 Conversation already running.
        let r_busy = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/organizations/default/conversations/conv/messages")
                    .header("host", "example.test")
                    .header("origin", "http://example.test")
                    .header("cookie", &cookie)
                    .header("content-type", "application/json")
                    .header("idempotency-key", "k-inst-busy")
                    .body(Body::from(r#"{"id":"m_busy","text":"blocked"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r_busy.status(), StatusCode::CONFLICT);

        // With interruptActive: true, it cancels the active run and accepts immediately!
        let r2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/organizations/default/conversations/conv/messages")
                    .header("host", "example.test")
                    .header("origin", "http://example.test")
                    .header("cookie", &cookie)
                    .header("content-type", "application/json")
                    .header("idempotency-key", "k-inst-2")
                    .body(Body::from(r#"{"id":"m2","text":"instant override","interruptActive":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::ACCEPTED);

        let mut status2 = String::new();
        for _ in 0..120 {
            if let Ok(s) = db.try_with_connection(|c| Ok(c.query_row("SELECT status FROM port_runs WHERE user_message_id='m2'", [], |r| r.get::<_, String>(0))?)) {
                status2 = s;
                if status2 != "running" { break; }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(status2, "completed");

        if let Some(tx) = hold_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        mock.await.unwrap();

        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
