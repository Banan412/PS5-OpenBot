//! Policy rules CRUD, boundaries, approval settings, interactive HITL approvals,
//! single-use atomic approval consumption, and audit events API.
use crate::{
    local_auth::{self, AuthState, Identity},
    runs,
    storage::StorageError,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, types::Value as SqlValue, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_RULES_PER_SCOPE: usize = 512;
const MAX_BOUNDARY_RULES: usize = 256;
const MAX_BOUNDARY_EXPR_LEN: usize = 1000;
const MAX_CEL_DEPTH: usize = 32;
const MAX_ARGS_BYTES: usize = 65_536;
const DEFAULT_APPROVAL_TTL_SECS: i64 = 604_800;
const MAX_APPROVAL_TTL_SECS: i64 = 2_592_000;
const IDEM_TTL_SECS: i64 = 86_400;

const ACTION_KINDS: [&str; 7] = [
    "deleting",
    "sending",
    "sharing",
    "publishing",
    "payments",
    "credentials",
    "security_settings",
];

#[derive(Debug)]
pub enum ApprovalError {
    InvalidInput(&'static str),
    Unauthorized,
    NotFound,
    Conflict(&'static str),
    Expired,
    DigestMismatch,
    Storage(rusqlite::Error),
    Clock,
    Entropy,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "{msg}"),
            Self::Unauthorized => write!(f, "action not authorized"),
            Self::NotFound => write!(f, "approval not found"),
            Self::Conflict(msg) => write!(f, "{msg}"),
            Self::Expired => write!(f, "approval expired"),
            Self::DigestMismatch => write!(f, "approval action digest mismatch"),
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::Clock => write!(f, "clock unavailable"),
            Self::Entropy => write!(f, "entropy unavailable"),
        }
    }
}

impl std::error::Error for ApprovalError {}

impl From<rusqlite::Error> for ApprovalError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleBehaviour {
    Allow,
    PreApproved,
    Ask,
    HandOff,
}

impl RuleBehaviour {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::PreApproved => "pre_approved",
            Self::Ask => "ask",
            Self::HandOff => "hand_off",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "pre_approved" => Some(Self::PreApproved),
            "ask" => Some(Self::Ask),
            "hand_off" => Some(Self::HandOff),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationDecision {
    Allow,
    Ask,
    HandOff,
    Deny,
}

impl EvaluationDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::HandOff => "hand_off",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub decision: EvaluationDecision,
    pub source: &'static str,
    pub reason: String,
    pub kind: Option<String>,
    pub closed: bool,
}

impl PolicyOutcome {
    pub fn to_policy_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("behaviour".into(), json!(self.decision.as_str()));
        obj.insert("source".into(), json!(self.source));
        obj.insert("reason".into(), json!(self.reason));
        if let Some(kind) = &self.kind {
            obj.insert("kind".into(), json!(kind));
        }
        if self.closed {
            obj.insert("closed".into(), json!(true));
        }
        Value::Object(obj)
    }
}

pub struct ActionEvalRequest<'a> {
    pub organization_id: &'a str,
    pub actor_id: &'a str,
    pub bot_id: &'a str,
    pub conversation_id: &'a str,
    pub tool_ref: &'a str,
    pub effect: &'a str,
    pub scope: &'a str,
    pub user_explicitly_requested: bool,
    pub boundary_context: Option<&'a Value>,
}

pub struct CreatePendingApprovalRequest<'a> {
    pub organization_id: &'a str,
    pub actor_id: &'a str,
    pub bot_id: &'a str,
    pub conversation_id: &'a str,
    pub run_id: &'a str,
    pub tool_call_id: Option<&'a str>,
    pub tool_ref: &'a str,
    pub effect: &'a str,
    pub scope: &'a str,
    pub thread_id: &'a str,
    pub args: &'a Value,
    pub target: Option<&'a Value>,
    pub account: Option<&'a str>,
    pub policy: Option<&'a Value>,
    pub ttl_seconds: Option<i64>,
}

pub struct ConsumeApprovalRequest<'a> {
    pub approval_id: &'a str,
    pub organization_id: &'a str,
    pub actor_id: &'a str,
    pub bot_id: &'a str,
    pub conversation_id: &'a str,
    pub tool_ref: &'a str,
    pub effect: &'a str,
    pub scope: &'a str,
    pub args: &'a Value,
}

pub struct CompleteApprovalRequest<'a> {
    pub approval_id: &'a str,
    pub organization_id: &'a str,
    pub actor_id: &'a str,
    pub error: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub id: String,
    pub organization_id: String,
    pub actor_id: String,
    pub bot_id: String,
    pub conversation_id: String,
    pub run_id: String,
    pub tool_call_id: Option<String>,
    pub tool_ref: String,
    pub effect: String,
    pub scope: String,
    pub thread_id: String,
    pub args_json: String,
    pub target_json: Option<String>,
    pub account: Option<String>,
    pub policy_json: Option<String>,
    pub action_digest: Vec<u8>,
    pub status: String,
    pub decision: Option<String>,
    pub result_json: Option<String>,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub consumed_at: Option<i64>,
    pub completed_at: Option<i64>,
    pub expires_at: i64,
}

pub fn router(state: AuthState) -> Router {
    router_with_runs(state, None)
}

pub(crate) fn router_with_runs(state: AuthState, runs: Option<runs::RunState>) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/people/{person}/approvals",
            get(list_approvals),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/approvals/{approvalId}",
            delete(delete_approval),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/approvals/{approvalId}/decide",
            post(decide_approval),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/approvals/step",
            post(run_computer_step),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/computer-steps",
            post(run_computer_step),
        )
        .route(
            "/api/v2/organizations/{organization}/approval-rules",
            get(list_org_rules).post(create_org_rule),
        )
        .route(
            "/api/v2/organizations/{organization}/approval-rules/{approvalRuleId}",
            patch(update_org_rule).delete(delete_org_rule),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/approval-rules",
            get(list_person_rules).post(create_person_rule),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/approval-rules/{approvalRuleId}",
            patch(update_person_rule).delete(delete_person_rule),
        )
        .route(
            "/api/v2/organizations/{organization}/approval-settings",
            get(get_approval_settings).patch(update_approval_settings),
        )
        .route(
            "/api/v2/organizations/{organization}/approvals/settings",
            get(get_approval_settings).patch(update_approval_settings),
        )
        .route(
            "/api/v2/organizations/{organization}/boundaries",
            get(get_boundaries).put(replace_boundaries),
        )
        .route(
            "/api/v2/organizations/{organization}/audit-events",
            get(list_audit_events),
        )
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(Extension(runs))
        .with_state(state)
}

// ---------- Common Utilities ----------

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && !s.chars().any(char::is_control)
}

fn valid_scope(s: &str) -> bool {
    !s.is_empty() && s.len() <= 2048 && !s.chars().any(char::is_control)
}

/// Extract a sanitized, non-empty scope string from tool arguments (`path`, `url`, or `command`).
pub(crate) fn extract_tool_scope(args: &Value) -> String {
    let raw = args
        .get("path")
        .or_else(|| args.get("url"))
        .or_else(|| args.get("command"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return "*".to_owned();
    }
    if trimmed.len() <= 1000 {
        return trimmed.to_owned();
    }
    let mut end = 0usize;
    for (idx, ch) in trimmed.char_indices() {
        if idx + ch.len_utf8() > 1000 {
            break;
        }
        end = idx + ch.len_utf8();
    }
    if end == 0 {
        "*".to_owned()
    } else {
        trimmed[..end].to_owned()
    }
}

fn valid_pattern(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 300 || trimmed.contains('\0') {
        return None;
    }
    if trimmed.chars().any(char::is_control) {
        return None;
    }
    Some(trimmed.to_owned())
}

fn now_secs() -> Result<i64, ApprovalError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or(ApprovalError::Clock)
}

fn random_id(prefix: &str) -> Result<String, ApprovalError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| ApprovalError::Entropy)?;
    let mut out = String::with_capacity(prefix.len() + 32);
    out.push_str(prefix);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Format Unix epoch seconds as UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    // Howard Hinnant's civil_from_days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Parse UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SS[.fff]Z` or `+00:00`) into Unix epoch seconds.
fn parse_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let core = s
        .strip_suffix('Z')
        .or_else(|| s.strip_suffix("+00:00"))
        .or_else(|| s.strip_suffix("-00:00"))?;
    let (date_part, time_part) = core.split_once('T')?;
    let mut d_parts = date_part.split('-');
    let year: i64 = d_parts.next()?.parse().ok()?;
    let month: i64 = d_parts.next()?.parse().ok()?;
    let day: i64 = d_parts.next()?.parse().ok()?;
    if d_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let time_no_frac = time_part.split('.').next()?;
    let mut t_parts = time_no_frac.split(':');
    let hour: i64 = t_parts.next()?.parse().ok()?;
    let minute: i64 = t_parts.next()?.parse().ok()?;
    let second: i64 = t_parts.next()?.parse().ok()?;
    if t_parts.next().is_some()
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    // Howard Hinnant's days_from_civil algorithm.
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days.checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)
}

fn canonicalize_json(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted: BTreeMap<&String, Value> = BTreeMap::new();
            for (k, val) in map {
                sorted.insert(k, canonicalize_json(val));
            }
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k.clone(), val);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_json).collect()),
        other => other.clone(),
    }
}

pub fn compute_action_digest(
    organization_id: &str,
    actor_id: &str,
    bot_id: &str,
    conversation_id: &str,
    tool_ref: &str,
    effect: &str,
    scope: &str,
    args: &Value,
) -> Result<[u8; 32], ApprovalError> {
    #[derive(Serialize)]
    struct CanonicalAction<'a> {
        organization_id: &'a str,
        actor_id: &'a str,
        bot_id: &'a str,
        conversation_id: &'a str,
        tool_ref: &'a str,
        effect: &'a str,
        scope: &'a str,
        args: Value,
    }
    let payload = CanonicalAction {
        organization_id,
        actor_id,
        bot_id,
        conversation_id,
        tool_ref,
        effect,
        scope,
        args: canonicalize_json(args),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|_| ApprovalError::InvalidInput("invalid args"))?;
    if bytes.len() > MAX_ARGS_BYTES + 2048 {
        return Err(ApprovalError::InvalidInput("action payload too large"));
    }
    Ok(Sha256::digest(&bytes).into())
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "private_key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn redact_args(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                if is_secret_key(k) {
                    out.insert(k.clone(), Value::String("[REDACTED]".into()));
                } else {
                    out.insert(k.clone(), redact_args(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().take(64).map(redact_args).collect()),
        Value::String(s) => {
            if s.chars().count() > 500 {
                let prefix: String = s.chars().take(497).collect();
                Value::String(format!("{prefix}..."))
            } else {
                Value::String(s.clone())
            }
        }
        other => other.clone(),
    }
}

// ---------- Wildcard Matching & Action Kind Classification ----------

fn matches_pattern(pattern: &str, value: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty()
        || p.chars().count() > 2048
        || p.contains('\0')
        || value.is_empty()
        || value.len() > 4096
        || value.contains('\0')
    {
        return false;
    }
    if p == "*" {
        return true;
    }
    let p: Vec<char> = p.chars().collect();
    let s: Vec<char> = value.chars().collect();
    let (mut i, mut j, mut star, mut restart) = (0, 0, None, 0);
    while j < s.len() {
        if i < p.len() && p[i] == s[j] {
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

fn extract_url_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    let lower = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty() {
        None
    } else {
        Some(lower)
    }
}

fn hosts_share_site(rule_host: &str, req_host: &str) -> bool {
    if rule_host == req_host {
        return true;
    }
    let r = rule_host.strip_prefix("www.").unwrap_or(rule_host);
    let q = req_host.strip_prefix("www.").unwrap_or(req_host);
    if r == q {
        return true;
    }
    q.ends_with(&format!(".{r}")) || r.ends_with(&format!(".{q}"))
}

fn rule_matches_scope(rule_scope: &str, req_scope: &str) -> bool {
    if matches_pattern(rule_scope, req_scope) {
        return true;
    }
    let trimmed = rule_scope.trim();
    if let Some(req_host) = extract_url_host(req_scope) {
        if let Some(rule_host) = extract_url_host(trimmed) {
            if !trimmed.contains('*') && hosts_share_site(&rule_host, &req_host) {
                return true;
            }
        } else if !trimmed.contains('/')
            && !trimmed.contains(' ')
            && !trimmed.contains("://")
            && matches_pattern(&trimmed.to_ascii_lowercase(), &req_host)
        {
            return true;
        }
    }
    false
}

fn standing_rule_scope_for_record(tool_ref: &str, scope: &str) -> String {
    let t = tool_ref.trim().to_ascii_lowercase();
    if t.starts_with("computer_") || is_host_command_tool(&t) {
        return "*".to_owned();
    }
    let trimmed = scope.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
    {
        return "*".to_owned();
    }
    trimmed.to_owned()
}

fn classify_action_kind(tool_ref: &str, effect: &str) -> Option<&'static str> {
    let t = tool_ref.to_ascii_lowercase();
    if t.contains("credential") || t.contains("secret") || t.contains("api_key") || t.contains("password") {
        return Some("credentials");
    }
    if t.contains("security") || t.contains("boundary") || t.contains("approval_rule") {
        return Some("security_settings");
    }
    if t.contains("payment") || t.contains("charge") || t.contains("invoice") || t.contains("transfer") {
        return Some("payments");
    }
    if t.contains("delete") || t.contains("remove") || t.contains("destroy") {
        return Some("deleting");
    }
    if t.contains("publish") || t.contains("deploy") {
        return Some("publishing");
    }
    if t.contains("share") || t.contains("invite") {
        return Some("sharing");
    }
    if effect.eq_ignore_ascii_case("write") && (t.contains("send") || t.contains("post_message") || t.contains("email")) {
        return Some("sending");
    }
    None
}

fn is_host_command_tool(tool_ref: &str) -> bool {
    let t = tool_ref.to_ascii_lowercase();
    t == "run_command" || t == "host/run_command" || t == "computer_run_command"
}

fn split_unquoted_pipes(cmd: &str) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if escape {
            cur.push(ch);
            escape = false;
            i += 1;
            continue;
        }
        if ch == '\\' && !in_single {
            cur.push(ch);
            escape = true;
            i += 1;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            cur.push(ch);
            i += 1;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            cur.push(ch);
            i += 1;
            continue;
        }
        if !in_single && !in_double {
            // Reject chaining, redirection, backgrounding, subshells, and newlines.
            if matches!(ch, ';' | '&' | '>' | '<' | '`' | '\n' | '\r') {
                return None;
            }
            if ch == '$' && i + 1 < chars.len() && matches!(chars[i + 1], '(' | '{') {
                return None;
            }
            if ch == '|' {
                if i + 1 < chars.len() && matches!(chars[i + 1], '|' | '&') {
                    return None;
                }
                let seg = cur.trim().to_owned();
                if seg.is_empty() {
                    return None;
                }
                segments.push(seg);
                cur.clear();
                i += 1;
                continue;
            }
        } else if in_double {
            if matches!(ch, '`' | '\n' | '\r') {
                return None;
            }
            if ch == '$' && i + 1 < chars.len() && matches!(chars[i + 1], '(' | '{') {
                return None;
            }
        }
        cur.push(ch);
        i += 1;
    }
    if in_single || in_double || escape {
        return None;
    }
    let tail = cur.trim().to_owned();
    if tail.is_empty() {
        return None;
    }
    segments.push(tail);
    Some(segments)
}

fn split_shell_words(segment: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    for ch in segment.chars() {
        if escape {
            cur.push(ch);
            escape = false;
            in_token = true;
            continue;
        }
        if ch == '\\' && !in_single {
            escape = true;
            in_token = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            in_token = true;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            in_token = true;
            continue;
        }
        if ch.is_ascii_whitespace() && !in_single && !in_double {
            if in_token {
                words.push(std::mem::take(&mut cur));
                in_token = false;
            }
            continue;
        }
        cur.push(ch);
        in_token = true;
    }
    if in_single || in_double || escape {
        return None;
    }
    if in_token {
        words.push(cur);
    }
    if words.is_empty() {
        None
    } else {
        Some(words)
    }
}

fn is_safe_git_command(args: &[String]) -> bool {
    let mut idx = 0usize;
    while idx < args.len() {
        let a = args[idx].as_str();
        if a == "-c"
            || a.starts_with("-c=")
            || a == "--exec-path"
            || a.starts_with("--exec-path=")
            || a == "--upload-pack"
            || a.starts_with("--upload-pack=")
            || a == "--receive-pack"
            || a.starts_with("--receive-pack=")
        {
            return false;
        }
        if matches!(a, "-C" | "--git-dir" | "--work-tree") {
            idx += 2;
            continue;
        }
        if a.starts_with("--git-dir=")
            || a.starts_with("--work-tree=")
            || matches!(a, "--no-pager" | "-p" | "--paginate" | "--bare" | "--no-optional-locks")
        {
            idx += 1;
            continue;
        }
        if a.starts_with('-') {
            return matches!(a, "--version" | "-v" | "--help" | "-h");
        }
        break;
    }
    let Some(sub) = args.get(idx).map(String::as_str) else {
        return false;
    };
    let rest = &args[idx + 1..];
    match sub {
        "status" | "log" | "diff" | "show" | "rev-parse" | "ls-files" | "ls-tree" | "blame"
        | "describe" | "shortlog" | "reflog" | "grep" => {
            !rest.iter().any(|a| a.starts_with("--output="))
        }
        "branch" => !rest.iter().any(|a| {
            matches!(
                a.as_str(),
                "-d" | "-D" | "-m" | "-M" | "-c" | "-C" | "--delete" | "--move" | "--copy" | "--edit-description"
            ) || a.starts_with("--set-upstream")
                || a.starts_with("--unset-upstream")
        }),
        "tag" => rest.is_empty() || rest.iter().all(|a| matches!(a.as_str(), "-l" | "--list" | "-n")),
        "remote" => {
            rest.is_empty()
                || rest
                    .iter()
                    .all(|a| matches!(a.as_str(), "-v" | "--verbose" | "show"))
        }
        _ => false,
    }
}

fn is_safe_readonly_segment(words: &[String]) -> bool {
    let Some(cmd_raw) = words.first() else {
        return false;
    };
    let cmd = cmd_raw.rsplit(['/', '\\']).next().unwrap_or(cmd_raw);
    let args = &words[1..];
    match cmd {
        "ls" | "ll" | "la" | "dir" | "cat" | "head" | "tail" | "pwd" | "echo" | "printf"
        | "grep" | "egrep" | "fgrep" | "rg" | "ag" | "ack" | "wc" | "sort" | "uniq" | "cut"
        | "tr" | "which" | "whereis" | "type" | "whoami" | "id" | "uname" | "hostname"
        | "date" | "uptime" | "df" | "du" | "free" | "ps" | "stat" | "file" | "basename"
        | "dirname" | "realpath" | "readlink" | "tree" | "less" | "more" | "diff" | "cmp"
        | "md5sum" | "sha256sum" | "sha1sum" | "b2sum" => {
            // Disallow output flags like sort -o / tee-like writes
            if cmd == "sort" && args.iter().any(|a| a == "-o" || a.starts_with("--output")) {
                return false;
            }
            true
        }
        "find" => !args.iter().any(|a| {
            matches!(
                a.as_str(),
                "-exec" | "-execdir" | "-ok" | "-okdir" | "-delete" | "-fprint" | "-fprint0"
                    | "-fprintf" | "-fls"
            )
        }),
        "git" => is_safe_git_command(args),
        "python" | "python3" | "node" | "bun" | "npm" | "cargo" | "rustc" | "go" | "java"
        | "gcc" | "clang" | "rustup" => {
            !args.is_empty()
                && args
                    .iter()
                    .all(|a| matches!(a.as_str(), "--version" | "-V" | "-v" | "--help" | "-h"))
        }
        _ => false,
    }
}

fn is_safe_readonly_shell_command(command: &str) -> bool {
    let trimmed = command.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return false;
    }
    let Some(segments) = split_unquoted_pipes(trimmed) else {
        return false;
    };
    segments.iter().all(|seg| {
        split_shell_words(seg).is_some_and(|words| is_safe_readonly_segment(&words))
    })
}

fn is_auto_mode_safe_action(tool_ref: &str, effect: &str, scope: &str) -> bool {
    if is_host_command_tool(tool_ref) {
        return is_safe_readonly_shell_command(scope);
    }
    let t = tool_ref.trim().to_ascii_lowercase();
    if matches!(
        t.as_str(),
        "computer_web_fetch" | "computer_navigate" | "computer_list_files" | "computer_read_file"
    ) {
        return !effect.eq_ignore_ascii_case("write");
    }
    (t.starts_with("computer_") || t.starts_with("mcp/") || t.starts_with("mcp__"))
        && effect.eq_ignore_ascii_case("read")
}

// ---------- Mini-CEL Parser & Evaluator for Boundaries ----------

#[derive(Debug, Clone)]
enum CelExpr {
    Bool(bool),
    Str(String),
    Ident(String),
    Not(Box<CelExpr>),
    And(Box<CelExpr>, Box<CelExpr>),
    Or(Box<CelExpr>, Box<CelExpr>),
    Eq(Box<CelExpr>, Box<CelExpr>),
    Ne(Box<CelExpr>, Box<CelExpr>),
    In(Box<CelExpr>, Vec<String>),
    StrMethod {
        target: Box<CelExpr>,
        method: &'static str,
        arg: String,
    },
}

struct CelParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> CelParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
            depth: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn starts_with(&self, s: &str) -> bool {
        self.bytes[self.pos..].starts_with(s.as_bytes())
    }

    fn parse_all(&mut self) -> Result<CelExpr, &'static str> {
        let expr = self.parse_or()?;
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err("unexpected trailing tokens in boundary expression");
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<CelExpr, &'static str> {
        let mut left = self.parse_and()?;
        loop {
            self.skip_ws();
            if self.starts_with("||") {
                self.pos += 2;
                let right = self.parse_and()?;
                left = CelExpr::Or(Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn parse_and(&mut self) -> Result<CelExpr, &'static str> {
        let mut left = self.parse_not()?;
        loop {
            self.skip_ws();
            if self.starts_with("&&") {
                self.pos += 2;
                let right = self.parse_not()?;
                left = CelExpr::And(Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn parse_not(&mut self) -> Result<CelExpr, &'static str> {
        self.skip_ws();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'!' && !self.starts_with("!=") {
            self.pos += 1;
            self.depth += 1;
            if self.depth > MAX_CEL_DEPTH {
                return Err("boundary expression exceeds maximum nesting depth");
            }
            let inner = self.parse_not()?;
            self.depth -= 1;
            return Ok(CelExpr::Not(Box::new(inner)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<CelExpr, &'static str> {
        let left = self.parse_primary()?;
        self.skip_ws();
        if self.starts_with("==") {
            self.pos += 2;
            let right = self.parse_primary()?;
            Ok(CelExpr::Eq(Box::new(left), Box::new(right)))
        } else if self.starts_with("!=") {
            self.pos += 2;
            let right = self.parse_primary()?;
            Ok(CelExpr::Ne(Box::new(left), Box::new(right)))
        } else if self.starts_with("in")
            && self
                .bytes
                .get(self.pos + 2)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'[')
        {
            self.pos += 2;
            let list = self.parse_string_list()?;
            Ok(CelExpr::In(Box::new(left), list))
        } else {
            Ok(left)
        }
    }

    fn parse_primary(&mut self) -> Result<CelExpr, &'static str> {
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return Err("unexpected end of boundary expression");
        }
        if self.bytes[self.pos] == b'(' {
            self.pos += 1;
            self.depth += 1;
            if self.depth > MAX_CEL_DEPTH {
                return Err("boundary expression exceeds maximum nesting depth");
            }
            let inner = self.parse_or()?;
            self.depth -= 1;
            self.skip_ws();
            if self.pos >= self.bytes.len() || self.bytes[self.pos] != b')' {
                return Err("unclosed parenthesis in boundary expression");
            }
            self.pos += 1;
            return Ok(inner);
        }
        if self.bytes[self.pos] == b'"' || self.bytes[self.pos] == b'\'' {
            return Ok(CelExpr::Str(self.parse_string_literal()?));
        }
        let ident = self.parse_dotted_ident()?;
        if ident == "true" {
            return Ok(CelExpr::Bool(true));
        }
        if ident == "false" {
            return Ok(CelExpr::Bool(false));
        }
        if let Some((base, method)) = ident.rsplit_once('.') {
            if matches!(method, "startsWith" | "endsWith" | "contains") {
                self.skip_ws();
                if self.pos < self.bytes.len() && self.bytes[self.pos] == b'(' {
                    self.pos += 1;
                    self.skip_ws();
                    let arg = self.parse_string_literal()?;
                    self.skip_ws();
                    if self.pos >= self.bytes.len() || self.bytes[self.pos] != b')' {
                        return Err("expected ')' after string method argument");
                    }
                    self.pos += 1;
                    if !is_known_cel_ident(base) {
                        return Err("unknown identifier in boundary expression");
                    }
                    let method_name = match method {
                        "startsWith" => "startsWith",
                        "endsWith" => "endsWith",
                        _ => "contains",
                    };
                    return Ok(CelExpr::StrMethod {
                        target: Box::new(CelExpr::Ident(base.to_owned())),
                        method: method_name,
                        arg,
                    });
                }
            }
        }
        if !is_known_cel_ident(&ident) {
            return Err("unknown identifier in boundary expression");
        }
        Ok(CelExpr::Ident(ident))
    }

    fn parse_string_literal(&mut self) -> Result<String, &'static str> {
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return Err("expected string literal");
        }
        let quote = self.bytes[self.pos];
        if quote != b'"' && quote != b'\'' {
            return Err("expected string literal");
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == quote {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                if self.pos >= self.bytes.len() {
                    return Err("unterminated escape sequence");
                }
                let esc = self.bytes[self.pos];
                self.pos += 1;
                match esc {
                    b'\\' => out.push('\\'),
                    b'"' => out.push('"'),
                    b'\'' => out.push('\''),
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    _ => return Err("unsupported escape sequence"),
                }
            } else {
                let rest = std::str::from_utf8(&self.bytes[self.pos..])
                    .map_err(|_| "invalid utf-8 in boundary expression")?;
                let ch = rest.chars().next().ok_or("unexpected eof")?;
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }
        Err("unterminated string literal")
    }

    fn parse_string_list(&mut self) -> Result<Vec<String>, &'static str> {
        self.skip_ws();
        if self.pos >= self.bytes.len() || self.bytes[self.pos] != b'[' {
            return Err("expected '['");
        }
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.pos >= self.bytes.len() {
                return Err("unterminated list literal");
            }
            if self.bytes[self.pos] == b']' {
                self.pos += 1;
                return Ok(items);
            }
            if !items.is_empty() {
                if self.bytes[self.pos] != b',' {
                    return Err("expected ',' in list literal");
                }
                self.pos += 1;
                self.skip_ws();
            }
            if items.len() >= 64 {
                return Err("list literal too large");
            }
            items.push(self.parse_string_literal()?);
        }
    }

    fn parse_dotted_ident(&mut self) -> Result<String, &'static str> {
        self.skip_ws();
        let start = self.pos;
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err("expected identifier");
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid identifier")?;
        if s.starts_with('.') || s.ends_with('.') || s.contains("..") {
            return Err("invalid dotted identifier");
        }
        Ok(s.to_owned())
    }
}

fn is_known_cel_ident(ident: &str) -> bool {
    matches!(
        ident,
        "bot"
            | "botId"
            | "tool"
            | "toolRef"
            | "app"
            | "effect"
            | "scope"
            | "intent"
            | "initiator.kind"
            | "initiator.id"
            | "surface"
            | "host"
            | "command"
            | "file"
            | "label"
    )
}

fn parse_cel_rule(rule: &str) -> Result<CelExpr, &'static str> {
    let trimmed = rule.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_BOUNDARY_EXPR_LEN || trimmed.contains('\0') {
        return Err("invalid boundary rule length or control character");
    }
    if trimmed.chars().any(char::is_control) {
        return Err("boundary rule contains control characters");
    }
    let expr = CelParser::new(trimmed).parse_all()?;
    // Top-level rule must evaluate as a boolean predicate.
    match &expr {
        CelExpr::Bool(_)
        | CelExpr::Not(_)
        | CelExpr::And(_, _)
        | CelExpr::Or(_, _)
        | CelExpr::Eq(_, _)
        | CelExpr::Ne(_, _)
        | CelExpr::In(_, _)
        | CelExpr::StrMethod { .. } => Ok(expr),
        _ => Err("boundary rule must evaluate to a boolean"),
    }
}

fn resolve_cel_string(ident: &str, req: &ActionEvalRequest<'_>) -> String {
    let ctx_str = |k: &str| -> Option<String> {
        req.boundary_context
            .and_then(|v| v.get(k))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    match ident {
        "bot" | "botId" => req.bot_id.to_owned(),
        "tool" | "toolRef" => req.tool_ref.to_owned(),
        "app" => req
            .tool_ref
            .split('/')
            .nth(1)
            .filter(|s| !s.is_empty())
            .unwrap_or(req.scope)
            .to_owned(),
        "effect" => req.effect.to_owned(),
        "scope" => req.scope.to_owned(),
        "intent" => ctx_str("intent").unwrap_or_else(|| {
            if is_host_command_tool(req.tool_ref) {
                "run_command".into()
            } else if req.effect.eq_ignore_ascii_case("write") {
                "write_tool".into()
            } else {
                "read_tool".into()
            }
        }),
        "initiator.kind" => req
            .boundary_context
            .and_then(|v| v.get("initiator"))
            .and_then(|v| v.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("person")
            .to_owned(),
        "initiator.id" => req
            .boundary_context
            .and_then(|v| v.get("initiator"))
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
            .unwrap_or(req.actor_id)
            .to_owned(),
        "surface" => ctx_str("surface").unwrap_or_default(),
        "host" => ctx_str("host").unwrap_or_default(),
        "command" => ctx_str("command").unwrap_or_default(),
        "file" => ctx_str("file").unwrap_or_default(),
        "label" => ctx_str("label").unwrap_or_default(),
        _ => String::new(),
    }
}

fn eval_cel_value(expr: &CelExpr, req: &ActionEvalRequest<'_>) -> Result<Value, ()> {
    match expr {
        CelExpr::Bool(b) => Ok(Value::Bool(*b)),
        CelExpr::Str(s) => Ok(Value::String(s.clone())),
        CelExpr::Ident(id) => Ok(Value::String(resolve_cel_string(id, req))),
        CelExpr::Not(inner) => match eval_cel_value(inner, req)? {
            Value::Bool(b) => Ok(Value::Bool(!b)),
            _ => Err(()),
        },
        CelExpr::And(a, b) => {
            let av = eval_cel_value(a, req)?.as_bool().ok_or(())?;
            if !av {
                return Ok(Value::Bool(false));
            }
            let bv = eval_cel_value(b, req)?.as_bool().ok_or(())?;
            Ok(Value::Bool(bv))
        }
        CelExpr::Or(a, b) => {
            let av = eval_cel_value(a, req)?.as_bool().ok_or(())?;
            if av {
                return Ok(Value::Bool(true));
            }
            let bv = eval_cel_value(b, req)?.as_bool().ok_or(())?;
            Ok(Value::Bool(bv))
        }
        CelExpr::Eq(a, b) => Ok(Value::Bool(eval_cel_value(a, req)? == eval_cel_value(b, req)?)),
        CelExpr::Ne(a, b) => Ok(Value::Bool(eval_cel_value(a, req)? != eval_cel_value(b, req)?)),
        CelExpr::In(target, items) => {
            let s = eval_cel_value(target, req)?;
            let Some(val) = s.as_str() else { return Err(()); };
            Ok(Value::Bool(items.iter().any(|item| item == val)))
        }
        CelExpr::StrMethod {
            target,
            method,
            arg,
        } => {
            let s = eval_cel_value(target, req)?;
            let Some(val) = s.as_str() else { return Err(()); };
            let matched = match *method {
                "startsWith" => val.starts_with(arg.as_str()),
                "endsWith" => val.ends_with(arg.as_str()),
                _ => val.contains(arg.as_str()),
            };
            Ok(Value::Bool(matched))
        }
    }
}

fn eval_cel_predicate(rule: &str, req: &ActionEvalRequest<'_>) -> bool {
    let Ok(expr) = parse_cel_rule(rule) else {
        return false;
    };
    matches!(eval_cel_value(&expr, req), Ok(Value::Bool(true)))
}

// ---------- Ownership & Membership Guards ----------

fn verify_actor_bot_conversation(
    c: &Connection,
    organization_id: &str,
    actor_id: &str,
    bot_id: &str,
    conversation_id: &str,
) -> Result<(), ApprovalError> {
    let permitted: bool = c.query_row(
        "SELECT EXISTS(
            SELECT 1
              FROM auth_memberships m
              JOIN auth_users u ON u.id = m.user_id
              JOIN port_bots b ON b.id = ?3 AND b.organization_id = m.organization_id AND b.owner_id = m.user_id
              JOIN port_conversations c ON c.id = ?4 AND c.organization_id = m.organization_id AND c.owner_id = m.user_id
             WHERE m.organization_id = ?1
               AND m.user_id = ?2
               AND u.revoked = 0
               AND c.deleted = 0
        )",
        params![organization_id, actor_id, bot_id, conversation_id],
        |r| r.get(0),
    )?;
    if !permitted {
        return Err(ApprovalError::Unauthorized);
    }
    let bot_list: String = c.query_row(
        "SELECT bot_ids_json FROM port_conversations WHERE id = ?1",
        params![conversation_id],
        |r| r.get(0),
    )?;
    let bots: Vec<String> =
        serde_json::from_str(&bot_list).map_err(|_| ApprovalError::InvalidInput("invalid bot list"))?;
    if !bots.iter().any(|b| b == bot_id) {
        return Err(ApprovalError::Unauthorized);
    }
    Ok(())
}

fn verify_active_member(
    c: &Connection,
    organization_id: &str,
    actor_id: &str,
) -> Result<(), ApprovalError> {
    let active: bool = c.query_row(
        "SELECT EXISTS(
            SELECT 1
              FROM auth_memberships m
              JOIN auth_users u ON u.id = m.user_id
             WHERE m.organization_id = ?1
               AND m.user_id = ?2
               AND u.revoked = 0
        )",
        params![organization_id, actor_id],
        |r| r.get(0),
    )?;
    if !active {
        return Err(ApprovalError::Unauthorized);
    }
    Ok(())
}

// ---------- Programmatic Choke-Point API ----------

struct RuleRow {
    bot_id: String,
    tool_ref: String,
    effect: String,
    scope: String,
    behaviour: RuleBehaviour,
}

fn load_rules(
    c: &Connection,
    organization_id: &str,
    scope_owner_id: &str,
) -> Result<Vec<RuleRow>, ApprovalError> {
    let mut stmt = c.prepare(
        "SELECT bot_id, tool_ref, effect, scope, behaviour
           FROM port_approval_rules
          WHERE organization_id = ?1 AND scope_owner_id = ?2
          ORDER BY created_at DESC, id DESC
          LIMIT ?3",
    )?;
    let rows = stmt
        .query_map(
            params![organization_id, scope_owner_id, (MAX_RULES_PER_SCOPE + 1) as i64],
            |r| {
                let b_str: String = r.get(4)?;
                let behaviour = RuleBehaviour::from_str(&b_str)
                    .ok_or_else(|| rusqlite::Error::InvalidColumnType(4, "behaviour".into(), rusqlite::types::Type::Text))?;
                Ok(RuleRow {
                    bot_id: r.get(0)?,
                    tool_ref: r.get(1)?,
                    effect: r.get(2)?,
                    scope: r.get(3)?,
                    behaviour,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn eval_rule_tier(
    rules: &[RuleRow],
    req: &ActionEvalRequest<'_>,
) -> Option<Result<RuleBehaviour, ()>> {
    if rules.len() > MAX_RULES_PER_SCOPE {
        return Some(Err(()));
    }
    let mut selected: Option<RuleBehaviour> = None;
    for r in rules {
        if matches_pattern(&r.bot_id, req.bot_id)
            && matches_pattern(&r.tool_ref, req.tool_ref)
            && matches_pattern(&r.effect, req.effect)
            && rule_matches_scope(&r.scope, req.scope)
        {
            if selected.is_some_and(|prev| prev != r.behaviour) {
                return Some(Err(()));
            }
            selected = Some(r.behaviour);
        }
    }
    selected.map(Ok)
}

/// Evaluate boundaries, approval settings, org rules, personal rules, and conversation grants
/// in a fail-closed IMMEDIATE transaction.
pub fn evaluate_action(
    conn: &mut Connection,
    req: &ActionEvalRequest<'_>,
) -> Result<PolicyOutcome, ApprovalError> {
    if [
        req.organization_id,
        req.actor_id,
        req.bot_id,
        req.conversation_id,
        req.tool_ref,
        req.effect,
    ]
    .iter()
    .any(|s| !valid_id(s))
        || !valid_scope(req.scope)
    {
        return Err(ApprovalError::InvalidInput("invalid action identifiers"));
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_actor_bot_conversation(
        &tx,
        req.organization_id,
        req.actor_id,
        req.bot_id,
        req.conversation_id,
    )?;

    // 1. Organization Boundaries (when configured).
    let boundary_row: Option<(String, String, String)> = tx
        .query_row(
            "SELECT mode, deny_json, allow_json FROM port_boundaries WHERE organization_id = ?1",
            params![req.organization_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((mode, deny_json, allow_json)) = boundary_row {
        let deny_rules: Vec<String> = serde_json::from_str(&deny_json)
            .map_err(|_| ApprovalError::InvalidInput("corrupt boundary deny rules"))?;
        let allow_rules: Vec<String> = serde_json::from_str(&allow_json)
            .map_err(|_| ApprovalError::InvalidInput("corrupt boundary allow rules"))?;
        if mode == "enforce" {
            for rule in &deny_rules {
                if eval_cel_predicate(rule, req) {
                    tx.commit()?;
                    return Ok(PolicyOutcome {
                        decision: EvaluationDecision::Deny,
                        source: "boundary",
                        reason: format!("Action refused by boundary deny rule: {rule}"),
                        kind: None,
                        closed: false,
                    });
                }
            }
            let allowed_by_boundary = allow_rules.iter().any(|rule| eval_cel_predicate(rule, req));
            if !allowed_by_boundary {
                tx.commit()?;
                return Ok(PolicyOutcome {
                    decision: EvaluationDecision::Deny,
                    source: "boundary",
                    reason: "No boundary allow rule permits this action.".into(),
                    kind: None,
                    closed: false,
                });
            }
        }
    }

    // 2. Approval Settings (host_commands_cap, custom_rules_enabled, action_kinds, execution_mode).
    let settings_row: Option<(bool, bool, String, String, String)> = tx
        .query_row(
            "SELECT enforce_auto_review, custom_rules_enabled, host_commands_cap, action_kinds_json, execution_mode
               FROM port_approval_settings
              WHERE organization_id = ?1",
            params![req.organization_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let (
        _enforce_auto_review,
        custom_rules_enabled,
        host_commands_cap,
        action_kinds_json,
        execution_mode,
    ) = settings_row.unwrap_or((false, true, "ask".into(), "{}".into(), "ask".into()));

    if is_host_command_tool(req.tool_ref) && host_commands_cap == "never" {
        tx.commit()?;
        return Ok(PolicyOutcome {
            decision: EvaluationDecision::Deny,
            source: "safety",
            reason: "Host commands are disabled by organization policy.".into(),
            kind: None,
            closed: false,
        });
    }

    let action_kinds: Map<String, Value> =
        serde_json::from_str(&action_kinds_json).unwrap_or_default();
    let detected_kind = classify_action_kind(req.tool_ref, req.effect).map(str::to_owned);

    if execution_mode == "turbo" {
        tx.commit()?;
        return Ok(PolicyOutcome {
            decision: EvaluationDecision::Allow,
            source: "turbo_mode",
            reason: "Permitted automatically by Turbo execution mode.".into(),
            kind: detected_kind,
            closed: false,
        });
    }

    if let Some(kind) = &detected_kind {
        if let Some(policy) = action_kinds.get(kind).and_then(Value::as_str) {
            if policy == "hand_off" {
                tx.commit()?;
                return Ok(PolicyOutcome {
                    decision: EvaluationDecision::HandOff,
                    source: "safety",
                    reason: format!("Organization requires {kind} actions to be handed off."),
                    kind: Some(kind.clone()),
                    closed: false,
                });
            }
            if policy == "ask" {
                tx.commit()?;
                return Ok(PolicyOutcome {
                    decision: EvaluationDecision::Ask,
                    source: "safety",
                    reason: format!("Organization requires approval every time for {kind} actions."),
                    kind: Some(kind.clone()),
                    closed: true,
                });
            }
        }
    }

    // 3. Organization Approval Rules (strictly higher priority than personal rules).
    let org_rules = load_rules(&tx, req.organization_id, "")?;
    if let Some(res) = eval_rule_tier(&org_rules, req) {
        tx.commit()?;
        return Ok(match res {
            Ok(RuleBehaviour::Allow) => PolicyOutcome {
                decision: EvaluationDecision::Allow,
                source: "team_rule",
                reason: "Permitted by organization approval rule.".into(),
                kind: detected_kind,
                closed: false,
            },
            Ok(RuleBehaviour::PreApproved) => {
                if req.user_explicitly_requested {
                    PolicyOutcome {
                        decision: EvaluationDecision::Allow,
                        source: "team_rule",
                        reason: "Pre-approved by user request and organization rule.".into(),
                        kind: detected_kind,
                        closed: false,
                    }
                } else {
                    PolicyOutcome {
                        decision: EvaluationDecision::Ask,
                        source: "team_rule",
                        reason: "Requires explicit request or approval per organization rule.".into(),
                        kind: detected_kind,
                        closed: false,
                    }
                }
            }
            Ok(RuleBehaviour::Ask) => PolicyOutcome {
                decision: EvaluationDecision::Ask,
                source: "team_rule",
                reason: "Organization approval rule requires asking first.".into(),
                kind: detected_kind,
                closed: false,
            },
            Ok(RuleBehaviour::HandOff) => PolicyOutcome {
                decision: EvaluationDecision::HandOff,
                source: "team_rule",
                reason: "Organization approval rule hands this action off to the person.".into(),
                kind: detected_kind,
                closed: false,
            },
            Err(()) => PolicyOutcome {
                decision: EvaluationDecision::Deny,
                source: "team_rule",
                reason: "Conflicting organization approval rules; failing closed.".into(),
                kind: detected_kind,
                closed: false,
            },
        });
    }

    // 4. Personal Approval Rules (only when custom_rules_enabled).
    if custom_rules_enabled {
        let personal_rules = load_rules(&tx, req.organization_id, req.actor_id)?;
        if let Some(res) = eval_rule_tier(&personal_rules, req) {
            tx.commit()?;
            return Ok(match res {
                Ok(RuleBehaviour::Allow) => PolicyOutcome {
                    decision: EvaluationDecision::Allow,
                    source: "personal_rule",
                    reason: "Permitted by personal approval rule.".into(),
                    kind: detected_kind,
                    closed: false,
                },
                Ok(RuleBehaviour::PreApproved) => {
                    if req.user_explicitly_requested {
                        PolicyOutcome {
                            decision: EvaluationDecision::Allow,
                            source: "personal_rule",
                            reason: "Pre-approved by user request and personal rule.".into(),
                            kind: detected_kind,
                            closed: false,
                        }
                    } else {
                        PolicyOutcome {
                            decision: EvaluationDecision::Ask,
                            source: "personal_rule",
                            reason: "Requires explicit request or approval per personal rule.".into(),
                            kind: detected_kind,
                            closed: false,
                        }
                    }
                }
                Ok(RuleBehaviour::Ask) => PolicyOutcome {
                    decision: EvaluationDecision::Ask,
                    source: "personal_rule",
                    reason: "Personal approval rule requires asking first.".into(),
                    kind: detected_kind,
                    closed: false,
                },
                Ok(RuleBehaviour::HandOff) => PolicyOutcome {
                    decision: EvaluationDecision::HandOff,
                    source: "personal_rule",
                    reason: "Personal approval rule hands this action off to the person.".into(),
                    kind: detected_kind,
                    closed: false,
                },
                Err(()) => PolicyOutcome {
                    decision: EvaluationDecision::Deny,
                    source: "personal_rule",
                    reason: "Conflicting personal approval rules; failing closed.".into(),
                    kind: detected_kind,
                    closed: false,
                },
            });
        }
    }

    // 5. Conversation-scoped grants (from `allow_conversation`).
    let mut conv_stmt = tx.prepare(
        "SELECT bot_id, tool_ref, effect, scope
           FROM port_conversation_grants
          WHERE organization_id = ?1
            AND actor_id = ?2
            AND conversation_id = ?3
          ORDER BY created_at DESC
          LIMIT 512",
    )?;
    let conv_rows = conv_stmt.query_map(
        params![req.organization_id, req.actor_id, req.conversation_id],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        },
    )?;
    let mut has_conv_grant = false;
    for row in conv_rows {
        let (bot_pat, tool_pat, eff_pat, scope_pat) = row?;
        if matches_pattern(&bot_pat, req.bot_id)
            && matches_pattern(&tool_pat, req.tool_ref)
            && matches_pattern(&eff_pat, req.effect)
            && rule_matches_scope(&scope_pat, req.scope)
        {
            has_conv_grant = true;
            break;
        }
    }
    drop(conv_stmt);
    tx.commit()?;

    if has_conv_grant {
        return Ok(PolicyOutcome {
            decision: EvaluationDecision::Allow,
            source: "conversation",
            reason: "Allowed for this conversation.".into(),
            kind: detected_kind,
            closed: false,
        });
    }

    // 6. Auto mode: allow safe read-only & web tools and safe read-only shell commands.
    if execution_mode == "auto" && is_auto_mode_safe_action(req.tool_ref, req.effect, req.scope) {
        return Ok(PolicyOutcome {
            decision: EvaluationDecision::Allow,
            source: "auto_mode",
            reason: "Permitted automatically as a read-only action in Auto mode.".into(),
            kind: detected_kind,
            closed: false,
        });
    }

    // 7. Fail-closed default: require interactive HITL approval.
    Ok(PolicyOutcome {
        decision: EvaluationDecision::Ask,
        source: "default",
        reason: "Requires human approval before execution.".into(),
        kind: detected_kind,
        closed: false,
    })
}

fn fetch_approval_row(
    c: &Connection,
    approval_id: &str,
    organization_id: &str,
    actor_id: &str,
) -> Result<Option<ApprovalRecord>, ApprovalError> {
    c.query_row(
        "SELECT id, organization_id, actor_id, bot_id, conversation_id, run_id, tool_call_id,
                tool_ref, effect, scope, thread_id, args_json, target_json, account, policy_json,
                action_digest, status, decision, result_json, created_at, decided_at,
                consumed_at, completed_at, expires_at
           FROM port_approvals
          WHERE id = ?1 AND organization_id = ?2 AND actor_id = ?3",
        params![approval_id, organization_id, actor_id],
        row_to_approval_record,
    )
    .optional()
    .map_err(ApprovalError::from)
}

fn row_to_approval_record(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRecord> {
    Ok(ApprovalRecord {
        id: r.get(0)?,
        organization_id: r.get(1)?,
        actor_id: r.get(2)?,
        bot_id: r.get(3)?,
        conversation_id: r.get(4)?,
        run_id: r.get(5)?,
        tool_call_id: r.get(6)?,
        tool_ref: r.get(7)?,
        effect: r.get(8)?,
        scope: r.get(9)?,
        thread_id: r.get(10)?,
        args_json: r.get(11)?,
        target_json: r.get(12)?,
        account: r.get(13)?,
        policy_json: r.get(14)?,
        action_digest: r.get(15)?,
        status: r.get(16)?,
        decision: r.get(17)?,
        result_json: r.get(18)?,
        created_at: r.get(19)?,
        decided_at: r.get(20)?,
        consumed_at: r.get(21)?,
        completed_at: r.get(22)?,
        expires_at: r.get(23)?,
    })
}

/// Create a pending HITL approval bound to the canonical SHA-256 `action_digest`.
pub fn create_pending_approval(
    conn: &mut Connection,
    req: &CreatePendingApprovalRequest<'_>,
) -> Result<ApprovalRecord, ApprovalError> {
    if [
        req.organization_id,
        req.actor_id,
        req.bot_id,
        req.conversation_id,
        req.run_id,
        req.tool_ref,
        req.effect,
        req.thread_id,
    ]
    .iter()
    .any(|s| !valid_id(s))
        || !valid_scope(req.scope)
        || req.tool_call_id.is_some_and(|s| !valid_id(s))
        || req.account.is_some_and(|s| !valid_id(s))
    {
        return Err(ApprovalError::InvalidInput("invalid approval fields"));
    }
    let ttl = req.ttl_seconds.unwrap_or(DEFAULT_APPROVAL_TTL_SECS);
    if !(1..=MAX_APPROVAL_TTL_SECS).contains(&ttl) {
        return Err(ApprovalError::InvalidInput("invalid approval ttl"));
    }
    let args_json = serde_json::to_string(req.args)
        .map_err(|_| ApprovalError::InvalidInput("invalid args json"))?;
    if args_json.len() > MAX_ARGS_BYTES {
        return Err(ApprovalError::InvalidInput("args too large"));
    }
    let target_json = match req.target {
        Some(t) => Some(
            serde_json::to_string(t)
                .map_err(|_| ApprovalError::InvalidInput("invalid target json"))?,
        ),
        None => None,
    };
    let policy_json = match req.policy {
        Some(p) => Some(
            serde_json::to_string(p)
                .map_err(|_| ApprovalError::InvalidInput("invalid policy json"))?,
        ),
        None => None,
    };
    let digest = compute_action_digest(
        req.organization_id,
        req.actor_id,
        req.bot_id,
        req.conversation_id,
        req.tool_ref,
        req.effect,
        req.scope,
        req.args,
    )?;
    let id = random_id("appr_")?;
    let now = now_secs()?;
    let expires_at = now.checked_add(ttl).ok_or(ApprovalError::Clock)?;

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_actor_bot_conversation(
        &tx,
        req.organization_id,
        req.actor_id,
        req.bot_id,
        req.conversation_id,
    )?;
    tx.execute(
        "INSERT INTO port_approvals (
            id, organization_id, actor_id, bot_id, conversation_id, run_id, tool_call_id,
            tool_ref, effect, scope, thread_id, args_json, target_json, account, policy_json,
            action_digest, status, decision, result_json, created_at, decided_at,
            consumed_at, completed_at, expires_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
            ?16, 'pending', NULL, NULL, ?17, NULL,
            NULL, NULL, ?18
        )",
        params![
            id,
            req.organization_id,
            req.actor_id,
            req.bot_id,
            req.conversation_id,
            req.run_id,
            req.tool_call_id,
            req.tool_ref,
            req.effect,
            req.scope,
            req.thread_id,
            args_json,
            target_json,
            req.account,
            policy_json,
            digest.as_slice(),
            now,
            expires_at,
        ],
    )?;
    let record = fetch_approval_row(&tx, &id, req.organization_id, req.actor_id)?
        .ok_or(ApprovalError::NotFound)?;
    tx.commit()?;
    Ok(record)
}

/// Atomically consume an approved HITL approval (`approved -> consumed`, `rows_changed == 1`)
/// after verifying membership, ownership, non-revocation, expiry, and SHA-256 `action_digest`.
pub fn consume_approved_action(
    conn: &mut Connection,
    req: &ConsumeApprovalRequest<'_>,
) -> Result<ApprovalRecord, ApprovalError> {
    let now = now_secs()?;
    consume_approved_action_at(conn, req, now)
}

/// Deterministic-clock variant of `consume_approved_action` for expiry verification.
pub fn consume_approved_action_at(
    conn: &mut Connection,
    req: &ConsumeApprovalRequest<'_>,
    now: i64,
) -> Result<ApprovalRecord, ApprovalError> {
    if [
        req.approval_id,
        req.organization_id,
        req.actor_id,
        req.bot_id,
        req.conversation_id,
        req.tool_ref,
        req.effect,
    ]
    .iter()
    .any(|s| !valid_id(s))
        || !valid_scope(req.scope)
    {
        return Err(ApprovalError::InvalidInput("invalid consume identifiers"));
    }
    let expected_digest = compute_action_digest(
        req.organization_id,
        req.actor_id,
        req.bot_id,
        req.conversation_id,
        req.tool_ref,
        req.effect,
        req.scope,
        req.args,
    )?;

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_actor_bot_conversation(
        &tx,
        req.organization_id,
        req.actor_id,
        req.bot_id,
        req.conversation_id,
    )?;

    let existing = fetch_approval_row(&tx, req.approval_id, req.organization_id, req.actor_id)?
        .ok_or(ApprovalError::NotFound)?;

    if existing.bot_id != req.bot_id
        || existing.conversation_id != req.conversation_id
        || existing.action_digest.as_slice() != expected_digest.as_slice()
    {
        return Err(ApprovalError::DigestMismatch);
    }
    if now >= existing.expires_at {
        return Err(ApprovalError::Expired);
    }
    if existing.status != "approved"
        || !matches!(
            existing.decision.as_deref(),
            Some("allow_once" | "allow_conversation" | "allow_always")
        )
    {
        return Err(ApprovalError::Conflict(
            "approval is not in consumable approved state",
        ));
    }

    let rows_changed = tx.execute(
        "UPDATE port_approvals
            SET status = 'consumed',
                consumed_at = ?1
          WHERE id = ?2
            AND organization_id = ?3
            AND actor_id = ?4
            AND bot_id = ?5
            AND conversation_id = ?6
            AND action_digest = ?7
            AND status = 'approved'
            AND decision IN ('allow_once', 'allow_conversation', 'allow_always')
            AND expires_at > ?1",
        params![
            now,
            req.approval_id,
            req.organization_id,
            req.actor_id,
            req.bot_id,
            req.conversation_id,
            expected_digest.as_slice(),
        ],
    )?;
    if rows_changed != 1 {
        return Err(ApprovalError::Conflict(
            "approval could not be atomically consumed",
        ));
    }
    let updated = fetch_approval_row(&tx, req.approval_id, req.organization_id, req.actor_id)?
        .ok_or(ApprovalError::NotFound)?;
    tx.commit()?;
    Ok(updated)
}

/// Atomically mark a consumed approval as `completed` with its outcome (`{}` or `{"error": ...}`).
pub fn complete_approval_execution(
    conn: &mut Connection,
    req: &CompleteApprovalRequest<'_>,
) -> Result<ApprovalRecord, ApprovalError> {
    if [req.approval_id, req.organization_id, req.actor_id]
        .iter()
        .any(|s| !valid_id(s))
    {
        return Err(ApprovalError::InvalidInput("invalid completion identifiers"));
    }
    let result_json = match req.error {
        Some(err) => json!({ "error": err }).to_string(),
        None => json!({}).to_string(),
    };
    let now = now_secs()?;

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_active_member(&tx, req.organization_id, req.actor_id)?;

    let existing = fetch_approval_row(&tx, req.approval_id, req.organization_id, req.actor_id)?
        .ok_or(ApprovalError::NotFound)?;
    if existing.status != "consumed" {
        return Err(ApprovalError::Conflict(
            "approval is not in consumed state",
        ));
    }
    let rows_changed = tx.execute(
        "UPDATE port_approvals
            SET status = 'completed',
                result_json = ?1,
                completed_at = ?2
          WHERE id = ?3
            AND organization_id = ?4
            AND actor_id = ?5
            AND status = 'consumed'",
        params![
            result_json,
            now,
            req.approval_id,
            req.organization_id,
            req.actor_id,
        ],
    )?;
    if rows_changed != 1 {
        return Err(ApprovalError::Conflict(
            "approval could not be completed",
        ));
    }
    let updated = fetch_approval_row(&tx, req.approval_id, req.organization_id, req.actor_id)?
        .ok_or(ApprovalError::NotFound)?;
    tx.commit()?;
    Ok(updated)
}

// ---------- JSON Serialization Helpers ----------

fn approval_record_to_json(r: &ApprovalRecord) -> Value {
    let args_val: Value = serde_json::from_str(&r.args_json).unwrap_or(Value::Null);
    let redacted_args = redact_args(&args_val);
    let mut action = Map::new();
    action.insert("botId".into(), json!(r.bot_id));
    action.insert("toolRef".into(), json!(r.tool_ref));
    action.insert("effect".into(), json!(r.effect));
    action.insert("scope".into(), json!(r.scope));
    action.insert("threadId".into(), json!(r.thread_id));
    if let Some(call_id) = &r.tool_call_id {
        action.insert("toolCallId".into(), json!(call_id));
    }
    if !redacted_args.is_null() {
        action.insert("args".into(), redacted_args);
    }
    if let Some(target_str) = &r.target_json {
        if let Ok(target) = serde_json::from_str::<Value>(target_str) {
            action.insert("target".into(), target);
        }
    }
    if let Some(acc) = &r.account {
        action.insert("account".into(), json!(acc));
    }
    if let Some(pol_str) = &r.policy_json {
        if let Ok(pol) = serde_json::from_str::<Value>(pol_str) {
            action.insert("policy".into(), pol);
        }
    }

    let result_val: Value = match &r.result_json {
        Some(s) => serde_json::from_str(s).unwrap_or(Value::Null),
        None => Value::Null,
    };

    json!({
        "id": r.id,
        "status": r.status,
        "decision": r.decision,
        "result": result_val,
        "createdAt": format_utc(r.created_at),
        "decidedAt": r.decided_at.map(format_utc),
        "consumedAt": r.consumed_at.map(format_utc),
        "completedAt": r.completed_at.map(format_utc),
        "action": Value::Object(action),
    })
}

// ---------- HTTP Response & Auth Helpers ----------

fn problem(status: StatusCode, code: &str, detail: &str) -> Response {
    let category = match status {
        StatusCode::UNAUTHORIZED => "auth",
        StatusCode::FORBIDDEN => "permission",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::BAD_REQUEST => "validation",
        _ => "internal",
    };
    let title = match status {
        StatusCode::UNAUTHORIZED => "Authentication is required.",
        StatusCode::FORBIDDEN => "Permission denied.",
        StatusCode::NOT_FOUND => "Resource not found.",
        StatusCode::CONFLICT => "Conflict.",
        StatusCode::BAD_REQUEST => "Request validation failed.",
        _ => "Service unavailable.",
    };
    let err_slug = code.to_ascii_lowercase().replace('_', "-");
    let mut r = (
        status,
        Json(json!({
            "type": format!("https://open.bot/errors/{err_slug}"),
            "title": title,
            "status": status.as_u16(),
            "detail": detail,
            "code": code,
            "category": category,
            "retryable": status.is_server_error(),
            "requestId": "unavailable",
            "traceId": "unavailable",
        })),
    )
        .into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/problem+json"),
    );
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    r
}

fn unavailable() -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "SERVICE_UNAVAILABLE",
        "Service unavailable.",
    )
}

fn respond_json(status: StatusCode, body: Value, location: Option<&str>) -> Response {
    let mut r = (status, Json(body)).into_response();
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    if let Some(loc) = location {
        if let Ok(val) = axum::http::HeaderValue::from_str(loc) {
            r.headers_mut().insert(header::LOCATION, val);
        }
    }
    r
}

fn respond_no_content() -> Response {
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    r
}

async fn authenticate(
    s: &AuthState,
    h: &HeaderMap,
    org: &str,
    write: bool,
) -> Result<Identity, Response> {
    if write && !s.valid_origin(h).await {
        return Err(problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Forbidden."));
    }
    match local_auth::identity(s, h).await {
        Ok(Some(i)) if i.organization == org || i.slug == org => Ok(i),
        Ok(Some(_)) => Err(problem(
            StatusCode::NOT_FOUND,
            "ORGANIZATION_NOT_FOUND",
            "Couldn't find that organization.",
        )),
        Ok(None) => Err(problem(
            StatusCode::UNAUTHORIZED,
            "AUTH_UNAUTHENTICATED",
            "Authentication required.",
        )),
        Err(()) => Err(unavailable()),
    }
}

fn require_admin(i: &Identity) -> Result<(), Response> {
    if matches!(i.role.as_str(), "owner" | "admin") {
        Ok(())
    } else {
        Err(problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Only an admin can do this.",
        ))
    }
}

fn require_self(i: &Identity, person: &str) -> Result<(), Response> {
    if person == "me" || person == i.id {
        Ok(())
    } else {
        Err(problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Only they can see or answer what their Bots are waiting on.",
        ))
    }
}

fn extract_idem_key(h: &HeaderMap) -> Result<String, Response> {
    let mut values = h.get_all("idempotency-key").iter();
    match (values.next(), values.next()) {
        (Some(v), None) => match v.to_str() {
            Ok(s) if !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control) => {
                Ok(s.to_owned())
            }
            _ => Err(problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Invalid Idempotency-Key.",
            )),
        },
        _ => Err(problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Idempotency-Key is required.",
        )),
    }
}

fn hash_fingerprint(parts: &[&str]) -> Vec<u8> {
    let mut d = Sha256::new();
    for part in parts {
        d.update(part.as_bytes());
        d.update([0]);
    }
    d.finalize().to_vec()
}

async fn run_db<F, T>(s: &AuthState, f: F) -> Result<T, Response>
where
    F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    T: Send + 'static,
{
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return Err(unavailable());
    };
    let db = s.db.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(f)
    })
    .await
    {
        Ok(Ok(val)) => Ok(val),
        _ => Err(unavailable()),
    }
}

// ---------- Pagination Cursor Helpers ----------

#[derive(Serialize, Deserialize)]
struct KeysetCursor {
    v: u8,
    org: String,
    fh: String,
    ts: i64,
    id: String,
}

fn encode_cursor(org: &str, fh: &str, ts: i64, id: &str) -> Result<String, StorageError> {
    let payload = KeysetCursor {
        v: 1,
        org: org.to_owned(),
        fh: fh.to_owned(),
        ts,
        id: id.to_owned(),
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|_| StorageError::InvalidDatabase("cursor encode error"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(
    cursor: Option<&str>,
    org: &str,
    fh: &str,
) -> Result<Option<(i64, String)>, Response> {
    let Some(c) = cursor else {
        return Ok(None);
    };
    if c.is_empty()
        || c.len() > 4096
        || !c
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid cursor.",
        ));
    }
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(c) else {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid cursor.",
        ));
    };
    let Ok(parsed) = serde_json::from_slice::<KeysetCursor>(&bytes) else {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid cursor.",
        ));
    };
    if parsed.v != 1 || parsed.org != org || parsed.fh != fh {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid cursor.",
        ));
    }
    Ok(Some((parsed.ts, parsed.id)))
}

fn parse_limit(limit: Option<usize>) -> Result<usize, Response> {
    let limit = limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Limit must be between 1 and 100.",
        ));
    }
    Ok(limit)
}

// ---------- Policy Audit Helper ----------

fn append_policy_audit(
    tx: &Connection,
    org_id: &str,
    actor_id: &str,
    event_type: &str,
    target_type: &str,
    target_id: Option<&str>,
    payload: Value,
    now: i64,
) -> Result<(), StorageError> {
    let id = random_id("paud_").map_err(|_| StorageError::InvalidDatabase("entropy unavailable"))?;
    tx.execute(
        "INSERT INTO port_policy_audit_events(id, organization_id, actor_id, event_type, target_type, target_id, payload_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            org_id,
            actor_id,
            event_type,
            target_type,
            target_id,
            payload.to_string(),
            now,
        ],
    )?;
    Ok(())
}

// ---------- Idempotency Store Helpers ----------

enum IdemOutcome {
    Proceed,
    Replay(Response),
}

fn check_api_idem(
    tx: &Connection,
    org_id: &str,
    actor_id: &str,
    key: &str,
    fp: &[u8],
    now: i64,
) -> Result<IdemOutcome, StorageError> {
    tx.execute(
        "DELETE FROM port_approval_api_idem WHERE created_at < ?1",
        params![now - IDEM_TTL_SECS],
    )?;
    let existing: Option<(Vec<u8>, u16, String, Option<String>)> = tx
        .query_row(
            "SELECT fingerprint, status, body, location
               FROM port_approval_api_idem
              WHERE organization_id = ?1 AND actor_id = ?2 AND idem_key = ?3",
            params![org_id, actor_id, key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((old_fp, status, body, loc)) = existing else {
        return Ok(IdemOutcome::Proceed);
    };
    if old_fp != fp {
        return Ok(IdemOutcome::Replay(problem(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_KEY_CONFLICT",
            "That Idempotency-Key was used for a different request.",
        )));
    }
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    if code == StatusCode::NO_CONTENT {
        return Ok(IdemOutcome::Replay(respond_no_content()));
    }
    let val: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    Ok(IdemOutcome::Replay(respond_json(code, val, loc.as_deref())))
}

fn store_api_idem(
    tx: &Connection,
    org_id: &str,
    actor_id: &str,
    key: &str,
    fp: &[u8],
    status: u16,
    body: &str,
    location: Option<&str>,
    now: i64,
) -> Result<(), StorageError> {
    tx.execute(
        "INSERT INTO port_approval_api_idem(organization_id, actor_id, idem_key, fingerprint, status, body, location, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![org_id, actor_id, key, fp, status, body, location, now],
    )?;
    Ok(())
}

// ---------- Handlers: Approvals (list & decide) ----------

#[derive(Deserialize, Default)]
struct PageQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn list_approvals(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<PageQuery>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_self(&i, &person) {
        return e;
    }
    let limit = match parse_limit(q.limit) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let fh = format!("approvals:{}", i.id);
    let cursor = match decode_cursor(q.cursor.as_deref(), &i.organization, &fh) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let org_id = i.organization.clone();
    let actor_id = i.id.clone();

    let res = run_db(&s, move |c| {
        let mut stmt = match cursor {
            Some((ts, id)) => {
                let mut st = c.prepare(
                    "SELECT id, organization_id, actor_id, bot_id, conversation_id, run_id, tool_call_id,
                            tool_ref, effect, scope, thread_id, args_json, target_json, account, policy_json,
                            action_digest, status, decision, result_json, created_at, decided_at,
                            consumed_at, completed_at, expires_at
                       FROM port_approvals
                      WHERE organization_id = ?1 AND actor_id = ?2
                        AND (created_at < ?3 OR (created_at = ?3 AND id < ?4))
                      ORDER BY created_at DESC, id DESC
                      LIMIT ?5",
                )?;
                let rows = st
                    .query_map(
                        params![org_id, actor_id, ts, id, (limit + 1) as i64],
                        row_to_approval_record,
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                return build_approval_page(rows, limit, &org_id, &fh);
            }
            None => c.prepare(
                "SELECT id, organization_id, actor_id, bot_id, conversation_id, run_id, tool_call_id,
                        tool_ref, effect, scope, thread_id, args_json, target_json, account, policy_json,
                        action_digest, status, decision, result_json, created_at, decided_at,
                        consumed_at, completed_at, expires_at
                   FROM port_approvals
                  WHERE organization_id = ?1 AND actor_id = ?2
                  ORDER BY created_at DESC, id DESC
                  LIMIT ?3",
            )?,
        };
        let rows = stmt
            .query_map(params![org_id, actor_id, (limit + 1) as i64], row_to_approval_record)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        build_approval_page(rows, limit, &org_id, &fh)
    })
    .await;

    match res {
        Ok(v) => respond_json(StatusCode::OK, v, None),
        Err(e) => e,
    }
}

fn build_approval_page(
    mut rows: Vec<ApprovalRecord>,
    limit: usize,
    org_id: &str,
    fh: &str,
) -> Result<Value, StorageError> {
    let has_more = rows.len() > limit;
    if has_more {
        rows.pop();
    }
    let next = if has_more {
        rows.last()
            .map(|r| encode_cursor(org_id, fh, r.created_at, &r.id))
            .transpose()?
    } else {
        None
    };
    let items: Vec<Value> = rows.iter().map(approval_record_to_json).collect();
    Ok(json!({ "approvals": items, "nextCursor": next }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideApprovalBody {
    decision: String,
}

async fn decide_approval(
    State(s): State<AuthState>,
    Extension(runs_state): Extension<Option<runs::RunState>>,
    Path((org, person, approval_id)): Path<(String, String, String)>,
    h: HeaderMap,
    Json(body): Json<DecideApprovalBody>,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_self(&i, &person) {
        return e;
    }
    if !valid_id(&approval_id) {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid approval id.",
        );
    }
    if !matches!(
        body.decision.as_str(),
        "allow_once" | "allow_conversation" | "allow_always" | "deny" | "handled"
    ) {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid approval decision.",
        );
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let now = match now_secs() {
        Ok(n) => n,
        Err(_) => return unavailable(),
    };
    let fp = hash_fingerprint(&["DECIDE", &approval_id, &body.decision]);
    let org_id = i.organization.clone();
    let actor_id = i.id.clone();
    let decision = body.decision;

    enum DecideResult {
        Ok(Value),
        Replay(u16, Value),
        IdemConflict,
        NotFound,
        Refused(&'static str),
    }

    let decision_for_resume = decision.clone();
    let approval_id_for_resume = approval_id.clone();
    let res = run_db(&s, move |c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Fail-closed revocation re-check.
        let active: bool = tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM auth_memberships m
                JOIN auth_users u ON u.id = m.user_id
                WHERE m.organization_id = ?1 AND m.user_id = ?2 AND u.revoked = 0
            )",
            params![org_id, actor_id],
            |r| r.get(0),
        )?;
        if !active {
            return Ok(DecideResult::NotFound);
        }

        tx.execute(
            "DELETE FROM port_approval_decide_idem WHERE created_at < ?1",
            params![now - IDEM_TTL_SECS],
        )?;
        let existing_idem: Option<(Vec<u8>, u16, String)> = tx
            .query_row(
                "SELECT fingerprint, status, body
                   FROM port_approval_decide_idem
                  WHERE organization_id = ?1 AND actor_id = ?2 AND approval_id = ?3 AND idem_key = ?4",
                params![org_id, actor_id, approval_id, key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((old_fp, status, body_str)) = existing_idem {
            if old_fp != fp {
                return Ok(DecideResult::IdemConflict);
            }
            let val: Value = serde_json::from_str(&body_str).unwrap_or(Value::Null);
            return Ok(DecideResult::Replay(status, val));
        }

        let Some(record) = fetch_approval_row(&tx, &approval_id, &org_id, &actor_id)
            .map_err(|_| StorageError::InvalidDatabase("approval lookup failed"))?
        else {
            return Ok(DecideResult::NotFound);
        };
        if record.status != "pending" {
            return Ok(DecideResult::Refused("This request was already decided."));
        }
        if now >= record.expires_at && decision != "deny" {
            return Ok(DecideResult::Refused("This approval request has expired."));
        }

        let policy_val: Option<Value> = record
            .policy_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        let closed = policy_val
            .as_ref()
            .and_then(|v| v.get("closed"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if closed && !matches!(decision.as_str(), "allow_once" | "deny") {
            return Ok(DecideResult::Refused(
                "Your admin set this to ask every time. Allow it once, or deny it.",
            ));
        }
        if decision == "handled" {
            if let Some(beh) = policy_val
                .as_ref()
                .and_then(|v| v.get("behaviour"))
                .and_then(Value::as_str)
            {
                if beh != "hand_off" {
                    return Ok(DecideResult::Refused(
                        "Only actions handed off to the person can be marked handled.",
                    ));
                }
            }
        }

        let policy_kind = policy_val
            .as_ref()
            .and_then(|v| v.get("kind"))
            .and_then(Value::as_str)
            .map(str::to_owned);

        if decision == "allow_always" {
            let custom_enabled: bool = tx
                .query_row(
                    "SELECT custom_rules_enabled FROM port_approval_settings WHERE organization_id = ?1",
                    params![org_id],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(true);
            if !custom_enabled {
                return Ok(DecideResult::Refused(
                    "Your workspace has switched custom rules off, so personal rules cannot be edited.",
                ));
            }
            let rule_scope = standing_rule_scope_for_record(&record.tool_ref, &record.scope);
            let exists_identical: bool = tx.query_row(
                "SELECT EXISTS(
                    SELECT 1
                      FROM port_approval_rules
                     WHERE organization_id = ?1
                       AND scope_owner_id = ?2
                       AND bot_id = ?3
                       AND tool_ref = ?4
                       AND effect = ?5
                       AND scope = ?6
                       AND behaviour = 'allow'
                )",
                params![
                    org_id,
                    actor_id,
                    record.bot_id,
                    record.tool_ref,
                    record.effect,
                    rule_scope,
                ],
                |r| r.get(0),
            )?;
            if !exists_identical {
                let rule_id = random_id("rule_")
                    .map_err(|_| StorageError::InvalidDatabase("entropy unavailable"))?;
                tx.execute(
                    "INSERT INTO port_approval_rules(
                        id, organization_id, scope_owner_id, bot_id, tool_ref, effect, scope,
                        behaviour, account, kind, created_by, created_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'allow', ?8, ?9, ?3, ?10)",
                    params![
                        rule_id,
                        org_id,
                        actor_id,
                        record.bot_id,
                        record.tool_ref,
                        record.effect,
                        rule_scope,
                        record.account,
                        policy_kind,
                        now,
                    ],
                )?;
            }
        } else if decision == "allow_conversation" {
            let grant_scope = standing_rule_scope_for_record(&record.tool_ref, &record.scope);
            let exists_identical: bool = tx.query_row(
                "SELECT EXISTS(
                    SELECT 1
                      FROM port_conversation_grants
                     WHERE organization_id = ?1
                       AND actor_id = ?2
                       AND conversation_id = ?3
                       AND bot_id = ?4
                       AND tool_ref = ?5
                       AND effect = ?6
                       AND scope = ?7
                )",
                params![
                    org_id,
                    actor_id,
                    record.conversation_id,
                    record.bot_id,
                    record.tool_ref,
                    record.effect,
                    grant_scope,
                ],
                |r| r.get(0),
            )?;
            if !exists_identical {
                let grant_id = random_id("cgrant_")
                    .map_err(|_| StorageError::InvalidDatabase("entropy unavailable"))?;
                tx.execute(
                    "INSERT INTO port_conversation_grants(
                        id, organization_id, actor_id, conversation_id, thread_id,
                        bot_id, tool_ref, effect, scope, account, kind, created_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        grant_id,
                        org_id,
                        actor_id,
                        record.conversation_id,
                        record.thread_id,
                        record.bot_id,
                        record.tool_ref,
                        record.effect,
                        grant_scope,
                        record.account,
                        policy_kind,
                        now,
                    ],
                )?;
            }
        }

        let (new_status, completed_at, result_json): (&str, Option<i64>, Option<&str>) =
            match decision.as_str() {
                "deny" => ("denied", None, None),
                "handled" => ("completed", Some(now), Some("{}")),
                _ => ("approved", None, None),
            };
        let rows_changed = tx.execute(
            "UPDATE port_approvals
                SET status = ?1,
                    decision = ?2,
                    decided_at = ?3,
                    result_json = COALESCE(?4, result_json),
                    completed_at = COALESCE(?5, completed_at)
              WHERE id = ?6
                AND organization_id = ?7
                AND actor_id = ?8
                AND status = 'pending'
                AND (expires_at > ?3 OR ?2 = 'deny')",
            params![
                new_status,
                decision,
                now,
                result_json,
                completed_at,
                approval_id,
                org_id,
                actor_id,
            ],
        )?;
        if rows_changed != 1 {
            return Ok(DecideResult::Refused("This request was already decided."));
        }

        let updated = fetch_approval_row(&tx, &approval_id, &org_id, &actor_id)
            .map_err(|_| StorageError::InvalidDatabase("approval lookup failed"))?
            .ok_or(StorageError::InvalidDatabase("missing updated approval"))?;
        let resp_val = approval_record_to_json(&updated);
        tx.execute(
            "INSERT INTO port_approval_decide_idem(
                organization_id, actor_id, approval_id, idem_key, fingerprint, status, body, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, 200, ?6, ?7)",
            params![org_id, actor_id, approval_id, key, fp, resp_val.to_string(), now],
        )?;
        tx.commit()?;
        Ok(DecideResult::Ok(resp_val))
    })
    .await;

    match res {
        Ok(DecideResult::Ok(v)) => {
            if let Some(rs) = runs_state {
                if matches!(
                    decision_for_resume.as_str(),
                    "allow_once" | "allow_conversation" | "allow_always" | "deny"
                ) {
                    runs::spawn_approval_resume(rs, i.organization, i.id, approval_id_for_resume);
                }
            }
            respond_json(StatusCode::OK, v, None)
        }
        Ok(DecideResult::Replay(code, v)) => {
            respond_json(StatusCode::from_u16(code).unwrap_or(StatusCode::OK), v, None)
        }
        Ok(DecideResult::IdemConflict) => problem(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_KEY_CONFLICT",
            "That Idempotency-Key was used for a different request.",
        ),
        Ok(DecideResult::NotFound) => problem(
            StatusCode::NOT_FOUND,
            "APPROVAL_NOT_FOUND",
            "This approval could not be found.",
        ),
        Ok(DecideResult::Refused(msg)) => problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg),
        Err(e) => e,
    }
}

async fn delete_approval(
    State(s): State<AuthState>,
    Path((org, person, approval_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_self(&i, &person) {
        return e;
    }
    if !valid_id(&approval_id) {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid approval id.",
        );
    }
    let org_id = i.organization.clone();
    let actor_id = i.id.clone();
    let res = run_db(&s, move |c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: bool = tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM auth_memberships m
                JOIN auth_users u ON u.id = m.user_id
                WHERE m.organization_id = ?1 AND m.user_id = ?2 AND u.revoked = 0
            )",
            params![org_id, actor_id],
            |r| r.get(0),
        )?;
        if !active {
            return Ok(None);
        }
        let deleted = tx.execute(
            "DELETE FROM port_approvals WHERE id = ?1 AND organization_id = ?2 AND actor_id = ?3",
            params![approval_id, org_id, actor_id],
        )?;
        tx.commit()?;
        Ok(Some(deleted > 0))
    })
    .await;

    match res {
        Ok(Some(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Some(false)) | Ok(None) => problem(
            StatusCode::NOT_FOUND,
            "APPROVAL_NOT_FOUND",
            "This approval could not be found.",
        ),
        Err(e) => e,
    }
}

async fn run_computer_step(
    State(s): State<AuthState>,
    Extension(runs_state): Extension<Option<runs::RunState>>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_self(&i, &person) {
        return e;
    }
    let Some(bot_id) = body.get("botId").and_then(Value::as_str).map(str::to_owned) else {
        return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "botId is required.");
    };
    let Some(conv_obj) = body.get("conversation").and_then(Value::as_object) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "conversation is required.",
        );
    };
    let thread_id = conv_obj
        .get("threadId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let tool_call_id = conv_obj
        .get("toolCallId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let tool_name = conv_obj
        .get("toolName")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let args = conv_obj.get("args").cloned().unwrap_or_else(|| json!({}));
    if !valid_id(&bot_id) || !valid_id(&thread_id) || !valid_id(&tool_name) {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid step parameters.",
        );
    }

    let effect = match tool_name.as_str() {
        "computer_write_file" | "computer_run_command" | "computer_click" | "computer_type"
        | "computer_key" => "write",
        _ => "read",
    };
    let scope = extract_tool_scope(&args);

    enum StepEval {
        Allow,
        Deny(String),
        Waiting { id: String, reason: String },
        NoConversation,
    }

    let org_c = i.organization.clone();
    let act_c = i.id.clone();
    let bot_c = bot_id.clone();
    let thread_c = thread_id.clone();
    let tc_c = tool_call_id.clone();
    let tool_c = tool_name.clone();
    let eff_c = effect.to_owned();
    let scope_c = scope.clone();
    let args_c = args.clone();
    let eval_res = run_db(&s, move |c| {
        let conv_id: Option<String> = c
            .query_row(
                "SELECT id FROM port_conversations WHERE thread_id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0 LIMIT 1",
                params![thread_c, org_c, act_c],
                |r| r.get(0),
            )
            .optional()?;
        let Some(conv_id) = conv_id else {
            return Ok(StepEval::NoConversation);
        };
        if !tc_c.is_empty() {
            let pending: Option<(String, Option<String>)> = c
                .query_row(
                    "SELECT id, policy_json FROM port_approvals WHERE organization_id=?1 AND actor_id=?2 AND conversation_id=?3 AND tool_call_id=?4 AND status='pending' ORDER BY created_at DESC LIMIT 1",
                    params![org_c, act_c, conv_id, tc_c],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((id, policy_json_opt)) = pending {
                let reason = policy_json_opt
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    .and_then(|v| v.get("reason").and_then(Value::as_str).map(str::to_owned))
                    .unwrap_or_else(|| "Approval required before proceeding.".into());
                return Ok(StepEval::Waiting { id, reason });
            }
        }
        let outcome = evaluate_action(
            c,
            &ActionEvalRequest {
                organization_id: &org_c,
                actor_id: &act_c,
                bot_id: &bot_c,
                conversation_id: &conv_id,
                tool_ref: &tool_c,
                effect: &eff_c,
                scope: &scope_c,
                user_explicitly_requested: false,
                boundary_context: None,
            },
        )
        .map_err(|_| StorageError::InvalidDatabase("approval evaluation failed"))?;
        match outcome.decision {
            EvaluationDecision::Allow => Ok(StepEval::Allow),
            EvaluationDecision::Deny => Ok(StepEval::Deny(outcome.reason)),
            EvaluationDecision::Ask | EvaluationDecision::HandOff => {
                let policy_json = outcome.to_policy_json();
                let run_id = conv_obj_run_id(&conv_id, c);
                let rec = create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: &org_c,
                        actor_id: &act_c,
                        bot_id: &bot_c,
                        conversation_id: &conv_id,
                        run_id: &run_id,
                        tool_call_id: if tc_c.is_empty() { None } else { Some(&tc_c) },
                        tool_ref: &tool_c,
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
                .map_err(|_| StorageError::InvalidDatabase("approval creation failed"))?;
                Ok(StepEval::Waiting {
                    id: rec.id,
                    reason: outcome.reason,
                })
            }
        }
    })
    .await;

    match eval_res {
        Ok(StepEval::NoConversation) => problem(
            StatusCode::NOT_FOUND,
            "CONVERSATION_NOT_FOUND",
            "Conversation not found.",
        ),
        Ok(StepEval::Waiting { id, reason }) => respond_json(
            StatusCode::OK,
            json!({ "outcome": "waiting", "approvalId": id, "reason": reason }),
            None,
        ),
        Ok(StepEval::Deny(reason)) => respond_json(
            StatusCode::OK,
            json!({ "outcome": "done", "result": { "ok": false, "refused": true, "reason": reason } }),
            None,
        ),
        Ok(StepEval::Allow) => {
            let Some(vc) = runs_state.and_then(|r| r.virtual_computer_state()) else {
                return respond_json(
                    StatusCode::OK,
                    json!({ "outcome": "done", "result": { "ok": false, "error": "Virtual computer unavailable." } }),
                    None,
                );
            };
            match vc
                .execute_tool_for_owner(&i.organization, &i.id, &bot_id, &tool_name, args)
                .await
            {
                Ok(mut val) => {
                    if let Some(obj) = val.as_object_mut() {
                        obj.entry("ok".to_owned()).or_insert_with(|| json!(true));
                    }
                    respond_json(
                        StatusCode::OK,
                        json!({ "outcome": "done", "result": val }),
                        None,
                    )
                }
                Err(err) => {
                    if err.contains("driving this computer") {
                        respond_json(
                            StatusCode::OK,
                            json!({ "outcome": "held", "error": err, "humanHasControl": true }),
                            None,
                        )
                    } else {
                        respond_json(
                            StatusCode::OK,
                            json!({ "outcome": "done", "result": { "ok": false, "error": err } }),
                            None,
                        )
                    }
                }
            }
        }
        Err(e) => e,
    }
}

fn conv_obj_run_id(conv_id: &str, c: &Connection) -> String {
    c.query_row(
        "SELECT id FROM port_runs WHERE conversation_id=?1 ORDER BY created_at DESC, rowid DESC LIMIT 1",
        params![conv_id],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .ok()
    .flatten()
    .unwrap_or_else(|| format!("step_{conv_id}"))
}

// ---------- Handlers: Approval Rules CRUD (Org & Personal) ----------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleInputBody {
    bot_id: Option<String>,
    tool_ref: String,
    effect: Option<String>,
    scope: Option<String>,
    behaviour: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleChangeBody {
    bot_id: Option<String>,
    tool_ref: Option<String>,
    effect: Option<String>,
    scope: Option<String>,
    behaviour: Option<String>,
}

fn rule_row_to_json(r: &rusqlite::Row<'_>, personal: bool) -> rusqlite::Result<Value> {
    let id: String = r.get(0)?;
    let bot_id: String = r.get(1)?;
    let tool_ref: String = r.get(2)?;
    let effect: String = r.get(3)?;
    let scope: String = r.get(4)?;
    let behaviour: String = r.get(5)?;
    let account: Option<String> = r.get(6)?;
    let kind: Option<String> = r.get(7)?;
    let created_by: Option<String> = r.get(8)?;
    let created_at: i64 = r.get(9)?;
    if personal {
        Ok(json!({
            "id": id,
            "botId": bot_id,
            "toolRef": tool_ref,
            "effect": effect,
            "scope": scope,
            "behaviour": behaviour,
            "account": account,
            "kind": kind,
            "createdAt": format_utc(created_at),
        }))
    } else {
        Ok(json!({
            "id": id,
            "botId": bot_id,
            "toolRef": tool_ref,
            "effect": effect,
            "scope": scope,
            "behaviour": behaviour,
            "createdBy": created_by,
            "createdAt": format_utc(created_at),
        }))
    }
}

async fn list_org_rules(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<PageQuery>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    list_rules_impl(&s, &i, "", q, false).await
}

async fn list_person_rules(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<PageQuery>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_self(&i, &person) {
        return e;
    }
    let owner = i.id.clone();
    list_rules_impl(&s, &i, &owner, q, true).await
}

async fn list_rules_impl(
    s: &AuthState,
    i: &Identity,
    scope_owner: &str,
    q: PageQuery,
    personal: bool,
) -> Response {
    let limit = match parse_limit(q.limit) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let fh = format!("rules:{scope_owner}");
    let cursor = match decode_cursor(q.cursor.as_deref(), &i.organization, &fh) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let org_id = i.organization.clone();
    let owner = scope_owner.to_owned();

    let res = run_db(s, move |c| {
        let mut rows: Vec<(Value, i64, String)> = match cursor {
            Some((ts, id)) => {
                let mut st = c.prepare(
                    "SELECT id, bot_id, tool_ref, effect, scope, behaviour, account, kind, created_by, created_at
                       FROM port_approval_rules
                      WHERE organization_id = ?1 AND scope_owner_id = ?2
                        AND (created_at < ?3 OR (created_at = ?3 AND id < ?4))
                      ORDER BY created_at DESC, id DESC
                      LIMIT ?5",
                )?;
                let collected = st
                    .query_map(
                        params![org_id, owner, ts, id, (limit + 1) as i64],
                        |r| Ok((rule_row_to_json(r, personal)?, r.get::<_, i64>(9)?, r.get::<_, String>(0)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                collected
            }
            None => {
                let mut st = c.prepare(
                    "SELECT id, bot_id, tool_ref, effect, scope, behaviour, account, kind, created_by, created_at
                       FROM port_approval_rules
                      WHERE organization_id = ?1 AND scope_owner_id = ?2
                      ORDER BY created_at DESC, id DESC
                      LIMIT ?3",
                )?;
                let collected = st
                    .query_map(
                        params![org_id, owner, (limit + 1) as i64],
                        |r| Ok((rule_row_to_json(r, personal)?, r.get::<_, i64>(9)?, r.get::<_, String>(0)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                collected
            }
        };
        let has_more = rows.len() > limit;
        if has_more {
            rows.pop();
        }
        let next = if has_more {
            rows.last()
                .map(|(_, t, id)| encode_cursor(&org_id, &fh, *t, id))
                .transpose()?
        } else {
            None
        };
        let items: Vec<Value> = rows.into_iter().map(|(v, _, _)| v).collect();
        Ok(json!({ "approvalRules": items, "nextCursor": next }))
    })
    .await;

    match res {
        Ok(v) => respond_json(StatusCode::OK, v, None),
        Err(e) => e,
    }
}

async fn create_org_rule(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<RuleInputBody>,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_admin(&i) {
        return e;
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    create_rule_impl(&s, &i, "", key, body, false).await
}

async fn create_person_rule(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<RuleInputBody>,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_self(&i, &person) {
        return e;
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let owner = i.id.clone();
    create_rule_impl(&s, &i, &owner, key, body, true).await
}

async fn create_rule_impl(
    s: &AuthState,
    i: &Identity,
    scope_owner: &str,
    key: String,
    body: RuleInputBody,
    personal: bool,
) -> Response {
    let Some(bot_id) = valid_pattern(body.bot_id.as_deref().unwrap_or("*")) else {
        return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid botId pattern.");
    };
    let Some(tool_ref) = valid_pattern(&body.tool_ref) else {
        return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid toolRef pattern.");
    };
    let Some(effect) = valid_pattern(body.effect.as_deref().unwrap_or("*")) else {
        return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid effect pattern.");
    };
    let Some(scope) = valid_pattern(body.scope.as_deref().unwrap_or("*")) else {
        return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid scope pattern.");
    };
    let Some(behaviour) = RuleBehaviour::from_str(&body.behaviour) else {
        return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid rule behaviour.");
    };
    let now = match now_secs() {
        Ok(n) => n,
        Err(_) => return unavailable(),
    };
    let rule_id = match random_id("rule_") {
        Ok(id) => id,
        Err(_) => return unavailable(),
    };
    let fp = hash_fingerprint(&[
        if personal { "POST_PERSON_RULE" } else { "POST_ORG_RULE" },
        scope_owner,
        &bot_id,
        &tool_ref,
        &effect,
        &scope,
        behaviour.as_str(),
    ]);
    let org_id = i.organization.clone();
    let actor_id = i.id.clone();
    let owner = scope_owner.to_owned();

    enum CreateOutcome {
        Done(Response),
        CustomRulesDisabled,
    }

    let res = run_db(s, move |c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let IdemOutcome::Replay(resp) = check_api_idem(&tx, &org_id, &actor_id, &key, &fp, now)? {
            return Ok(CreateOutcome::Done(resp));
        }
        if personal {
            let custom_enabled: bool = tx
                .query_row(
                    "SELECT custom_rules_enabled FROM port_approval_settings WHERE organization_id = ?1",
                    params![org_id],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(true);
            if !custom_enabled {
                return Ok(CreateOutcome::CustomRulesDisabled);
            }
        }
        tx.execute(
            "INSERT INTO port_approval_rules(
                id, organization_id, scope_owner_id, bot_id, tool_ref, effect, scope,
                behaviour, account, kind, created_by, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9, ?10)",
            params![
                rule_id,
                org_id,
                owner,
                bot_id,
                tool_ref,
                effect,
                scope,
                behaviour.as_str(),
                actor_id,
                now,
            ],
        )?;
        let resp_val = if personal {
            json!({
                "id": rule_id,
                "botId": bot_id,
                "toolRef": tool_ref,
                "effect": effect,
                "scope": scope,
                "behaviour": behaviour.as_str(),
                "account": null,
                "kind": null,
                "createdAt": format_utc(now),
            })
        } else {
            json!({
                "id": rule_id,
                "botId": bot_id,
                "toolRef": tool_ref,
                "effect": effect,
                "scope": scope,
                "behaviour": behaviour.as_str(),
                "createdBy": actor_id,
                "createdAt": format_utc(now),
            })
        };
        let location = if personal {
            format!("/api/v2/organizations/{org_id}/people/{owner}/approval-rules/{rule_id}")
        } else {
            format!("/api/v2/organizations/{org_id}/approval-rules/{rule_id}")
        };
        append_policy_audit(
            &tx,
            &org_id,
            &actor_id,
            if personal { "person_approval_rule.created" } else { "approval_rule.created" },
            "approval_rule",
            Some(&rule_id),
            resp_val.clone(),
            now,
        )?;
        store_api_idem(
            &tx,
            &org_id,
            &actor_id,
            &key,
            &fp,
            201,
            &resp_val.to_string(),
            Some(&location),
            now,
        )?;
        tx.commit()?;
        Ok(CreateOutcome::Done(respond_json(
            StatusCode::CREATED,
            resp_val,
            Some(&location),
        )))
    })
    .await;

    match res {
        Ok(CreateOutcome::Done(resp)) => resp,
        Ok(CreateOutcome::CustomRulesDisabled) => problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Your workspace has switched custom rules off, so personal rules cannot be edited.",
        ),
        Err(e) => e,
    }
}

async fn update_org_rule(
    State(s): State<AuthState>,
    Path((org, rule_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<RuleChangeBody>,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_admin(&i) {
        return e;
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    update_rule_impl(&s, &i, "", rule_id, key, body, false).await
}

async fn update_person_rule(
    State(s): State<AuthState>,
    Path((org, person, rule_id)): Path<(String, String, String)>,
    h: HeaderMap,
    Json(body): Json<RuleChangeBody>,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_self(&i, &person) {
        return e;
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let owner = i.id.clone();
    update_rule_impl(&s, &i, &owner, rule_id, key, body, true).await
}

async fn update_rule_impl(
    s: &AuthState,
    i: &Identity,
    scope_owner: &str,
    rule_id: String,
    key: String,
    body: RuleChangeBody,
    personal: bool,
) -> Response {
    if !valid_id(&rule_id) {
        return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid approvalRuleId.");
    }
    if body.bot_id.is_none()
        && body.tool_ref.is_none()
        && body.effect.is_none()
        && body.scope.is_none()
        && body.behaviour.is_none()
    {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "At least one field is required.",
        );
    }
    let bot_id = match body.bot_id.as_deref().map(valid_pattern) {
        Some(None) => return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid botId."),
        Some(Some(v)) => Some(v),
        None => None,
    };
    let tool_ref = match body.tool_ref.as_deref().map(valid_pattern) {
        Some(None) => return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid toolRef."),
        Some(Some(v)) => Some(v),
        None => None,
    };
    let effect = match body.effect.as_deref().map(valid_pattern) {
        Some(None) => return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid effect."),
        Some(Some(v)) => Some(v),
        None => None,
    };
    let scope = match body.scope.as_deref().map(valid_pattern) {
        Some(None) => return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid scope."),
        Some(Some(v)) => Some(v),
        None => None,
    };
    let behaviour = match body.behaviour.as_deref() {
        Some(b) => match RuleBehaviour::from_str(b) {
            Some(parsed) => Some(parsed),
            None => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_ERROR",
                    "Invalid behaviour.",
                )
            }
        },
        None => None,
    };
    let now = match now_secs() {
        Ok(n) => n,
        Err(_) => return unavailable(),
    };
    let fp = hash_fingerprint(&[
        if personal { "PATCH_PERSON_RULE" } else { "PATCH_ORG_RULE" },
        scope_owner,
        &rule_id,
        bot_id.as_deref().unwrap_or(""),
        tool_ref.as_deref().unwrap_or(""),
        effect.as_deref().unwrap_or(""),
        scope.as_deref().unwrap_or(""),
        behaviour.map_or("", |b| b.as_str()),
    ]);
    let org_id = i.organization.clone();
    let actor_id = i.id.clone();
    let owner = scope_owner.to_owned();

    enum UpdateOutcome {
        Done(Response),
        NotFound,
        CustomRulesDisabled,
    }

    let res = run_db(s, move |c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let IdemOutcome::Replay(resp) = check_api_idem(&tx, &org_id, &actor_id, &key, &fp, now)? {
            return Ok(UpdateOutcome::Done(resp));
        }
        if personal {
            let custom_enabled: bool = tx
                .query_row(
                    "SELECT custom_rules_enabled FROM port_approval_settings WHERE organization_id = ?1",
                    params![org_id],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(true);
            if !custom_enabled {
                return Ok(UpdateOutcome::CustomRulesDisabled);
            }
        }
        let existing: Option<(String, String, String, String, String, Option<String>, Option<String>, Option<String>, i64)> = tx
            .query_row(
                "SELECT bot_id, tool_ref, effect, scope, behaviour, account, kind, created_by, created_at
                   FROM port_approval_rules
                  WHERE id = ?1 AND organization_id = ?2 AND scope_owner_id = ?3",
                params![rule_id, org_id, owner],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((cur_bot, cur_tool, cur_eff, cur_scope, cur_beh, account, kind, created_by, created_at)) = existing else {
            return Ok(UpdateOutcome::NotFound);
        };
        let new_bot = bot_id.unwrap_or(cur_bot);
        let new_tool = tool_ref.unwrap_or(cur_tool);
        let new_eff = effect.unwrap_or(cur_eff);
        let new_scope = scope.unwrap_or(cur_scope);
        let new_beh = behaviour.map(|b| b.as_str().to_owned()).unwrap_or(cur_beh);
        tx.execute(
            "UPDATE port_approval_rules
                SET bot_id = ?1, tool_ref = ?2, effect = ?3, scope = ?4, behaviour = ?5
              WHERE id = ?6 AND organization_id = ?7 AND scope_owner_id = ?8",
            params![new_bot, new_tool, new_eff, new_scope, new_beh, rule_id, org_id, owner],
        )?;
        let resp_val = if personal {
            json!({
                "id": rule_id,
                "botId": new_bot,
                "toolRef": new_tool,
                "effect": new_eff,
                "scope": new_scope,
                "behaviour": new_beh,
                "account": account,
                "kind": kind,
                "createdAt": format_utc(created_at),
            })
        } else {
            json!({
                "id": rule_id,
                "botId": new_bot,
                "toolRef": new_tool,
                "effect": new_eff,
                "scope": new_scope,
                "behaviour": new_beh,
                "createdBy": created_by,
                "createdAt": format_utc(created_at),
            })
        };
        append_policy_audit(
            &tx,
            &org_id,
            &actor_id,
            if personal { "person_approval_rule.updated" } else { "approval_rule.updated" },
            "approval_rule",
            Some(&rule_id),
            resp_val.clone(),
            now,
        )?;
        store_api_idem(&tx, &org_id, &actor_id, &key, &fp, 200, &resp_val.to_string(), None, now)?;
        tx.commit()?;
        Ok(UpdateOutcome::Done(respond_json(StatusCode::OK, resp_val, None)))
    })
    .await;

    match res {
        Ok(UpdateOutcome::Done(resp)) => resp,
        Ok(UpdateOutcome::NotFound) => problem(
            StatusCode::NOT_FOUND,
            "APPROVAL_RULE_NOT_FOUND",
            "This approval rule could not be found.",
        ),
        Ok(UpdateOutcome::CustomRulesDisabled) => problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Your workspace has switched custom rules off, so personal rules cannot be edited.",
        ),
        Err(e) => e,
    }
}

async fn delete_org_rule(
    State(s): State<AuthState>,
    Path((org, rule_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_admin(&i) {
        return e;
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    delete_rule_impl(&s, &i, "", rule_id, key, false).await
}

async fn delete_person_rule(
    State(s): State<AuthState>,
    Path((org, person, rule_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_self(&i, &person) {
        return e;
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let owner = i.id.clone();
    delete_rule_impl(&s, &i, &owner, rule_id, key, true).await
}

async fn delete_rule_impl(
    s: &AuthState,
    i: &Identity,
    scope_owner: &str,
    rule_id: String,
    key: String,
    personal: bool,
) -> Response {
    if !valid_id(&rule_id) {
        return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid approvalRuleId.");
    }
    let now = match now_secs() {
        Ok(n) => n,
        Err(_) => return unavailable(),
    };
    let fp = hash_fingerprint(&[
        if personal { "DELETE_PERSON_RULE" } else { "DELETE_ORG_RULE" },
        scope_owner,
        &rule_id,
    ]);
    let org_id = i.organization.clone();
    let actor_id = i.id.clone();
    let owner = scope_owner.to_owned();

    enum DeleteOutcome {
        Done(Response),
        NotFound,
    }

    let res = run_db(s, move |c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let IdemOutcome::Replay(resp) = check_api_idem(&tx, &org_id, &actor_id, &key, &fp, now)? {
            return Ok(DeleteOutcome::Done(resp));
        }
        let n = tx.execute(
            "DELETE FROM port_approval_rules
              WHERE id = ?1 AND organization_id = ?2 AND scope_owner_id = ?3",
            params![rule_id, org_id, owner],
        )?;
        if n == 0 {
            return Ok(DeleteOutcome::NotFound);
        }
        append_policy_audit(
            &tx,
            &org_id,
            &actor_id,
            if personal { "person_approval_rule.deleted" } else { "approval_rule.deleted" },
            "approval_rule",
            Some(&rule_id),
            json!({ "id": rule_id }),
            now,
        )?;
        store_api_idem(&tx, &org_id, &actor_id, &key, &fp, 204, "", None, now)?;
        tx.commit()?;
        Ok(DeleteOutcome::Done(respond_no_content()))
    })
    .await;

    match res {
        Ok(DeleteOutcome::Done(resp)) => resp,
        Ok(DeleteOutcome::NotFound) => problem(
            StatusCode::NOT_FOUND,
            "APPROVAL_RULE_NOT_FOUND",
            "This approval rule could not be found.",
        ),
        Err(e) => e,
    }
}

// ---------- Handlers: Approval Settings ----------

fn read_approval_settings(c: &Connection, org_id: &str) -> Result<Value, StorageError> {
    let row: Option<(bool, bool, String, String, String)> = c
        .query_row(
            "SELECT enforce_auto_review, custom_rules_enabled, host_commands_cap, action_kinds_json, execution_mode
               FROM port_approval_settings
              WHERE organization_id = ?1",
            params![org_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let (
        enforce_auto_review,
        custom_rules_enabled,
        host_commands_cap,
        action_kinds_json,
        execution_mode,
    ) = row.unwrap_or((false, true, "ask".into(), "{}".into(), "ask".into()));
    let action_kinds: Value = serde_json::from_str(&action_kinds_json).unwrap_or_else(|_| json!({}));
    Ok(json!({
        "enforceAutoReview": enforce_auto_review,
        "customRulesEnabled": custom_rules_enabled,
        "hostCommandsCap": host_commands_cap,
        "actionKinds": action_kinds,
        "executionMode": execution_mode,
    }))
}

async fn get_approval_settings(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = i.organization;
    match run_db(&s, move |c| read_approval_settings(c, &org_id)).await {
        Ok(v) => respond_json(StatusCode::OK, v, None),
        Err(e) => e,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateApprovalSettingsBody {
    enforce_auto_review: Option<bool>,
    custom_rules_enabled: Option<bool>,
    host_commands_cap: Option<String>,
    action_kinds: Option<Map<String, Value>>,
    execution_mode: Option<String>,
}

async fn update_approval_settings(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<UpdateApprovalSettingsBody>,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_admin(&i) {
        return e;
    }
    if body.enforce_auto_review.is_none()
        && body.custom_rules_enabled.is_none()
        && body.host_commands_cap.is_none()
        && body.action_kinds.is_none()
        && body.execution_mode.is_none()
    {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "At least one setting must be provided.",
        );
    }
    if let Some(cap) = body.host_commands_cap.as_deref() {
        if !matches!(cap, "ask" | "allow" | "never") {
            return problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Invalid hostCommandsCap value.",
            );
        }
    }
    if let Some(mode) = body.execution_mode.as_deref() {
        if !matches!(mode, "ask" | "auto" | "turbo") {
            return problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Invalid executionMode value. Must be ask, auto, or turbo.",
            );
        }
    }
    if let Some(kinds) = &body.action_kinds {
        for (k, v) in kinds {
            if !ACTION_KINDS.contains(&k.as_str()) {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_ERROR",
                    "Unknown action kind.",
                );
            }
            if !matches!(v.as_str(), Some("open" | "ask" | "hand_off")) {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_ERROR",
                    "Invalid action kind policy.",
                );
            }
        }
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let now = match now_secs() {
        Ok(n) => n,
        Err(_) => return unavailable(),
    };
    let body_canon = canonicalize_json(&json!({
        "enforceAutoReview": body.enforce_auto_review,
        "customRulesEnabled": body.custom_rules_enabled,
        "hostCommandsCap": body.host_commands_cap,
        "actionKinds": body.action_kinds,
        "executionMode": body.execution_mode,
    }));
    let fp = hash_fingerprint(&["PATCH_APPROVAL_SETTINGS", &body_canon.to_string()]);
    let org_id = i.organization.clone();
    let actor_id = i.id.clone();

    let res = run_db(&s, move |c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let IdemOutcome::Replay(resp) = check_api_idem(&tx, &org_id, &actor_id, &key, &fp, now)? {
            return Ok(resp);
        }
        let current = read_approval_settings(&tx, &org_id)?;
        let enforce = body
            .enforce_auto_review
            .unwrap_or_else(|| current["enforceAutoReview"].as_bool().unwrap_or(false));
        let custom = body
            .custom_rules_enabled
            .unwrap_or_else(|| current["customRulesEnabled"].as_bool().unwrap_or(true));
        let cap = body
            .host_commands_cap
            .unwrap_or_else(|| current["hostCommandsCap"].as_str().unwrap_or("ask").to_owned());
        let execution_mode = body
            .execution_mode
            .unwrap_or_else(|| current["executionMode"].as_str().unwrap_or("ask").to_owned());
        let mut kinds_map = current["actionKinds"].as_object().cloned().unwrap_or_default();
        if let Some(patch_kinds) = body.action_kinds {
            for (k, v) in patch_kinds {
                kinds_map.insert(k, v);
            }
        }
        let kinds_json = Value::Object(kinds_map.clone()).to_string();
        tx.execute(
            "INSERT INTO port_approval_settings(
                organization_id, enforce_auto_review, custom_rules_enabled, host_commands_cap, action_kinds_json, execution_mode
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(organization_id) DO UPDATE SET
                enforce_auto_review = excluded.enforce_auto_review,
                custom_rules_enabled = excluded.custom_rules_enabled,
                host_commands_cap = excluded.host_commands_cap,
                action_kinds_json = excluded.action_kinds_json,
                execution_mode = excluded.execution_mode",
            params![org_id, enforce, custom, cap, kinds_json, execution_mode],
        )?;
        let resp_val = json!({
            "enforceAutoReview": enforce,
            "customRulesEnabled": custom,
            "hostCommandsCap": cap,
            "actionKinds": kinds_map,
            "executionMode": execution_mode,
        });
        append_policy_audit(
            &tx,
            &org_id,
            &actor_id,
            "approval_settings.updated",
            "approval_settings",
            Some(&org_id),
            resp_val.clone(),
            now,
        )?;
        store_api_idem(
            &tx,
            &org_id,
            &actor_id,
            &key,
            &fp,
            200,
            &resp_val.to_string(),
            None,
            now,
        )?;
        tx.commit()?;
        Ok(respond_json(StatusCode::OK, resp_val, None))
    })
    .await;

    match res {
        Ok(resp) => resp,
        Err(e) => e,
    }
}

// ---------- Handlers: Boundaries ----------

fn read_boundaries_json(c: &Connection, org_id: &str) -> Result<Value, StorageError> {
    let row: Option<(String, String, String, String)> = c
        .query_row(
            "SELECT mode, deny_json, allow_json, labels_json
               FROM port_boundaries
              WHERE organization_id = ?1",
            params![org_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (mode, deny_json, allow_json, labels_json) = row.unwrap_or((
        "enforce".into(),
        "[]".into(),
        "[]".into(),
        "{}".into(),
    ));
    let deny: Value = serde_json::from_str(&deny_json).unwrap_or_else(|_| json!([]));
    let allow: Value = serde_json::from_str(&allow_json).unwrap_or_else(|_| json!([]));
    let labels: Value = serde_json::from_str(&labels_json).unwrap_or_else(|_| json!({}));
    Ok(json!({
        "mode": mode,
        "deny": deny,
        "allow": allow,
        "labels": labels,
    }))
}

async fn get_boundaries(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_admin(&i) {
        return e;
    }
    let org_id = i.organization;
    match run_db(&s, move |c| read_boundaries_json(c, &org_id)).await {
        Ok(v) => respond_json(StatusCode::OK, v, None),
        Err(e) => e,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryLabelInput {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryAuthoringInput {
    source: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundariesInputBody {
    mode: String,
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    labels: BTreeMap<String, BoundaryLabelInput>,
    authoring: Option<BoundaryAuthoringInput>,
}

async fn replace_boundaries(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<BoundariesInputBody>,
) -> Response {
    let i = match authenticate(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_admin(&i) {
        return e;
    }
    if !matches!(body.mode.as_str(), "enforce" | "dry-run") {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Boundary mode must be enforce or dry-run.",
        );
    }
    if body.deny.len() > MAX_BOUNDARY_RULES || body.allow.len() > MAX_BOUNDARY_RULES {
        return problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Too many boundary rules.",
        );
    }
    for expr in body.deny.iter().chain(body.allow.iter()) {
        if let Err(msg) = parse_cel_rule(expr) {
            return problem(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg);
        }
    }
    let rule_set: HashSet<&str> = body
        .deny
        .iter()
        .chain(body.allow.iter())
        .map(String::as_str)
        .collect();
    let mut stored_labels = BTreeMap::new();
    for (rule_key, lbl) in &body.labels {
        let name = lbl.name.trim();
        if name.is_empty()
            || name.chars().count() > 80
            || name.contains('\0')
            || name.chars().any(char::is_control)
        {
            return problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Invalid boundary rule label name.",
            );
        }
        let desc = lbl.description.as_deref().unwrap_or("").trim();
        if desc.chars().count() > 300 || desc.contains('\0') || desc.chars().any(char::is_control) {
            return problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Invalid boundary rule label description.",
            );
        }
        if rule_set.contains(rule_key.as_str()) {
            stored_labels.insert(
                rule_key.clone(),
                json!({ "name": name, "description": desc }),
            );
        }
    }
    if let Some(auth) = &body.authoring {
        let t = auth.text.trim();
        if auth.source != "english" || t.is_empty() || t.chars().count() > 2000 || t.contains('\0') {
            return problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Invalid boundary authoring.",
            );
        }
    }
    let key = match extract_idem_key(&h) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let now = match now_secs() {
        Ok(n) => n,
        Err(_) => return unavailable(),
    };
    let resp_val = json!({
        "mode": body.mode,
        "deny": body.deny,
        "allow": body.allow,
        "labels": stored_labels,
    });
    let fp = hash_fingerprint(&["PUT_BOUNDARIES", &resp_val.to_string()]);
    let org_id = i.organization.clone();
    let actor_id = i.id.clone();
    let deny_json = json!(body.deny).to_string();
    let allow_json = json!(body.allow).to_string();
    let labels_json = json!(stored_labels).to_string();
    let mode = body.mode;

    let res = run_db(&s, move |c| {
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let IdemOutcome::Replay(resp) = check_api_idem(&tx, &org_id, &actor_id, &key, &fp, now)? {
            return Ok(resp);
        }
        tx.execute(
            "INSERT INTO port_boundaries(organization_id, mode, deny_json, allow_json, labels_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(organization_id) DO UPDATE SET
                mode = excluded.mode,
                deny_json = excluded.deny_json,
                allow_json = excluded.allow_json,
                labels_json = excluded.labels_json",
            params![org_id, mode, deny_json, allow_json, labels_json],
        )?;
        append_policy_audit(
            &tx,
            &org_id,
            &actor_id,
            "boundaries.updated",
            "boundaries",
            Some(&org_id),
            resp_val.clone(),
            now,
        )?;
        store_api_idem(
            &tx,
            &org_id,
            &actor_id,
            &key,
            &fp,
            200,
            &resp_val.to_string(),
            None,
            now,
        )?;
        tx.commit()?;
        Ok(respond_json(StatusCode::OK, resp_val, None))
    })
    .await;

    match res {
        Ok(resp) => resp,
        Err(e) => e,
    }
}

// ---------- Handlers: Audit Events ----------

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct AuditEventsQuery {
    limit: Option<usize>,
    cursor: Option<String>,
    bot: Option<String>,
    tool: Option<String>,
    effect: Option<String>,
    event_type: Option<String>,
    actor_user_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

fn validate_filter_text(val: Option<&str>) -> Result<Vec<String>, Response> {
    let Some(s) = val else {
        return Ok(Vec::new());
    };
    if s.len() > 4096 || s.contains('\0') {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid audit filter.",
        ));
    }
    Ok(s.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect())
}

fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

async fn list_audit_events(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<AuditEventsQuery>,
    h: HeaderMap,
) -> Response {
    let i = match authenticate(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_admin(&i) {
        return e;
    }
    let limit = match parse_limit(q.limit) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let bots = match validate_filter_text(q.bot.as_deref()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let tools = match validate_filter_text(q.tool.as_deref()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let event_types = match validate_filter_text(q.event_type.as_deref()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let effect = match q.effect.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some("read") => Some("read".to_owned()),
        Some("write") => Some("write".to_owned()),
        Some(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Effect must be read or write.",
            )
        }
        None => None,
    };
    let actor_filter = match q.actor_user_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(a) if a.len() <= 4096 && !a.contains('\0') => Some(a.to_owned()),
        Some(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Invalid actorUserId.",
            )
        }
        None => None,
    };
    let from_ts = match q.from.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(f) => match parse_utc(f) {
            Some(ts) => Some(ts),
            None => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_ERROR",
                    "Invalid from timestamp.",
                )
            }
        },
        None => None,
    };
    let to_ts = match q.to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(t) => match parse_utc(t) {
            Some(ts) => Some(ts),
            None => {
                return problem(
                    StatusCode::BAD_REQUEST,
                    "VALIDATION_ERROR",
                    "Invalid to timestamp.",
                )
            }
        },
        None => None,
    };

    let fh_input = format!(
        "audit|b={}|t={}|e={}|et={}|a={}|f={:?}|to={:?}",
        bots.join(","),
        tools.join(","),
        effect.as_deref().unwrap_or(""),
        event_types.join(","),
        actor_filter.as_deref().unwrap_or(""),
        from_ts,
        to_ts,
    );
    let fh = hex_encode(&Sha256::digest(fh_input.as_bytes())[..12]);
    let cursor = match decode_cursor(q.cursor.as_deref(), &i.organization, &fh) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let org_id = i.organization.clone();

    let res = run_db(&s, move |c| {
        let mut params_vec: Vec<SqlValue> = vec![SqlValue::Text(org_id.clone())];
        let mut conds: Vec<String> = Vec::new();

        if !bots.is_empty() {
            let placeholders: Vec<String> = bots
                .iter()
                .map(|b| {
                    params_vec.push(SqlValue::Text(b.clone()));
                    format!("?{}", params_vec.len())
                })
                .collect();
            conds.push(format!("bot_id IN ({})", placeholders.join(",")));
        }
        if !tools.is_empty() {
            let mut tool_ors = Vec::new();
            for t in &tools {
                let lower = t.to_ascii_lowercase();
                params_vec.push(SqlValue::Text(lower.clone()));
                let p_exact = params_vec.len();
                params_vec.push(SqlValue::Text(format!("%/{}", escape_like(&lower))));
                let p_suffix = params_vec.len();
                tool_ors.push(format!(
                    "(LOWER(tool_ref) = ?{p_exact} OR LOWER(tool_ref) LIKE ?{p_suffix} ESCAPE '\\')"
                ));
            }
            conds.push(format!("({})", tool_ors.join(" OR ")));
        }
        if let Some(eff) = &effect {
            params_vec.push(SqlValue::Text(eff.clone()));
            conds.push(format!("LOWER(effect) = LOWER(?{})", params_vec.len()));
        }
        if !event_types.is_empty() {
            let placeholders: Vec<String> = event_types
                .iter()
                .map(|et| {
                    params_vec.push(SqlValue::Text(et.clone()));
                    format!("?{}", params_vec.len())
                })
                .collect();
            conds.push(format!("event_type IN ({})", placeholders.join(",")));
        }
        if let Some(actor) = &actor_filter {
            params_vec.push(SqlValue::Text(actor.clone()));
            conds.push(format!("actor_id = ?{}", params_vec.len()));
        }
        if let Some(from) = from_ts {
            params_vec.push(SqlValue::Integer(from));
            conds.push(format!("ts >= ?{}", params_vec.len()));
        }
        if let Some(to) = to_ts {
            params_vec.push(SqlValue::Integer(to));
            conds.push(format!("ts <= ?{}", params_vec.len()));
        }
        if let Some((c_ts, c_id)) = cursor {
            params_vec.push(SqlValue::Integer(c_ts));
            let p_ts = params_vec.len();
            params_vec.push(SqlValue::Text(c_id));
            let p_id = params_vec.len();
            conds.push(format!("(ts < ?{p_ts} OR (ts = ?{p_ts} AND id < ?{p_id}))"));
        }

        let where_clause = if conds.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conds.join(" AND "))
        };
        params_vec.push(SqlValue::Integer((limit + 1) as i64));
        let p_limit = params_vec.len();

        let sql = format!(
            "WITH events AS (
                SELECT created_at AS ts,
                       id,
                       CASE WHEN phase = 'refused' THEN 'governance.action_refused' ELSE 'governance.action_intent' END AS event_type,
                       actor_id,
                       'person' AS initiator_kind,
                       NULL AS initiator_id,
                       'bot' AS target_type,
                       bot_id AS target_id,
                       bot_id,
                       '' AS tool_ref,
                       '' AS effect,
                       '' AS scope,
                       conversation_id AS aux_a,
                       attempt_id AS aux_b,
                       action_digest AS digest,
                       'gov' AS source_kind
                  FROM port_governance_audit
                 WHERE organization_id = ?1
                UNION ALL
                SELECT decided_at AS ts,
                       'appr_dec_' || id AS id,
                       CASE WHEN decision = 'deny' THEN 'approval.denied' ELSE 'approval.approved' END AS event_type,
                       actor_id,
                       'person' AS initiator_kind,
                       NULL AS initiator_id,
                       'approval' AS target_type,
                       id AS target_id,
                       bot_id,
                       tool_ref,
                       effect,
                       scope,
                       COALESCE(decision, '') AS aux_a,
                       status AS aux_b,
                       action_digest AS digest,
                       'appr_dec' AS source_kind
                  FROM port_approvals
                 WHERE organization_id = ?1
                   AND decided_at IS NOT NULL
                   AND decision IS NOT NULL
                UNION ALL
                SELECT completed_at AS ts,
                       'appr_out_' || id AS id,
                       'approval.completed' AS event_type,
                       actor_id,
                       'person' AS initiator_kind,
                       NULL AS initiator_id,
                       'approval' AS target_type,
                       id AS target_id,
                       bot_id,
                       tool_ref,
                       effect,
                       scope,
                       COALESCE(result_json, '{{}}') AS aux_a,
                       status AS aux_b,
                       action_digest AS digest,
                       'appr_out' AS source_kind
                  FROM port_approvals
                 WHERE organization_id = ?1
                   AND completed_at IS NOT NULL
                UNION ALL
                SELECT created_at AS ts,
                       id,
                       event_type,
                       actor_id,
                       'person' AS initiator_kind,
                       NULL AS initiator_id,
                       target_type,
                       target_id,
                       '' AS bot_id,
                       '' AS tool_ref,
                       '' AS effect,
                       '' AS scope,
                       payload_json AS aux_a,
                       '' AS aux_b,
                       X'' AS digest,
                       'policy' AS source_kind
                  FROM port_policy_audit_events
                 WHERE organization_id = ?1
            )
            SELECT ts, id, event_type, actor_id, initiator_kind, initiator_id, target_type, target_id,
                   bot_id, tool_ref, effect, scope, aux_a, aux_b, digest, source_kind
              FROM events
              {where_clause}
             ORDER BY ts DESC, id DESC
             LIMIT ?{p_limit}"
        );

        let mut stmt = c.prepare(&sql)?;
        let mut rows = stmt
            .query_map(rusqlite::params_from_iter(params_vec.iter()), |r| {
                let ts: i64 = r.get(0)?;
                let id: String = r.get(1)?;
                let event_type: String = r.get(2)?;
                let actor_id: Option<String> = r.get(3)?;
                let initiator_kind: String = r.get(4)?;
                let initiator_id: Option<String> = r.get(5)?;
                let target_type: String = r.get(6)?;
                let target_id: Option<String> = r.get(7)?;
                let bot_id: String = r.get(8)?;
                let tool_ref: String = r.get(9)?;
                let effect: String = r.get(10)?;
                let scope: String = r.get(11)?;
                let aux_a: String = r.get(12)?;
                let aux_b: String = r.get(13)?;
                let digest: Vec<u8> = r.get(14)?;
                let source_kind: String = r.get(15)?;

                let payload = match source_kind.as_str() {
                    "gov" => json!({
                        "bot": bot_id,
                        "conversationId": aux_a,
                        "attemptId": aux_b,
                        "actionDigest": hex_encode(&digest),
                    }),
                    "appr_dec" => json!({
                        "approvalId": target_id,
                        "bot": bot_id,
                        "toolRef": tool_ref,
                        "effect": effect,
                        "scope": scope,
                        "decision": aux_a,
                        "status": aux_b,
                    }),
                    "appr_out" => {
                        let result: Value = serde_json::from_str(&aux_a).unwrap_or_else(|_| json!({}));
                        json!({
                            "approvalId": target_id,
                            "bot": bot_id,
                            "toolRef": tool_ref,
                            "effect": effect,
                            "scope": scope,
                            "status": aux_b,
                            "result": result,
                        })
                    }
                    _ => serde_json::from_str(&aux_a).unwrap_or_else(|_| json!({})),
                };

                Ok((
                    json!({
                        "id": id,
                        "actorUserId": actor_id,
                        "initiatorKind": initiator_kind,
                        "initiatorId": initiator_id,
                        "eventType": event_type,
                        "targetType": target_type,
                        "targetId": target_id,
                        "payload": payload,
                        "createdAt": format_utc(ts),
                    }),
                    ts,
                    id,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let has_more = rows.len() > limit;
        if has_more {
            rows.pop();
        }
        let next = if has_more {
            rows.last()
                .map(|(_, ts, id)| encode_cursor(&org_id, &fh, *ts, id))
                .transpose()?
        } else {
            None
        };
        let events: Vec<Value> = rows.into_iter().map(|(v, _, _)| v).collect();
        Ok(json!({ "auditEvents": events, "nextCursor": next }))
    })
    .await;

    match res {
        Ok(v) => respond_json(StatusCode::OK, v, None),
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{governance, storage::Storage};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    struct TestFixture {
        db: Arc<Storage>,
        app: Router,
        db_path: std::path::PathBuf,
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.db_path);
        }
    }

    fn setup_fixture() -> TestFixture {
        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).unwrap();
        let db_path = std::env::temp_dir().join(format!(
            "openbot-approvals-{:x}.db",
            u64::from_le_bytes(rand)
        ));
        let db = Arc::new(Storage::open(&db_path).unwrap());
        db.try_with_connection(|c| {
            let exists: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'port_approvals')",
                [],
                |r| r.get(0),
            )?;
            if !exists {
                c.execute_batch(include_str!("../migrations/0011_approvals.sql"))?;
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
        let app = local_auth::router(state.clone()).merge(router(state));
        TestFixture { db, app, db_path }
    }

    fn req(method: &str, uri: &str, cookie: &str, idem: &str, body: &str) -> Request<Body> {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("origin", "http://example.test")
            .header(header::HOST, "example.test")
            .header("content-type", "application/json");
        if !cookie.is_empty() {
            b = b.header("cookie", cookie);
        }
        if !idem.is_empty() {
            b = b.header("idempotency-key", idem);
        }
        b.body(Body::from(body.to_owned())).unwrap()
    }

    async fn setup_owner_and_member(f: &TestFixture) -> (String, String, String, String) {
        let setup_res = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                "/api/port/auth/setup",
                "",
                "",
                r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"long secure password"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(setup_res.status(), StatusCode::NO_CONTENT);
        let owner_cookie = setup_res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let me_res = f
            .app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/people/me",
                &owner_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        let me_json: Value =
            serde_json::from_slice(&to_bytes(me_res.into_body(), 8192).await.unwrap()).unwrap();
        let owner_id = me_json["person"]["id"].as_str().unwrap().to_owned();

        // Provision a second regular member with an active session + bot + conversation.
        let member_id = "user_member_1".to_owned();
        let member_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let member_cookie = format!("openbot_session={member_token}");
        let member_hash = Sha256::digest(member_token.as_bytes()).to_vec();
        let now = now_secs().unwrap();

        f.db.try_with_connection(|c| {
            c.execute(
                "INSERT INTO auth_users(id, email, display_name, password_hash, revoked)
                 VALUES (?1, 'member@example.test', 'Member', 'unused', 0)",
                params![member_id],
            )?;
            c.execute(
                "INSERT INTO auth_memberships(user_id, organization_id, role)
                 VALUES (?1, 'default', 'member')",
                params![member_id],
            )?;
            c.execute(
                "INSERT INTO auth_sessions(token_hash, user_id, created_at, last_seen_at, expires_at)
                 VALUES (?1, ?2, ?3, ?3, ?4)",
                params![member_hash, member_id, now, now + 3600],
            )?;
            c.execute(
                "INSERT INTO port_bots(id, organization_id, owner_id, name, title, role_description, created_at)
                 VALUES ('bot_owner', 'default', ?1, 'OwnerBot', '', 'helper', ?2),
                        ('bot_member', 'default', ?3, 'MemberBot', '', 'helper', ?2)",
                params![owner_id, now, member_id],
            )?;
            c.execute(
                "INSERT INTO port_conversations(id, organization_id, owner_id, thread_id, bot_ids_json, name, created_at, deleted)
                 VALUES ('conv_owner', 'default', ?1, 'thread_owner', '[\"bot_owner\"]', 'OwnerChat', ?2, 0),
                        ('conv_member', 'default', ?3, 'thread_member', '[\"bot_member\"]', 'MemberChat', ?2, 0)",
                params![owner_id, now, member_id],
            )?;
            Ok(())
        })
        .unwrap();

        (owner_cookie, owner_id, member_cookie, member_id)
    }

    #[tokio::test]
    async fn rule_priority_boundaries_and_settings_evaluation() {
        let f = setup_fixture();
        let (owner_cookie, _owner_id, member_cookie, member_id) =
            setup_owner_and_member(&f).await;

        // Default with no rules -> Ask (fail-closed, never Allow).
        let default_eval = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .map_err(|_| StorageError::InvalidDatabase("eval failed"))?)
            })
            .unwrap();
        assert_eq!(default_eval.decision, EvaluationDecision::Ask);
        assert_eq!(default_eval.source, "default");

        // Member creates a personal allow rule -> Allow.
        let r = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/people/me/approval-rules",
                &member_cookie,
                "pr-1",
                r#"{"toolRef":"mcp/gmail/*","behaviour":"allow"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);

        let eval_personal = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(eval_personal.decision, EvaluationDecision::Allow);
        assert_eq!(eval_personal.source, "personal_rule");

        // Admin creates an org ask rule -> org overrides personal rule!
        let r = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/approval-rules",
                &owner_cookie,
                "or-1",
                r#"{"toolRef":"mcp/gmail/*","behaviour":"ask"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let org_rule: Value =
            serde_json::from_slice(&to_bytes(r.into_body(), 8192).await.unwrap()).unwrap();
        let org_rule_id = org_rule["id"].as_str().unwrap().to_owned();

        let eval_org_wins = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(eval_org_wins.decision, EvaluationDecision::Ask);
        assert_eq!(eval_org_wins.source, "team_rule");

        // Update org rule to pre_approved: requires explicit user request.
        let r = f
            .app
            .clone()
            .oneshot(req(
                "PATCH",
                &format!("/api/v2/organizations/default/approval-rules/{org_rule_id}"),
                &owner_cookie,
                "or-patch",
                r#"{"behaviour":"pre_approved"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        let (no_req, with_req) = f
            .db
            .try_with_connection(|c| {
                let a = evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .unwrap();
                let b = evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        user_explicitly_requested: true,
                        boundary_context: None,
                    },
                )
                .unwrap();
                Ok((a, b))
            })
            .unwrap();
        assert_eq!(no_req.decision, EvaluationDecision::Ask);
        assert_eq!(with_req.decision, EvaluationDecision::Allow);

        // Conflicting org rule in same tier -> Deny (fail closed).
        let r = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/approval-rules",
                &owner_cookie,
                "or-2",
                r#"{"toolRef":"mcp/gmail/send_email","behaviour":"hand_off"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let conflict_rule_id = serde_json::from_slice::<Value>(
            &to_bytes(r.into_body(), 8192).await.unwrap(),
        )
        .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();

        let eval_conflict = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        user_explicitly_requested: true,
                        boundary_context: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(eval_conflict.decision, EvaluationDecision::Deny);

        // Clean up conflicting rule, then test boundaries deny > allow.
        let del = f
            .app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v2/organizations/default/approval-rules/{conflict_rule_id}"),
                &owner_cookie,
                "or-del",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::NO_CONTENT);

        // Invalid boundary CEL expression is rejected with 400.
        let bad_b = f
            .app
            .clone()
            .oneshot(req(
                "PUT",
                "/api/v2/organizations/default/boundaries",
                &owner_cookie,
                "b-bad",
                r#"{"mode":"enforce","deny":["unknown_ident == \"x\""],"allow":["true"]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(bad_b.status(), StatusCode::BAD_REQUEST);

        // Enforce boundary denying send_email overrides pre_approved/allow rules.
        let good_b = f
            .app
            .clone()
            .oneshot(req(
                "PUT",
                "/api/v2/organizations/default/boundaries",
                &owner_cookie,
                "b-good",
                r#"{"mode":"enforce","deny":["toolRef == \"mcp/gmail/send_email\""],"allow":["true"],"labels":{"toolRef == \"mcp/gmail/send_email\"":{"name":"No Gmail send","description":"Block send"}}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(good_b.status(), StatusCode::OK);

        let eval_boundary = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        user_explicitly_requested: true,
                        boundary_context: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(eval_boundary.decision, EvaluationDecision::Deny);
        assert_eq!(eval_boundary.source, "boundary");
    }

    #[tokio::test]
    async fn hitl_approval_lifecycle_single_use_and_allow_always() {
        let f = setup_fixture();
        let (owner_cookie, _owner_id, member_cookie, member_id) =
            setup_owner_and_member(&f).await;

        let args = json!({"to":"bob@example.com","api_key":"super_secret_value"});
        let pending = f
            .db
            .try_with_connection(|c| {
                Ok(create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_1",
                        tool_call_id: Some("call_1"),
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        thread_id: "thread_member",
                        args: &args,
                        target: Some(&json!({"app":"gmail"})),
                        account: None,
                        policy: Some(&json!({"behaviour":"ask","source":"default","reason":"Ask"})),
                        ttl_seconds: Some(600),
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(pending.status, "pending");

        // Cannot consume while still pending.
        let early_consume = f
            .db
            .try_with_connection(|c| {
                Ok(consume_approved_action(
                    c,
                    &ConsumeApprovalRequest {
                        approval_id: &pending.id,
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        args: &args,
                    },
                ))
            })
            .unwrap();
        assert!(matches!(early_consume, Err(ApprovalError::Conflict(_))));

        // List approvals masks secrets in args!
        let list_res = f
            .app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/people/me/approvals",
                &member_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(list_res.status(), StatusCode::OK);
        let list_json: Value =
            serde_json::from_slice(&to_bytes(list_res.into_body(), 16384).await.unwrap())
                .unwrap();
        assert_eq!(
            list_json["approvals"][0]["action"]["args"]["api_key"],
            "[REDACTED]"
        );

        // Member decides `allow_always` -> approves AND atomically inserts personal rule.
        let decide_uri = format!(
            "/api/v2/organizations/default/people/me/approvals/{}/decide",
            pending.id
        );
        let decide_res = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &decide_uri,
                &member_cookie,
                "dec-1",
                r#"{"decision":"allow_always"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(decide_res.status(), StatusCode::OK);
        let decided_body = to_bytes(decide_res.into_body(), 16384).await.unwrap();
        let decided_json: Value = serde_json::from_slice(&decided_body).unwrap();
        assert_eq!(decided_json["status"], "approved");
        assert_eq!(decided_json["decision"], "allow_always");

        // Idempotent replay with same key & body returns exact 200 without duplicating personal rule.
        let replay_decide = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &decide_uri,
                &member_cookie,
                "dec-1",
                r#"{"decision":"allow_always"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(replay_decide.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(replay_decide.into_body(), 16384).await.unwrap(),
            decided_body
        );

        // Conflicting body with same Idempotency-Key returns 409.
        let conflict_decide = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &decide_uri,
                &member_cookie,
                "dec-1",
                r#"{"decision":"deny"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(conflict_decide.status(), StatusCode::CONFLICT);

        // Verify personal rule was created atomically (exactly 1 rule).
        let rules_res = f
            .app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/people/me/approval-rules",
                &member_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        let rules_json: Value =
            serde_json::from_slice(&to_bytes(rules_res.into_body(), 16384).await.unwrap())
                .unwrap();
        assert_eq!(rules_json["approvalRules"].as_array().unwrap().len(), 1);

        // Digest mismatch (tampered args) fails consumption!
        let bad_digest = f
            .db
            .try_with_connection(|c| {
                Ok(consume_approved_action(
                    c,
                    &ConsumeApprovalRequest {
                        approval_id: &pending.id,
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        args: &json!({"to":"attacker@evil.com"}),
                    },
                ))
            })
            .unwrap();
        assert!(matches!(bad_digest, Err(ApprovalError::DigestMismatch)));

        // Valid single-use consume succeeds (`approved -> consumed`).
        let consumed = f
            .db
            .try_with_connection(|c| {
                Ok(consume_approved_action(
                    c,
                    &ConsumeApprovalRequest {
                        approval_id: &pending.id,
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        args: &args,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(consumed.status, "consumed");
        assert!(consumed.consumed_at.is_some());

        // Replay consumption MUST fail!
        let replay_consume = f
            .db
            .try_with_connection(|c| {
                Ok(consume_approved_action(
                    c,
                    &ConsumeApprovalRequest {
                        approval_id: &pending.id,
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        args: &args,
                    },
                ))
            })
            .unwrap();
        assert!(matches!(replay_consume, Err(ApprovalError::Conflict(_))));

        // Complete execution (`consumed -> completed`).
        let completed = f
            .db
            .try_with_connection(|c| {
                Ok(complete_approval_execution(
                    c,
                    &CompleteApprovalRequest {
                        approval_id: &pending.id,
                        organization_id: "default",
                        actor_id: &member_id,
                        error: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(completed.status, "completed");
        assert_eq!(completed.result_json.as_deref(), Some("{}"));

        // Also record a governance refusal and verify Audit Events API returns both governance + approval events!
        f.db.try_with_connection(|c| {
            governance::record_refusal(
                c,
                &governance::Action {
                    organization_id: "default",
                    actor_id: &member_id,
                    bot_id: "bot_member",
                    conversation_id: "conv_member",
                    attempt_id: "att_1",
                    canonical_action: &json!({"tool":"mcp/gmail/send_email","secret":"leak"}),
                },
            )
            .map_err(|_| StorageError::InvalidDatabase("gov"))?;
            Ok(())
        })
        .unwrap();

        let audit_res = f
            .app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/audit-events?limit=2",
                &owner_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(audit_res.status(), StatusCode::OK);
        let audit_page1: Value =
            serde_json::from_slice(&to_bytes(audit_res.into_body(), 16384).await.unwrap())
                .unwrap();
        assert_eq!(audit_page1["auditEvents"].as_array().unwrap().len(), 2);
        let cursor = audit_page1["nextCursor"].as_str().unwrap();

        let audit_res2 = f
            .app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/audit-events?limit=10&cursor={cursor}"),
                &owner_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(audit_res2.status(), StatusCode::OK);

        // Filter audit events by tool & effect.
        let filtered = f
            .app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v2/organizations/default/audit-events?bot=bot_member&tool=send_email&effect=write",
                &owner_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(filtered.status(), StatusCode::OK);
        let filtered_json: Value =
            serde_json::from_slice(&to_bytes(filtered.into_body(), 16384).await.unwrap())
                .unwrap();
        assert_eq!(filtered_json["auditEvents"].as_array().unwrap().len(), 2); // approval.approved + approval.completed
    }

    #[tokio::test]
    async fn expiry_rejection_and_cross_user_isolation() {
        let f = setup_fixture();
        let (owner_cookie, owner_id, member_cookie, member_id) =
            setup_owner_and_member(&f).await;

        let args = json!({"x":1});
        let pending = f
            .db
            .try_with_connection(|c| {
                Ok(create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_exp",
                        tool_call_id: None,
                        tool_ref: "mcp/slack/post",
                        effect: "write",
                        scope: "slack",
                        thread_id: "thread_member",
                        args: &args,
                        target: None,
                        account: None,
                        policy: None,
                        ttl_seconds: Some(60),
                    },
                )
                .unwrap())
            })
            .unwrap();

        // Cross-user isolation: even the org owner/admin CANNOT read or decide member's approvals or personal rules!
        let cross_list = f
            .app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/people/{member_id}/approvals"),
                &owner_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(cross_list.status(), StatusCode::FORBIDDEN);

        let cross_decide = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/{member_id}/approvals/{}/decide",
                    pending.id
                ),
                &owner_cookie,
                "cross-1",
                r#"{"decision":"allow_once"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(cross_decide.status(), StatusCode::FORBIDDEN);

        let cross_rules = f
            .app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v2/organizations/default/people/{member_id}/approval-rules"),
                &owner_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(cross_rules.status(), StatusCode::FORBIDDEN);

        // Member CANNOT mutate org rules, settings, boundaries, or read audit-events.
        for (method, uri, body) in [
            ("POST", "/api/v2/organizations/default/approval-rules", r#"{"toolRef":"*","behaviour":"ask"}"#),
            ("PATCH", "/api/v2/organizations/default/approval-settings", r#"{"customRulesEnabled":false}"#),
            ("GET", "/api/v2/organizations/default/boundaries", ""),
            ("PUT", "/api/v2/organizations/default/boundaries", r#"{"mode":"enforce","deny":[],"allow":["true"]}"#),
            ("GET", "/api/v2/organizations/default/audit-events", ""),
        ] {
            let r = f
                .app
                .clone()
                .oneshot(req(method, uri, &member_cookie, "m-forbid", body))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{method} {uri} must forbid member");
        }

        // Member CAN read org approval rules & settings.
        assert_eq!(
            f.app
                .clone()
                .oneshot(req("GET", "/api/v2/organizations/default/approval-rules", &member_cookie, "", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            f.app
                .clone()
                .oneshot(req("GET", "/api/v2/organizations/default/approval-settings", &member_cookie, "", ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        // Member approves their own pending approval.
        let ok_decide = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v2/organizations/default/people/me/approvals/{}/decide", pending.id),
                &member_cookie,
                "ok-dec",
                r#"{"decision":"allow_once"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(ok_decide.status(), StatusCode::OK);

        // Owner cannot consume member's approved action programmatically either.
        let cross_consume = f
            .db
            .try_with_connection(|c| {
                Ok(consume_approved_action(
                    c,
                    &ConsumeApprovalRequest {
                        approval_id: &pending.id,
                        organization_id: "default",
                        actor_id: &owner_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/slack/post",
                        effect: "write",
                        scope: "slack",
                        args: &args,
                    },
                ))
            })
            .unwrap();
        assert!(matches!(cross_consume, Err(ApprovalError::Unauthorized)));

        // Expired approval is rejected at consumption time.
        let expired = f
            .db
            .try_with_connection(|c| {
                Ok(consume_approved_action_at(
                    c,
                    &ConsumeApprovalRequest {
                        approval_id: &pending.id,
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/slack/post",
                        effect: "write",
                        scope: "slack",
                        args: &args,
                    },
                    pending.expires_at,
                ))
            })
            .unwrap();
        assert!(matches!(expired, Err(ApprovalError::Expired)));

        // Pending expired approval is also rejected by /decide.
        let past_pending = f
            .db
            .try_with_connection(|c| {
                let rec = create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_exp2",
                        tool_call_id: None,
                        tool_ref: "mcp/slack/post",
                        effect: "write",
                        scope: "slack",
                        thread_id: "thread_member",
                        args: &args,
                        target: None,
                        account: None,
                        policy: None,
                        ttl_seconds: Some(1),
                    },
                )
                .unwrap();
                c.execute(
                    "UPDATE port_approvals SET expires_at = created_at - 10 WHERE id = ?1",
                    params![rec.id],
                )?;
                Ok(rec)
            })
            .unwrap();
        let dec_exp = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    past_pending.id
                ),
                &member_cookie,
                "exp-dec",
                r#"{"decision":"allow_once"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(dec_exp.status(), StatusCode::BAD_REQUEST);

        // Denying an expired pending approval is still allowed so stale cards can be resolved.
        let deny_exp = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    past_pending.id
                ),
                &member_cookie,
                "exp-deny",
                r#"{"decision":"deny"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(deny_exp.status(), StatusCode::OK);

        // Deleting/dismissing an approval works cleanly and removes it.
        let del_exp = f
            .app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}",
                    past_pending.id
                ),
                &member_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(del_exp.status(), StatusCode::NO_CONTENT);

        let del_again = f
            .app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}",
                    past_pending.id
                ),
                &member_cookie,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(del_again.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn settings_custom_rules_toggle_conversation_grant_deny_and_handled() {
        let f = setup_fixture();
        let (owner_cookie, _owner_id, member_cookie, member_id) =
            setup_owner_and_member(&f).await;

        // Member creates a personal rule, then admin disables customRulesEnabled and sets sending = ask.
        let r = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/people/me/approval-rules",
                &member_cookie,
                "p-create",
                r#"{"toolRef":"mcp/docs/*","behaviour":"allow"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        let rule_id = serde_json::from_slice::<Value>(&to_bytes(r.into_body(), 8192).await.unwrap())
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();

        let s_patch = f
            .app
            .clone()
            .oneshot(req(
                "PATCH",
                "/api/v2/organizations/default/approval-settings",
                &owner_cookie,
                "s-patch",
                r#"{"customRulesEnabled":false,"actionKinds":{"sending":"ask"}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(s_patch.status(), StatusCode::OK);

        // Creating or patching personal rule now fails (400), deleting still succeeds (204).
        let blocked_create = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v2/organizations/default/people/me/approval-rules",
                &member_cookie,
                "p-create-2",
                r#"{"toolRef":"mcp/other/*","behaviour":"allow"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(blocked_create.status(), StatusCode::BAD_REQUEST);

        let del_ok = f
            .app
            .clone()
            .oneshot(req(
                "DELETE",
                &format!("/api/v2/organizations/default/people/me/approval-rules/{rule_id}"),
                &member_cookie,
                "p-del",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(del_ok.status(), StatusCode::NO_CONTENT);

        // Evaluating a sending action yields closed: true Ask!
        let send_outcome = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        user_explicitly_requested: true,
                        boundary_context: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(send_outcome.decision, EvaluationDecision::Ask);
        assert!(send_outcome.closed);
        let pol_json = send_outcome.to_policy_json();

        let args = json!({"k":"v"});
        let closed_appr = f
            .db
            .try_with_connection(|c| {
                Ok(create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_c",
                        tool_call_id: None,
                        tool_ref: "mcp/gmail/send_email",
                        effect: "write",
                        scope: "gmail",
                        thread_id: "thread_member",
                        args: &args,
                        target: None,
                        account: None,
                        policy: Some(&pol_json),
                        ttl_seconds: Some(300),
                    },
                )
                .unwrap())
            })
            .unwrap();

        // Closed approval rejects allow_conversation, accepts allow_once.
        let rej = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    closed_appr.id
                ),
                &member_cookie,
                "c-rej",
                r#"{"decision":"allow_conversation"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(rej.status(), StatusCode::BAD_REQUEST);

        let acc = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    closed_appr.id
                ),
                &member_cookie,
                "c-acc",
                r#"{"decision":"allow_once"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(acc.status(), StatusCode::OK);

        // Non-closed action with allow_conversation grants future evaluations in same conversation.
        let conv_appr = f
            .db
            .try_with_connection(|c| {
                Ok(create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_cg",
                        tool_call_id: None,
                        tool_ref: "mcp/docs/update_doc",
                        effect: "write",
                        scope: "docs",
                        thread_id: "thread_member",
                        args: &args,
                        target: None,
                        account: None,
                        policy: Some(&json!({"behaviour":"ask","source":"default","reason":"Ask"})),
                        ttl_seconds: Some(300),
                    },
                )
                .unwrap())
            })
            .unwrap();
        let cg_res = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    conv_appr.id
                ),
                &member_cookie,
                "cg-1",
                r#"{"decision":"allow_conversation"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(cg_res.status(), StatusCode::OK);

        let eval_cg = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/docs/update_doc",
                        effect: "write",
                        scope: "docs",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(eval_cg.decision, EvaluationDecision::Allow);
        assert_eq!(eval_cg.source, "conversation");

        // Handled approval cannot be consumed by executor.
        let hand_appr = f
            .db
            .try_with_connection(|c| {
                Ok(create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_h",
                        tool_call_id: None,
                        tool_ref: "mcp/docs/manual",
                        effect: "write",
                        scope: "docs",
                        thread_id: "thread_member",
                        args: &args,
                        target: None,
                        account: None,
                        policy: Some(&json!({"behaviour":"hand_off","source":"team_rule","reason":"Manual"})),
                        ttl_seconds: Some(300),
                    },
                )
                .unwrap())
            })
            .unwrap();
        let hand_res = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    hand_appr.id
                ),
                &member_cookie,
                "hand-1",
                r#"{"decision":"handled"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(hand_res.status(), StatusCode::OK);
        let hand_json: Value =
            serde_json::from_slice(&to_bytes(hand_res.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(hand_json["status"], "completed");

        let hand_consume = f
            .db
            .try_with_connection(|c| {
                Ok(consume_approved_action(
                    c,
                    &ConsumeApprovalRequest {
                        approval_id: &hand_appr.id,
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "mcp/docs/manual",
                        effect: "write",
                        scope: "docs",
                        args: &args,
                    },
                ))
            })
            .unwrap();
        assert!(matches!(hand_consume, Err(ApprovalError::Conflict(_))));
    }

    #[tokio::test]
    async fn allow_always_and_conversation_work_across_urls_subdomains_and_commands() {
        let f = setup_fixture();
        let (_owner_cookie, _owner_id, member_cookie, member_id) =
            setup_owner_and_member(&f).await;

        f.db.try_with_connection(|c| {
            c.execute(
                "INSERT INTO port_conversations(id, organization_id, owner_id, thread_id, bot_ids_json, name, created_at, deleted)
                 VALUES ('conv_member_2', 'default', ?1, 'thread_member_2', '[\"bot_member\"]', 'MemberChat2', 0, 0)",
                params![member_id],
            )?;
            Ok(())
        })
        .unwrap();

        // 1. computer_web_fetch: Allow always on one URL covers any URL/subdomain/long query.
        let fetch_args = json!({"url": "https://news.ycombinator.com/news?p=1"});
        let fetch_pending = f
            .db
            .try_with_connection(|c| {
                Ok(create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_web_1",
                        tool_call_id: Some("tc_web_1"),
                        tool_ref: "computer_web_fetch",
                        effect: "read",
                        scope: "https://news.ycombinator.com/news?p=1",
                        thread_id: "thread_member",
                        args: &fetch_args,
                        target: None,
                        account: None,
                        policy: Some(&json!({"behaviour":"ask","source":"default","reason":"Ask"})),
                        ttl_seconds: Some(600),
                    },
                )
                .unwrap())
            })
            .unwrap();

        let dec_web = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    fetch_pending.id
                ),
                &member_cookie,
                "web-always-1",
                r#"{"decision":"allow_always"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(dec_web.status(), StatusCode::OK);

        // Verify saved rule uses wildcard scope `*` and matches other pages, subdomains, and >200 char URLs.
        let long_url = format!("https://en.wikipedia.org/wiki/PlayStation_5?q={}", "a".repeat(220));
        for next_url in [
            "https://news.ycombinator.com/item?id=42",
            "https://docs.rs/tokio/latest/tokio/",
            long_url.as_str(),
        ] {
            let outcome = f
                .db
                .try_with_connection(|c| {
                    Ok(evaluate_action(
                        c,
                        &ActionEvalRequest {
                            organization_id: "default",
                            actor_id: &member_id,
                            bot_id: "bot_member",
                            conversation_id: "conv_member",
                            tool_ref: "computer_web_fetch",
                            effect: "read",
                            scope: next_url,
                            user_explicitly_requested: false,
                            boundary_context: None,
                        },
                    )
                    .unwrap())
                })
                .unwrap();
            assert_eq!(outcome.decision, EvaluationDecision::Allow, "expected Allow for {next_url}");
            assert_eq!(outcome.source, "personal_rule");
        }

        // 2. computer_run_command: Allow always on one command allows subsequent commands without re-prompting.
        let cmd_args = json!({"command": "ls -la /tmp"});
        let cmd_pending = f
            .db
            .try_with_connection(|c| {
                Ok(create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_cmd_1",
                        tool_call_id: Some("tc_cmd_1"),
                        tool_ref: "computer_run_command",
                        effect: "write",
                        scope: "ls -la /tmp",
                        thread_id: "thread_member",
                        args: &cmd_args,
                        target: None,
                        account: None,
                        policy: Some(&json!({"behaviour":"ask","source":"default","reason":"Ask"})),
                        ttl_seconds: Some(600),
                    },
                )
                .unwrap())
            })
            .unwrap();
        let dec_cmd = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    cmd_pending.id
                ),
                &member_cookie,
                "cmd-always-1",
                r#"{"decision":"allow_always"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(dec_cmd.status(), StatusCode::OK);

        let cmd_eval = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "computer_run_command",
                        effect: "write",
                        scope: "python3 --version && ls -la",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(cmd_eval.decision, EvaluationDecision::Allow);
        assert_eq!(cmd_eval.source, "personal_rule");

        // 3. allow_conversation on computer_navigate allows different URLs in conv_member, but not conv_member_2.
        let nav_args = json!({"url": "https://docs.rs/tokio"});
        let nav_pending = f
            .db
            .try_with_connection(|c| {
                Ok(create_pending_approval(
                    c,
                    &CreatePendingApprovalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        run_id: "run_nav_1",
                        tool_call_id: Some("tc_nav_1"),
                        tool_ref: "computer_navigate",
                        effect: "read",
                        scope: "https://docs.rs/tokio",
                        thread_id: "thread_member",
                        args: &nav_args,
                        target: None,
                        account: None,
                        policy: Some(&json!({"behaviour":"ask","source":"default","reason":"Ask"})),
                        ttl_seconds: Some(600),
                    },
                )
                .unwrap())
            })
            .unwrap();
        let dec_nav = f
            .app
            .clone()
            .oneshot(req(
                "POST",
                &format!(
                    "/api/v2/organizations/default/people/me/approvals/{}/decide",
                    nav_pending.id
                ),
                &member_cookie,
                "nav-conv-1",
                r#"{"decision":"allow_conversation"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(dec_nav.status(), StatusCode::OK);

        let (same_conv, other_conv) = f
            .db
            .try_with_connection(|c| {
                let a = evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "computer_navigate",
                        effect: "read",
                        scope: "https://crates.io/crates/tokio",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .unwrap();
                let b = evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member_2",
                        tool_ref: "computer_navigate",
                        effect: "read",
                        scope: "https://crates.io/crates/tokio",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .unwrap();
                Ok((a, b))
            })
            .unwrap();
        assert_eq!(same_conv.decision, EvaluationDecision::Allow);
        assert_eq!(same_conv.source, "conversation");
        assert_eq!(other_conv.decision, EvaluationDecision::Ask);

        // 4. Legacy exact-URL rule still matches subpages and subdomains on the same site, not unrelated domains.
        assert!(rule_matches_scope("https://example.com/page1", "https://example.com/page2"));
        assert!(rule_matches_scope("https://example.com/page1", "https://sub.example.com/other"));
        assert!(!rule_matches_scope("https://example.com/page1", "https://evil.com/page1"));
    }

    #[tokio::test]
    async fn execution_mode_ask_auto_turbo_api_and_evaluation() {
        let f = setup_fixture();
        let (owner_cookie, _owner_id, member_cookie, member_id) =
            setup_owner_and_member(&f).await;

        // Default GET returns executionMode = "ask" on both canonical and alias routes.
        for path in [
            "/api/v2/organizations/default/approval-settings",
            "/api/v2/organizations/default/approvals/settings",
        ] {
            let res = f
                .app
                .clone()
                .oneshot(req("GET", path, &member_cookie, "", ""))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body: Value =
                serde_json::from_slice(&to_bytes(res.into_body(), 8192).await.unwrap()).unwrap();
            assert_eq!(body["executionMode"], "ask");
            assert_eq!(body["customRulesEnabled"], true);
        }

        // Invalid executionMode is rejected with 400; member PATCH is rejected with 403.
        let bad_mode = f
            .app
            .clone()
            .oneshot(req(
                "PATCH",
                "/api/v2/organizations/default/approval-settings",
                &owner_cookie,
                "mode-bad",
                r#"{"executionMode":"yolo"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(bad_mode.status(), StatusCode::BAD_REQUEST);

        let member_patch = f
            .app
            .clone()
            .oneshot(req(
                "PATCH",
                "/api/v2/organizations/default/approval-settings",
                &member_cookie,
                "mode-member",
                r#"{"executionMode":"turbo"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(member_patch.status(), StatusCode::FORBIDDEN);

        // Switch to "auto" mode and verify safe reads/web/commands pass while risky writes/commands ask.
        let auto_patch = f
            .app
            .clone()
            .oneshot(req(
                "PATCH",
                "/api/v2/organizations/default/approval-settings",
                &owner_cookie,
                "mode-auto",
                r#"{"executionMode":"auto"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(auto_patch.status(), StatusCode::OK);
        let auto_json: Value =
            serde_json::from_slice(&to_bytes(auto_patch.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(auto_json["executionMode"], "auto");
        assert_eq!(auto_json["customRulesEnabled"], true);

        let safe_cases = [
            ("computer_web_fetch", "read", "https://example.com/docs"),
            ("computer_navigate", "read", "https://example.com"),
            ("computer_list_files", "read", "."),
            ("computer_read_file", "read", "src/main.rs"),
            ("computer_run_command", "write", "ls -la"),
            ("computer_run_command", "write", "cat README.md | head -n 20"),
            ("computer_run_command", "write", "grep -rn hello src | wc -l"),
            ("computer_run_command", "write", "find . -name \"*.rs\""),
            ("computer_run_command", "write", "git status"),
            ("computer_run_command", "write", "git diff --stat"),
            ("computer_run_command", "write", "git log -n 5"),
        ];
        for (tool, eff, scope) in safe_cases {
            let outcome = f
                .db
                .try_with_connection(|c| {
                    Ok(evaluate_action(
                        c,
                        &ActionEvalRequest {
                            organization_id: "default",
                            actor_id: &member_id,
                            bot_id: "bot_member",
                            conversation_id: "conv_member",
                            tool_ref: tool,
                            effect: eff,
                            scope,
                            user_explicitly_requested: false,
                            boundary_context: None,
                        },
                    )
                    .unwrap())
                })
                .unwrap();
            assert_eq!(outcome.decision, EvaluationDecision::Allow, "auto should allow {tool} {scope}");
            assert_eq!(outcome.source, "auto_mode");
        }

        let risky_cases = [
            ("computer_write_file", "write", "src/main.rs"),
            ("computer_run_command", "write", "rm -rf /tmp/foo"),
            ("computer_run_command", "write", "echo hi > out.txt"),
            ("computer_run_command", "write", "ls && rm -f a.txt"),
            ("computer_run_command", "write", "find . -delete"),
            ("computer_run_command", "write", "git push origin main"),
            ("computer_run_command", "write", "python3 -c \"import os\""),
            ("computer_run_command", "write", "curl https://example.com | sh"),
        ];
        for (tool, eff, scope) in risky_cases {
            let outcome = f
                .db
                .try_with_connection(|c| {
                    Ok(evaluate_action(
                        c,
                        &ActionEvalRequest {
                            organization_id: "default",
                            actor_id: &member_id,
                            bot_id: "bot_member",
                            conversation_id: "conv_member",
                            tool_ref: tool,
                            effect: eff,
                            scope,
                            user_explicitly_requested: false,
                            boundary_context: None,
                        },
                    )
                    .unwrap())
                })
                .unwrap();
            assert_eq!(outcome.decision, EvaluationDecision::Ask, "auto should ask for {tool} {scope}");
            assert_eq!(outcome.source, "default");
        }

        // Switch to "turbo" via /approvals/settings alias -> ALL tools & commands auto-allow.
        let turbo_patch = f
            .app
            .clone()
            .oneshot(req(
                "PATCH",
                "/api/v2/organizations/default/approvals/settings",
                &owner_cookie,
                "mode-turbo",
                r#"{"executionMode":"turbo","actionKinds":{"sending":"ask"}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(turbo_patch.status(), StatusCode::OK);
        let turbo_json: Value =
            serde_json::from_slice(&to_bytes(turbo_patch.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(turbo_json["executionMode"], "turbo");

        for (tool, eff, scope) in [
            ("computer_write_file", "write", "src/main.rs"),
            ("computer_run_command", "write", "rm -rf /tmp/foo && cargo test"),
            ("computer_web_fetch", "read", "https://example.com"),
            ("mcp/gmail/send_email", "write", "gmail"),
        ] {
            let outcome = f
                .db
                .try_with_connection(|c| {
                    Ok(evaluate_action(
                        c,
                        &ActionEvalRequest {
                            organization_id: "default",
                            actor_id: &member_id,
                            bot_id: "bot_member",
                            conversation_id: "conv_member",
                            tool_ref: tool,
                            effect: eff,
                            scope,
                            user_explicitly_requested: false,
                            boundary_context: None,
                        },
                    )
                    .unwrap())
                })
                .unwrap();
            assert_eq!(outcome.decision, EvaluationDecision::Allow, "turbo should allow {tool} {scope}");
            assert_eq!(outcome.source, "turbo_mode");
        }

        // Explicit hostCommandsCap = "never" still blocks host commands even in turbo mode.
        let never_patch = f
            .app
            .clone()
            .oneshot(req(
                "PATCH",
                "/api/v2/organizations/default/approval-settings",
                &owner_cookie,
                "mode-never",
                r#"{"hostCommandsCap":"never"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(never_patch.status(), StatusCode::OK);
        let blocked_cmd = f
            .db
            .try_with_connection(|c| {
                Ok(evaluate_action(
                    c,
                    &ActionEvalRequest {
                        organization_id: "default",
                        actor_id: &member_id,
                        bot_id: "bot_member",
                        conversation_id: "conv_member",
                        tool_ref: "computer_run_command",
                        effect: "write",
                        scope: "ls",
                        user_explicitly_requested: false,
                        boundary_context: None,
                    },
                )
                .unwrap())
            })
            .unwrap();
        assert_eq!(blocked_cmd.decision, EvaluationDecision::Deny);
        assert_eq!(blocked_cmd.source, "safety");
    }
}

