//! PS5LM / llama.cpp context window discovery, fast token estimation, and
//! pre-flight automatic context compaction for OpenAI-compatible payloads.

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_CONTEXT_LIMIT: u64 = 8192;
pub const DEFAULT_AUTO_COMPACT_RATIO: f64 = 0.75;
pub const DEFAULT_COMPACT_TARGET_RATIO: f64 = 0.62;
pub const DEFAULT_CHARS_PER_TOKEN: f64 = 3.5;

const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
const DEFAULT_PROPS_TTL: Duration = Duration::from_secs(15);
const DEFAULT_SLOTS_TTL: Duration = Duration::from_secs(2);
const MAX_SERVER_JSON_BYTES: usize = 512 * 1024;
const ROLLING_SUMMARY_HEADER: &str = "[Compacted conversation context summary]";
const MAX_SUMMARY_CHARS: usize = 1200;
const TIGHT_SUMMARY_CHARS: usize = 450;
const COMPACT_OLD_TOOL_CHARS: usize = 240;

#[derive(Debug)]
pub enum ContextError {
    InvalidConfiguration(&'static str),
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ContextError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerContextInfo {
    pub context_limit: u64,
    pub server_kv_tokens: Option<u64>,
    pub is_processing: bool,
    pub model_alias: Option<String>,
    pub online: bool,
    pub is_sleeping: bool,
}

impl Default for ServerContextInfo {
    fn default() -> Self {
        Self {
            context_limit: DEFAULT_CONTEXT_LIMIT,
            server_kv_tokens: None,
            is_processing: false,
            model_alias: None,
            online: false,
            is_sleeping: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenBreakdown {
    pub total_tokens: u64,
    pub system_tokens: u64,
    pub history_tokens: u64,
    pub tools_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompactionResult {
    pub compacted: bool,
    pub before_tokens: u64,
    pub after_tokens: u64,
    pub threshold_tokens: u64,
    pub context_limit: u64,
    pub dropped_turns: usize,
    pub summarized_messages: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextSnapshot {
    pub used_tokens: u64,
    pub context_limit: u64,
    pub remaining_tokens: u64,
    pub percent_used: f64,
    pub auto_compact_threshold: u64,
    pub compacted: bool,
    pub estimated_prompt_tokens: u64,
    pub system_tokens: u64,
    pub history_tokens: u64,
    pub tools_tokens: u64,
    pub server_kv_tokens: Option<u64>,
    pub online: bool,
    pub is_processing: bool,
    pub model_alias: Option<String>,
    pub compacted_before_tokens: Option<u64>,
    pub compacted_after_tokens: Option<u64>,
    pub dropped_turns: usize,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Default)]
struct CachedProps {
    n_ctx: Option<u64>,
    model_alias: Option<String>,
    is_sleeping: bool,
    online: bool,
    fetched_at: Option<Instant>,
}

#[derive(Debug, Clone, Default)]
struct CachedSlots {
    n_ctx: Option<u64>,
    kv_tokens: Option<u64>,
    is_processing: bool,
    online: bool,
    fetched_at: Option<Instant>,
}

#[derive(Debug, Clone)]
struct RecordedConversationContext {
    breakdown: TokenBreakdown,
    compacted: bool,
    compacted_before_tokens: Option<u64>,
    compacted_after_tokens: Option<u64>,
    dropped_turns: usize,
    updated_at_ms: u64,
}

#[derive(Debug)]
struct ContextCache {
    props: CachedProps,
    slots: CachedSlots,
    conversations: HashMap<String, RecordedConversationContext>,
}

#[derive(Clone)]
pub struct ContextManager {
    client: Option<Client>,
    server_root: Option<Url>,
    default_n_ctx: u64,
    props_ttl: Duration,
    slots_ttl: Duration,
    probe_on_preflight: bool,
    cache: Arc<Mutex<ContextCache>>,
}

impl ContextManager {
    /// Creates a `ContextManager` targeting the llama.cpp / PS5LM server derived
    /// from an OpenAI-compatible API base URL (e.g. `http://127.0.0.1:8081/v1`).
    pub fn new(model_api_url: &str) -> Result<Self, ContextError> {
        Self::with_timeout(model_api_url, DEFAULT_QUERY_TIMEOUT)
    }

    pub fn with_timeout(model_api_url: &str, timeout: Duration) -> Result<Self, ContextError> {
        if timeout.is_zero() {
            return Err(ContextError::InvalidConfiguration(
                "context query timeout must be positive",
            ));
        }
        let server_root = derive_server_root(model_api_url)?;
        let client = Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .pool_idle_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(1)
            .tcp_nodelay(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ContextError::InvalidConfiguration("cannot build HTTP client"))?;

        Ok(Self {
            client: Some(client),
            server_root: Some(server_root),
            default_n_ctx: DEFAULT_CONTEXT_LIMIT,
            props_ttl: DEFAULT_PROPS_TTL,
            slots_ttl: DEFAULT_SLOTS_TTL,
            probe_on_preflight: !cfg!(test),
            cache: Arc::new(Mutex::new(ContextCache {
                props: CachedProps::default(),
                slots: CachedSlots::default(),
                conversations: HashMap::new(),
            })),
        })
    }

    /// Creates an offline/fallback `ContextManager` without a remote server URL.
    pub fn offline(default_n_ctx: u64) -> Self {
        Self {
            client: None,
            server_root: None,
            default_n_ctx: default_n_ctx.max(512),
            props_ttl: DEFAULT_PROPS_TTL,
            slots_ttl: DEFAULT_SLOTS_TTL,
            probe_on_preflight: false,
            cache: Arc::new(Mutex::new(ContextCache {
                props: CachedProps::default(),
                slots: CachedSlots::default(),
                conversations: HashMap::new(),
            })),
        }
    }

    pub fn with_live_probe(mut self, enabled: bool) -> Self {
        self.probe_on_preflight = enabled;
        self
    }

    pub fn with_default_n_ctx(mut self, n_ctx: u64) -> Self {
        self.default_n_ctx = n_ctx.max(512);
        self
    }

    pub fn with_cache_ttls(mut self, props_ttl: Duration, slots_ttl: Duration) -> Self {
        self.props_ttl = props_ttl;
        self.slots_ttl = slots_ttl;
        self
    }

    /// Queries PS5LM `/props` and `/slots` using short timeouts and TTL caching.
    /// Falls back gracefully to cached or default `n_ctx` when offline or busy.
    pub async fn query_server_context(&self) -> ServerContextInfo {
        let now = Instant::now();
        let (need_props, need_slots, cached_snapshot) = {
            let guard = self.cache.lock().expect("context cache lock poisoned");
            let props_fresh = guard
                .props
                .fetched_at
                .is_some_and(|t| now.saturating_duration_since(t) < self.props_ttl);
            let slots_fresh = guard
                .slots
                .fetched_at
                .is_some_and(|t| now.saturating_duration_since(t) < self.slots_ttl);
            let info = assemble_server_info(&guard.props, &guard.slots, self.default_n_ctx);
            (!props_fresh, !slots_fresh, info)
        };

        if !need_props && !need_slots {
            return cached_snapshot;
        }

        let (Some(client), Some(root)) = (&self.client, &self.server_root) else {
            return cached_snapshot;
        };

        let props_fut = async {
            if need_props {
                fetch_props_json(client, root).await
            } else {
                None
            }
        };
        let slots_fut = async {
            if need_slots {
                fetch_slots_json(client, root).await
            } else {
                None
            }
        };

        let (props_res, slots_res) = tokio::join!(props_fut, slots_fut);
        let fetched_at = Instant::now();

        let mut guard = self.cache.lock().expect("context cache lock poisoned");
        if need_props {
            match props_res {
                Some(v) => {
                    let parsed = parse_props_value(&v);
                    guard.props = CachedProps {
                        n_ctx: parsed.n_ctx.or(guard.props.n_ctx),
                        model_alias: parsed.model_alias.or_else(|| guard.props.model_alias.clone()),
                        is_sleeping: parsed.is_sleeping,
                        online: true,
                        fetched_at: Some(fetched_at),
                    };
                }
                None => {
                    guard.props.online = false;
                    guard.props.fetched_at = Some(fetched_at);
                }
            }
        }
        if need_slots {
            match slots_res {
                Some(v) => {
                    let parsed = parse_slots_value(&v);
                    guard.slots = CachedSlots {
                        n_ctx: parsed.n_ctx.or(guard.slots.n_ctx),
                        kv_tokens: parsed.kv_tokens,
                        is_processing: parsed.is_processing,
                        online: true,
                        fetched_at: Some(fetched_at),
                    };
                }
                None => {
                    guard.slots.online = false;
                    guard.slots.kv_tokens = None;
                    guard.slots.is_processing = false;
                    guard.slots.fetched_at = Some(fetched_at);
                }
            }
        }

        assemble_server_info(&guard.props, &guard.slots, self.default_n_ctx)
    }

    /// Queries PS5LM context limit (when live preflight probing is enabled)
    /// and applies `auto_compact_request` if needed.
    pub async fn preflight_compact(&self, request: &mut Value) -> (CompactionResult, ServerContextInfo) {
        let server = if self.probe_on_preflight {
            self.query_server_context().await
        } else {
            let guard = self.cache.lock().expect("context cache lock poisoned");
            assemble_server_info(&guard.props, &guard.slots, self.default_n_ctx)
        };
        let compaction = auto_compact_request(request, server.context_limit);
        (compaction, server)
    }

    /// Computes a `ContextSnapshot` from a token breakdown, optional compaction result,
    /// and live/cached server state.
    pub fn compute_snapshot(
        &self,
        breakdown: &TokenBreakdown,
        compaction: Option<&CompactionResult>,
        server: &ServerContextInfo,
    ) -> ContextSnapshot {
        let context_limit = server.context_limit.max(1);
        let used_tokens = if breakdown.total_tokens > 0 {
            if server.is_processing {
                server
                    .server_kv_tokens
                    .unwrap_or(0)
                    .max(breakdown.total_tokens)
            } else {
                breakdown.total_tokens
            }
        } else {
            server.server_kv_tokens.unwrap_or(0)
        };
        let remaining_tokens = context_limit.saturating_sub(used_tokens);
        let percent_used =
            (((used_tokens as f64 / context_limit as f64) * 100.0).clamp(0.0, 100.0) * 10.0)
                .round()
                / 10.0;
        let auto_compact_threshold =
            ((context_limit as f64) * DEFAULT_AUTO_COMPACT_RATIO).floor() as u64;

        let (compacted, compacted_before_tokens, compacted_after_tokens, dropped_turns) =
            match compaction {
                Some(c) if c.compacted => (
                    true,
                    Some(c.before_tokens),
                    Some(c.after_tokens),
                    c.dropped_turns,
                ),
                _ => (false, None, None, 0),
            };

        ContextSnapshot {
            used_tokens,
            context_limit,
            remaining_tokens,
            percent_used,
            auto_compact_threshold,
            compacted,
            estimated_prompt_tokens: breakdown.total_tokens,
            system_tokens: breakdown.system_tokens,
            history_tokens: breakdown.history_tokens,
            tools_tokens: breakdown.tools_tokens,
            server_kv_tokens: server.server_kv_tokens,
            online: server.online,
            is_processing: server.is_processing,
            model_alias: server.model_alias.clone(),
            compacted_before_tokens,
            compacted_after_tokens,
            dropped_turns,
            updated_at_ms: epoch_ms(),
        }
    }

    /// Records the latest prompt token breakdown & compaction outcome for a conversation.
    pub fn record_conversation_state(
        &self,
        conversation_id: &str,
        breakdown: TokenBreakdown,
        compaction: Option<&CompactionResult>,
    ) {
        let mut guard = self.cache.lock().expect("context cache lock poisoned");
        if guard.conversations.len() > 256 && !guard.conversations.contains_key(conversation_id) {
            if let Some(oldest_key) = guard
                .conversations
                .iter()
                .min_by_key(|(_, v)| v.updated_at_ms)
                .map(|(k, _)| k.clone())
            {
                guard.conversations.remove(&oldest_key);
            }
        }
        let (compacted, before, after, dropped) = match compaction {
            Some(c) if c.compacted => (
                true,
                Some(c.before_tokens),
                Some(c.after_tokens),
                c.dropped_turns,
            ),
            _ => (false, None, None, 0),
        };
        guard.conversations.insert(
            conversation_id.to_owned(),
            RecordedConversationContext {
                breakdown,
                compacted,
                compacted_before_tokens: before,
                compacted_after_tokens: after,
                dropped_turns: dropped,
                updated_at_ms: epoch_ms(),
            },
        );
    }

    /// Returns true if a run-level context snapshot has already been recorded for this conversation.
    pub fn has_conversation_state(&self, conversation_id: &str) -> bool {
        let guard = self.cache.lock().expect("context cache lock poisoned");
        guard.conversations.contains_key(conversation_id)
    }

    /// Builds a fresh `ContextSnapshot` for a conversation by combining live PS5LM
    /// `/props` + `/slots` data with the recorded conversation breakdown (or a fallback
    /// estimate from stored messages).
    pub async fn get_conversation_snapshot(
        &self,
        conversation_id: &str,
        fallback_request: Option<&Value>,
    ) -> ContextSnapshot {
        let server = self.query_server_context().await;
        let recorded = {
            let guard = self.cache.lock().expect("context cache lock poisoned");
            guard.conversations.get(conversation_id).cloned()
        };

        if let Some(rec) = recorded {
            let fake_compaction = if rec.compacted {
                Some(CompactionResult {
                    compacted: true,
                    before_tokens: rec.compacted_before_tokens.unwrap_or(rec.breakdown.total_tokens),
                    after_tokens: rec.compacted_after_tokens.unwrap_or(rec.breakdown.total_tokens),
                    threshold_tokens: ((server.context_limit as f64) * DEFAULT_AUTO_COMPACT_RATIO)
                        .floor() as u64,
                    context_limit: server.context_limit,
                    dropped_turns: rec.dropped_turns,
                    summarized_messages: rec.dropped_turns,
                })
            } else {
                None
            };
            let mut snap = self.compute_snapshot(&rec.breakdown, fake_compaction.as_ref(), &server);
            snap.updated_at_ms = rec.updated_at_ms;
            return snap;
        }

        if let Some(req) = fallback_request {
            let breakdown = estimate_request_tokens(req);
            return self.compute_snapshot(&breakdown, None, &server);
        }

        self.compute_snapshot(&TokenBreakdown::default(), None, &server)
    }
}

/// Derives the llama.cpp server root URL from an OpenAI-compatible base URL
/// (e.g. `http://127.0.0.1:8081/v1` -> `http://127.0.0.1:8081/`).
pub fn derive_server_root(model_api_url: &str) -> Result<Url, ContextError> {
    let mut base = Url::parse(model_api_url)
        .map_err(|_| ContextError::InvalidConfiguration("invalid model API URL"))?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(ContextError::InvalidConfiguration(
            "model API URL must be an HTTP(S) base URL without credentials, query or fragment",
        ));
    }

    let trimmed = base.path().trim_end_matches('/');
    let stripped = if let Some(prefix) = trimmed.strip_suffix("/v1") {
        if prefix.is_empty() {
            "/"
        } else {
            prefix
        }
    } else if trimmed.is_empty() {
        "/"
    } else {
        trimmed
    };
    let normalized = if stripped.ends_with('/') {
        stripped.to_owned()
    } else {
        format!("{stripped}/")
    };
    base.set_path(&normalized);
    Ok(base)
}

/// Fast token estimation for OpenAI `{messages, tools}` payloads using `chars / 3.5 + overhead`.
pub fn estimate_request_tokens(request: &Value) -> TokenBreakdown {
    let mut system_tokens = 0u64;
    let mut history_tokens = 0u64;
    let mut tools_tokens = 0u64;

    if let Some(messages) = request.get("messages").and_then(Value::as_array) {
        for msg in messages {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
            let est = estimate_message_tokens(msg);
            if role == "system" {
                system_tokens = system_tokens.saturating_add(est);
            } else {
                history_tokens = history_tokens.saturating_add(est);
            }
        }
    }

    if let Some(tools) = request.get("tools").and_then(Value::as_array) {
        if !tools.is_empty() {
            let mut chars = 0usize;
            for tool in tools {
                chars = chars.saturating_add(count_json_chars(tool));
            }
            let tool_overhead = (tools.len() as u64).saturating_mul(10).saturating_add(8);
            tools_tokens = chars_to_tokens(chars).saturating_add(tool_overhead);
        }
    }

    let has_messages = request
        .get("messages")
        .and_then(Value::as_array)
        .is_some_and(|m| !m.is_empty());
    let reply_priming = if has_messages || tools_tokens > 0 { 4 } else { 0 };
    let total_tokens = system_tokens
        .saturating_add(history_tokens)
        .saturating_add(tools_tokens)
        .saturating_add(reply_priming);

    TokenBreakdown {
        total_tokens,
        system_tokens,
        history_tokens,
        tools_tokens,
    }
}

/// Automatically compacts an OpenAI chat completions request before sending when estimated
/// prompt tokens exceed 75% of `n_ctx`.
///
/// Preserves:
/// - Leading system prompt(s)
/// - Latest user message and active trailing turns/tool calls
/// - Recent completed turns when budget permits
/// - Intact `assistant(tool_calls)` + `tool` pairs (never splitting a pair)
///
/// Oldest non-pinned turns are folded into a compact `[Compacted conversation context summary]`
/// system note.
pub fn auto_compact_request(request: &mut Value, n_ctx: u64) -> CompactionResult {
    auto_compact_request_with_ratio(request, n_ctx, DEFAULT_AUTO_COMPACT_RATIO)
}

pub fn auto_compact_request_with_ratio(
    request: &mut Value,
    n_ctx: u64,
    threshold_ratio: f64,
) -> CompactionResult {
    let before = estimate_request_tokens(request);
    let safe_ratio = if threshold_ratio.is_finite() && threshold_ratio > 0.0 && threshold_ratio <= 1.0 {
        threshold_ratio
    } else {
        DEFAULT_AUTO_COMPACT_RATIO
    };
    let threshold_tokens = ((n_ctx as f64) * safe_ratio).floor() as u64;

    if n_ctx == 0 || before.total_tokens <= threshold_tokens {
        return CompactionResult {
            compacted: false,
            before_tokens: before.total_tokens,
            after_tokens: before.total_tokens,
            threshold_tokens,
            context_limit: n_ctx,
            dropped_turns: 0,
            summarized_messages: 0,
        };
    }

    let tools_value = request.get("tools").cloned();
    let Some(msgs) = request.get("messages").and_then(Value::as_array).cloned() else {
        return CompactionResult {
            compacted: false,
            before_tokens: before.total_tokens,
            after_tokens: before.total_tokens,
            threshold_tokens,
            context_limit: n_ctx,
            dropped_turns: 0,
            summarized_messages: 0,
        };
    };

    if msgs.is_empty() {
        return CompactionResult {
            compacted: false,
            before_tokens: before.total_tokens,
            after_tokens: before.total_tokens,
            threshold_tokens,
            context_limit: n_ctx,
            dropped_turns: 0,
            summarized_messages: 0,
        };
    }

    // 1. Separate leading system prompts and any previous rolling summary note.
    let mut pinned_system: Vec<Value> = Vec::new();
    let mut prior_summary_lines: Vec<String> = Vec::new();
    let mut body_start = 0usize;

    while body_start < msgs.len() {
        let msg = &msgs[body_start];
        if msg.get("role").and_then(Value::as_str) != Some("system") {
            break;
        }
        let content = extract_message_text(msg);
        if content.starts_with(ROLLING_SUMMARY_HEADER) {
            for line in content.lines().skip(1) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    prior_summary_lines.push(trimmed.to_owned());
                }
            }
        } else {
            pinned_system.push(msg.clone());
        }
        body_start += 1;
    }

    // 2. Partition remaining messages into atomic groups so assistant(tool_calls) + tool* are never split.
    let groups = partition_atomic_groups(&msgs[body_start..]);
    if groups.is_empty() {
        // Only system messages exist; clip oversized system prompt if strictly necessary.
        let mut rebuilt = pinned_system;
        if !prior_summary_lines.is_empty() {
            rebuilt.push(make_summary_message(&prior_summary_lines, TIGHT_SUMMARY_CHARS));
        }
        shrink_oversized_messages(&mut rebuilt, tools_value.as_ref(), threshold_tokens);
        request["messages"] = Value::Array(rebuilt);
        let after = estimate_request_tokens(request);
        let changed = after.total_tokens < before.total_tokens;
        return CompactionResult {
            compacted: changed,
            before_tokens: before.total_tokens,
            after_tokens: after.total_tokens,
            threshold_tokens,
            context_limit: n_ctx,
            dropped_turns: 0,
            summarized_messages: 0,
        };
    }

    // 3. Identify the pinned tail starting at the latest user group (preserving active tool rounds too).
    let last_user_group = groups
        .iter()
        .rposition(|g| g.iter().any(|m| m.get("role").and_then(Value::as_str) == Some("user")));
    let tail_pinned_start = match last_user_group {
        Some(idx) => idx,
        None => groups.len().saturating_sub(1),
    };

    // Prefer keeping up to 2 recent groups before the latest user message if budget allows.
    let target_tokens = ((n_ctx as f64) * DEFAULT_COMPACT_TARGET_RATIO.min(safe_ratio))
        .floor()
        .max(1.0) as u64;
    let initial_keep_from = tail_pinned_start.saturating_sub(2);
    let mut keep_from = initial_keep_from;
    let mut best_messages: Option<Vec<Value>> = None;

    while keep_from <= tail_pinned_start {
        let mut candidate = build_compacted_messages(
            &pinned_system,
            &prior_summary_lines,
            &groups[..keep_from],
            &groups[keep_from..],
            MAX_SUMMARY_CHARS,
        );
        let est = estimate_candidate_tokens(&candidate, tools_value.as_ref());
        if est <= target_tokens {
            best_messages = Some(candidate);
            break;
        }
        if keep_from == tail_pinned_start {
            // Even dropping all non-pinned groups exceeded target_tokens; keep this minimal tail and
            // shrink oversized tool outputs / content in-place if still over threshold_tokens.
            if est > threshold_tokens {
                compact_older_tool_outputs_in_place(&mut candidate, COMPACT_OLD_TOOL_CHARS);
                if estimate_candidate_tokens(&candidate, tools_value.as_ref()) > threshold_tokens {
                    candidate = build_compacted_messages(
                        &pinned_system,
                        &prior_summary_lines,
                        &groups[..keep_from],
                        &groups[keep_from..],
                        TIGHT_SUMMARY_CHARS,
                    );
                    compact_older_tool_outputs_in_place(&mut candidate, COMPACT_OLD_TOOL_CHARS);
                }
                if estimate_candidate_tokens(&candidate, tools_value.as_ref()) > threshold_tokens {
                    shrink_oversized_messages(&mut candidate, tools_value.as_ref(), threshold_tokens);
                }
            }
            best_messages = Some(candidate);
            break;
        }
        keep_from += 1;
    }

    let final_messages = best_messages.unwrap_or(msgs);
    let dropped_turns = keep_from;
    let summarized_messages: usize = groups[..keep_from].iter().map(Vec::len).sum();
    let changed = dropped_turns > 0 || final_messages.len() != request["messages"].as_array().map_or(0, Vec::len);

    request["messages"] = Value::Array(final_messages);
    let after = estimate_request_tokens(request);
    let compacted = changed || after.total_tokens < before.total_tokens;

    CompactionResult {
        compacted,
        before_tokens: before.total_tokens,
        after_tokens: after.total_tokens,
        threshold_tokens,
        context_limit: n_ctx,
        dropped_turns,
        summarized_messages,
    }
}

fn partition_atomic_groups(messages: &[Value]) -> Vec<Vec<Value>> {
    let mut groups: Vec<Vec<Value>> = Vec::new();
    let mut i = 0usize;
    while i < messages.len() {
        let msg = &messages[i];
        let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
        let has_tool_calls = role == "assistant"
            && msg
                .get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|tc| !tc.is_empty());

        if has_tool_calls {
            let mut group = vec![msg.clone()];
            let mut j = i + 1;
            while j < messages.len()
                && messages[j].get("role").and_then(Value::as_str) == Some("tool")
            {
                group.push(messages[j].clone());
                j += 1;
            }
            groups.push(group);
            i = j;
        } else {
            groups.push(vec![msg.clone()]);
            i += 1;
        }
    }
    groups
}

fn build_compacted_messages(
    pinned_system: &[Value],
    prior_summary_lines: &[String],
    dropped_groups: &[Vec<Value>],
    kept_groups: &[Vec<Value>],
    max_summary_chars: usize,
) -> Vec<Value> {
    let mut out = Vec::with_capacity(pinned_system.len() + kept_groups.len() * 2 + 1);
    out.extend(pinned_system.iter().cloned());

    let mut summary_lines: Vec<String> = prior_summary_lines.to_vec();
    for group in dropped_groups {
        if let Some(line) = summarize_group(group) {
            summary_lines.push(line);
        }
    }

    if !summary_lines.is_empty() {
        out.push(make_summary_message(&summary_lines, max_summary_chars));
    }

    for group in kept_groups {
        out.extend(group.iter().cloned());
    }
    out
}

fn make_summary_message(lines: &[String], max_chars: usize) -> Value {
    // Keep the most recent summary lines if the rolling summary exceeds max_chars.
    let mut kept_rev: Vec<&str> = Vec::new();
    let mut used = ROLLING_SUMMARY_HEADER.len() + 1;
    for line in lines.iter().rev() {
        let line_len = line.len() + 1;
        if used + line_len > max_chars && !kept_rev.is_empty() {
            break;
        }
        used += line_len;
        kept_rev.push(line.as_str());
    }
    kept_rev.reverse();
    let body = if kept_rev.is_empty() {
        lines
            .last()
            .map(|s| clip_single_line(s, max_chars.saturating_sub(ROLLING_SUMMARY_HEADER.len() + 2)))
            .unwrap_or_default()
    } else {
        kept_rev.join("\n")
    };
    json!({
        "role": "system",
        "content": format!("{ROLLING_SUMMARY_HEADER}\n{body}")
    })
}

fn summarize_group(group: &[Value]) -> Option<String> {
    if group.is_empty() {
        return None;
    }
    let first = &group[0];
    let role = first.get("role").and_then(Value::as_str).unwrap_or("message");
    if role == "assistant"
        && first
            .get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
    {
        let names: Vec<String> = first["tool_calls"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|tc| {
                tc.get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        let tool_list = if names.is_empty() {
            "tools".to_owned()
        } else {
            names.join(", ")
        };
        let last_tool_preview = group
            .iter()
            .skip(1)
            .filter_map(|m| {
                let t = extract_message_text(m);
                let trimmed = t.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(clip_single_line(trimmed, 80))
                }
            })
            .next_back();
        return Some(match last_tool_preview {
            Some(preview) => format!("- Tools ({tool_list}): {preview}"),
            None => format!("- Tools ({tool_list}) executed."),
        });
    }

    let text = extract_message_text(first);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let label = match role {
        "user" => "User",
        "assistant" => "Assistant",
        "tool" => "Tool",
        "system" => "Note",
        _ => "Message",
    };
    Some(format!("- {label}: {}", clip_single_line(trimmed, 120)))
}

fn compact_older_tool_outputs_in_place(messages: &mut [Value], max_chars: usize) {
    let Some(last_tc_idx) = messages.iter().rposition(|m| {
        m.get("role").and_then(Value::as_str) == Some("assistant")
            && m.get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty())
    }) else {
        return;
    };
    for msg in messages[..last_tc_idx].iter_mut() {
        if msg.get("role").and_then(Value::as_str) == Some("tool") {
            if let Some(s) = msg.get("content").and_then(Value::as_str).map(str::to_owned) {
                if s.chars().count() > max_chars {
                    msg["content"] = Value::String(clip_head_tail(&s, max_chars));
                }
            }
        }
    }
}

fn shrink_oversized_messages(
    messages: &mut [Value],
    tools: Option<&Value>,
    threshold_tokens: u64,
) {
    if estimate_candidate_tokens(messages, tools) <= threshold_tokens {
        return;
    }

    // 1. Shrink rolling summary first if present.
    for msg in messages.iter_mut() {
        if msg.get("role").and_then(Value::as_str) == Some("system") {
            if let Some(s) = msg.get("content").and_then(Value::as_str).map(str::to_owned) {
                if s.starts_with(ROLLING_SUMMARY_HEADER) && s.chars().count() > 220 {
                    msg["content"] = Value::String(clip_head_tail(&s, 220));
                }
            }
        }
    }
    if estimate_candidate_tokens(messages, tools) <= threshold_tokens {
        return;
    }

    // 2. Shrink oversized tool results (preserving tool_call_id and role).
    for i in 0..messages.len() {
        if messages[i].get("role").and_then(Value::as_str) == Some("tool") {
            if let Some(s) = messages[i]
                .get("content")
                .and_then(Value::as_str)
                .map(str::to_owned)
            {
                if s.chars().count() > 600 {
                    messages[i]["content"] = Value::String(clip_head_tail(&s, 600));
                    if estimate_candidate_tokens(messages, tools) <= threshold_tokens {
                        return;
                    }
                }
            }
        }
    }

    // 3. Shrink oversized user/assistant message text proportionally to fit threshold_tokens.
    let current = estimate_candidate_tokens(messages, tools);
    if current <= threshold_tokens {
        return;
    }
    let excess_chars = (((current - threshold_tokens) as f64) * DEFAULT_CHARS_PER_TOKEN).ceil() as usize + 64;
    let mut remaining_to_trim = excess_chars;

    // Trim oldest non-system messages first, then latest user message if needed.
    for msg in messages.iter_mut() {
        if remaining_to_trim == 0 {
            break;
        }
        let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
        if role == "system" {
            continue;
        }
        if let Some(s) = msg.get("content").and_then(Value::as_str).map(str::to_owned) {
            let len = s.chars().count();
            if len > 256 {
                let target_len = len.saturating_sub(remaining_to_trim).max(200);
                if target_len < len {
                    remaining_to_trim = remaining_to_trim.saturating_sub(len - target_len);
                    msg["content"] = Value::String(clip_head_tail(&s, target_len));
                }
            }
        }
    }
}

fn estimate_candidate_tokens(messages: &[Value], tools: Option<&Value>) -> u64 {
    let mut req = json!({ "messages": messages });
    if let Some(t) = tools {
        req["tools"] = t.clone();
    }
    estimate_request_tokens(&req).total_tokens
}

fn estimate_message_tokens(msg: &Value) -> u64 {
    let mut chars = 0usize;
    let mut image_tokens = 0u64;
    let mut extra_overhead = 4u64;

    if let Some(role) = msg.get("role").and_then(Value::as_str) {
        chars = chars.saturating_add(role.chars().count());
    }
    if let Some(name) = msg.get("name").and_then(Value::as_str) {
        chars = chars.saturating_add(name.chars().count());
        extra_overhead = extra_overhead.saturating_add(2);
    }
    if let Some(tc_id) = msg.get("tool_call_id").and_then(Value::as_str) {
        chars = chars.saturating_add(tc_id.chars().count());
        extra_overhead = extra_overhead.saturating_add(2);
    }

    match msg.get("content") {
        Some(Value::String(s)) => {
            chars = chars.saturating_add(s.chars().count());
        }
        Some(Value::Array(parts)) => {
            for part in parts {
                let kind = part.get("type").and_then(Value::as_str).unwrap_or("");
                if kind == "image_url" || kind == "input_image" {
                    image_tokens = image_tokens.saturating_add(256);
                } else if let Some(text) = part.get("text").and_then(Value::as_str) {
                    chars = chars.saturating_add(text.chars().count());
                } else {
                    chars = chars.saturating_add(count_json_chars(part));
                }
            }
        }
        Some(other) if !other.is_null() => {
            chars = chars.saturating_add(count_json_chars(other));
        }
        _ => {}
    }

    if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array) {
        for tc in tool_calls {
            chars = chars.saturating_add(count_json_chars(tc));
            extra_overhead = extra_overhead.saturating_add(6);
        }
    }

    chars_to_tokens(chars)
        .saturating_add(extra_overhead)
        .saturating_add(image_tokens)
}

fn chars_to_tokens(chars: usize) -> u64 {
    if chars == 0 {
        0
    } else {
        ((chars as f64) / DEFAULT_CHARS_PER_TOKEN).ceil() as u64
    }
}

fn count_json_chars(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(b) => {
            if *b {
                4
            } else {
                5
            }
        }
        Value::Number(n) => n.to_string().len(),
        Value::String(s) => s.chars().count().saturating_add(2),
        Value::Array(arr) => arr
            .iter()
            .fold(2usize, |acc, item| acc.saturating_add(count_json_chars(item) + 1)),
        Value::Object(map) => map.iter().fold(2usize, |acc, (k, v)| {
            acc.saturating_add(k.chars().count())
                .saturating_add(count_json_chars(v))
                .saturating_add(4)
        }),
    }
}

fn extract_message_text(msg: &Value) -> String {
    match msg.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| {
                if let Some(t) = p.get("text").and_then(Value::as_str) {
                    Some(t.to_owned())
                } else if p.get("type").and_then(Value::as_str) == Some("image_url") {
                    Some("[image]".to_owned())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

fn clip_single_line(text: &str, max_chars: usize) -> String {
    let single: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let count = single.chars().count();
    if count <= max_chars {
        return single;
    }
    let take = max_chars.saturating_sub(3);
    let prefix: String = single.chars().take(take).collect();
    format!("{prefix}...")
}

fn clip_head_tail(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text.to_owned();
    }
    if max_chars <= 40 {
        return text.chars().take(max_chars).collect();
    }
    let marker = format!("\n[... compacted ~{} chars ...]\n", total.saturating_sub(max_chars));
    let marker_len = marker.chars().count();
    if max_chars <= marker_len + 16 {
        return text.chars().take(max_chars).collect();
    }
    let avail = max_chars - marker_len;
    let head_len = avail / 2;
    let tail_len = avail - head_len;
    let head: String = text.chars().take(head_len).collect();
    let tail: String = text.chars().skip(total.saturating_sub(tail_len)).collect();
    format!("{head}{marker}{tail}")
}

fn assemble_server_info(props: &CachedProps, slots: &CachedSlots, default_n_ctx: u64) -> ServerContextInfo {
    let context_limit = props
        .n_ctx
        .or(slots.n_ctx)
        .filter(|n| *n > 0)
        .unwrap_or(default_n_ctx.max(512));
    ServerContextInfo {
        context_limit,
        server_kv_tokens: slots.kv_tokens,
        is_processing: slots.is_processing,
        model_alias: props.model_alias.clone(),
        online: props.online || slots.online,
        is_sleeping: props.is_sleeping,
    }
}

struct ParsedProps {
    n_ctx: Option<u64>,
    model_alias: Option<String>,
    is_sleeping: bool,
}

fn parse_props_value(v: &Value) -> ParsedProps {
    let n_ctx = v
        .get("default_generation_settings")
        .and_then(|d| d.get("n_ctx"))
        .and_then(Value::as_u64)
        .or_else(|| v.get("n_ctx").and_then(Value::as_u64))
        .filter(|n| *n > 0);
    let model_alias = v
        .get("model_alias")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let is_sleeping = v
        .get("is_sleeping")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    ParsedProps {
        n_ctx,
        model_alias,
        is_sleeping,
    }
}

struct ParsedSlots {
    n_ctx: Option<u64>,
    kv_tokens: Option<u64>,
    is_processing: bool,
}

fn parse_slots_value(v: &Value) -> ParsedSlots {
    let Some(slots) = v.as_array() else {
        return ParsedSlots {
            n_ctx: None,
            kv_tokens: None,
            is_processing: false,
        };
    };

    let mut best_n_ctx: Option<u64> = None;
    let mut active_kv: Option<u64> = None;
    let mut fallback_kv: Option<u64> = None;
    let mut any_processing = false;

    for slot in slots {
        let slot_n_ctx = slot.get("n_ctx").and_then(Value::as_u64).filter(|n| *n > 0);
        if best_n_ctx.is_none() {
            best_n_ctx = slot_n_ctx;
        }
        let is_proc = slot
            .get("is_processing")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if is_proc {
            any_processing = true;
            if let Some(n) = slot_n_ctx {
                best_n_ctx = Some(n);
            }
        }

        // In llama.cpp `/slots`, `n_prompt_tokens` is `prompt.tokens.size()`, which already
        // includes generated tokens decoded into the slot so far (do NOT add `n_decoded`).
        let kv_tokens = slot.get("n_prompt_tokens").and_then(Value::as_u64).or_else(|| {
            let proc = slot
                .get("n_prompt_tokens_processed")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let cached = slot
                .get("n_prompt_tokens_cache")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let decoded_tokens = slot
                .get("next_token")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|nt| nt.get("n_decoded"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let base = proc.max(cached);
            if base > 0 || decoded_tokens > 0 {
                Some(base.saturating_add(decoded_tokens))
            } else {
                None
            }
        });

        if let Some(total) = kv_tokens {
            if is_proc {
                active_kv = Some(active_kv.map_or(total, |cur| cur.max(total)));
            } else {
                fallback_kv = Some(fallback_kv.map_or(total, |cur| cur.max(total)));
            }
        }
    }

    ParsedSlots {
        n_ctx: best_n_ctx,
        kv_tokens: active_kv.or(fallback_kv),
        is_processing: any_processing,
    }
}

async fn fetch_props_json(client: &Client, root: &Url) -> Option<Value> {
    let url = root.join("props").ok()?;
    fetch_bounded_json(client, url).await
}

async fn fetch_slots_json(client: &Client, root: &Url) -> Option<Value> {
    let url = root.join("slots").ok()?;
    fetch_bounded_json(client, url).await
}

async fn fetch_bounded_json(client: &Client, url: Url) -> Option<Value> {
    let mut response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut bytes = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if bytes.len().saturating_add(chunk.len()) > MAX_SERVER_JSON_BYTES {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).ok()
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn derives_server_root_from_openai_v1_url() {
        assert_eq!(
            derive_server_root("http://127.0.0.1:8081/v1").unwrap().as_str(),
            "http://127.0.0.1:8081/"
        );
        assert_eq!(
            derive_server_root("http://192.168.10.3:8081/v1/").unwrap().as_str(),
            "http://192.168.10.3:8081/"
        );
        assert_eq!(
            derive_server_root("http://127.0.0.1:8081/proxy/v1").unwrap().as_str(),
            "http://127.0.0.1:8081/proxy/"
        );
        assert!(derive_server_root("http://user:pass@localhost/v1").is_err());
        assert!(derive_server_root("file:///tmp/v1").is_err());
    }

    #[test]
    fn estimates_tokens_for_messages_and_tools() {
        let req = json!({
            "model": "qwen",
            "messages": [
                { "role": "system", "content": "You are a helpful assistant." },
                { "role": "user", "content": "Hello, world!" },
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": { "name": "computer_web_fetch", "arguments": "{\"url\":\"https://example.com\"}" }
                        }
                    ]
                },
                { "role": "tool", "tool_call_id": "call_1", "content": "Example Domain page body" }
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "computer_web_fetch",
                        "description": "Fetch a webpage",
                        "parameters": { "type": "object", "properties": { "url": { "type": "string" } } }
                    }
                }
            ]
        });

        let breakdown = estimate_request_tokens(&req);
        assert!(breakdown.system_tokens > 0);
        assert!(breakdown.history_tokens > breakdown.system_tokens);
        assert!(breakdown.tools_tokens > 0);
        assert_eq!(
            breakdown.total_tokens,
            breakdown.system_tokens + breakdown.history_tokens + breakdown.tools_tokens + 4
        );
    }

    #[test]
    fn does_not_compact_when_under_threshold() {
        let mut req = json!({
            "model": "qwen",
            "messages": [
                { "role": "system", "content": "System instructions." },
                { "role": "user", "content": "Hi" },
                { "role": "assistant", "content": "Hello!" },
                { "role": "user", "content": "How are you?" }
            ]
        });
        let original = req.clone();
        let res = auto_compact_request(&mut req, 8192);
        assert!(!res.compacted);
        assert_eq!(res.before_tokens, res.after_tokens);
        assert_eq!(res.threshold_tokens, 6144);
        assert_eq!(req, original);
    }

    #[test]
    fn compacts_oldest_turns_while_preserving_system_recent_and_tool_pairs() {
        let big_pad = "alpha beta gamma delta ".repeat(140); // ~3220 chars (~920 tok)
        let mut messages = vec![json!({
            "role": "system",
            "content": "Primary system prompt: follow safety rules."
        })];

        // Older turns that should be compacted into the rolling summary:
        messages.push(json!({ "role": "user", "content": format!("Old turn 1: {big_pad}") }));
        messages.push(json!({ "role": "assistant", "content": format!("Old reply 1: {big_pad}") }));
        messages.push(json!({ "role": "user", "content": format!("Old turn 2: {big_pad}") }));
        messages.push(json!({
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_old",
                "type": "function",
                "function": { "name": "computer_read_file", "arguments": "{\"path\":\"old.txt\"}" }
            }]
        }));
        messages.push(json!({
            "role": "tool",
            "tool_call_id": "call_old",
            "content": format!("Old file output: {big_pad}")
        }));

        // Recent turn + latest user message + active tool call/result pair:
        messages.push(json!({ "role": "user", "content": "Recent question before latest" }));
        messages.push(json!({ "role": "assistant", "content": "Recent concise answer" }));
        messages.push(json!({ "role": "user", "content": "Latest user request: open example.com" }));
        messages.push(json!({
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_live",
                "type": "function",
                "function": { "name": "computer_web_fetch", "arguments": "{\"url\":\"https://example.com\"}" }
            }]
        }));
        messages.push(json!({
            "role": "tool",
            "tool_call_id": "call_live",
            "content": "Fetched Example Domain successfully."
        }));

        let mut req = json!({ "model": "qwen", "messages": messages });
        let n_ctx = 4096; // 75% threshold = 3072 tokens
        let res = auto_compact_request(&mut req, n_ctx);

        assert!(res.compacted);
        assert!(res.before_tokens > res.threshold_tokens);
        assert!(res.after_tokens <= res.threshold_tokens);
        assert!(res.dropped_turns > 0);

        let out_msgs = req["messages"].as_array().unwrap();
        // System prompt preserved at index 0
        assert_eq!(out_msgs[0]["role"], "system");
        assert!(out_msgs[0]["content"]
            .as_str()
            .unwrap()
            .contains("Primary system prompt"));

        // Rolling summary inserted at index 1
        assert_eq!(out_msgs[1]["role"], "system");
        assert!(out_msgs[1]["content"]
            .as_str()
            .unwrap()
            .starts_with(ROLLING_SUMMARY_HEADER));

        // Latest user message and active tool_call/tool pair preserved intact
        let user_pos = out_msgs
            .iter()
            .position(|m| m["content"] == "Latest user request: open example.com")
            .expect("latest user message must be preserved");
        assert_eq!(out_msgs[user_pos + 1]["role"], "assistant");
        assert_eq!(
            out_msgs[user_pos + 1]["tool_calls"][0]["id"],
            "call_live"
        );
        assert_eq!(out_msgs[user_pos + 2]["role"], "tool");
        assert_eq!(out_msgs[user_pos + 2]["tool_call_id"], "call_live");

        // Verify invariant: no orphaned tool message or split assistant(tool_calls) anywhere
        assert_tool_pairing_intact(out_msgs);
    }

    #[test]
    fn never_splits_tool_call_pair_even_when_tool_turn_straddles_cutoff() {
        let pad = "token ".repeat(400);
        let mut req = json!({
            "model": "qwen",
            "messages": [
                { "role": "system", "content": "Sys" },
                { "role": "user", "content": format!("U1 {pad}") },
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        { "id": "c1", "type": "function", "function": { "name": "t1", "arguments": "{}" } },
                        { "id": "c2", "type": "function", "function": { "name": "t2", "arguments": "{}" } }
                    ]
                },
                { "role": "tool", "tool_call_id": "c1", "content": format!("R1 {pad}") },
                { "role": "tool", "tool_call_id": "c2", "content": format!("R2 {pad}") },
                { "role": "assistant", "content": "Done with U1" },
                { "role": "user", "content": "Final question" }
            ]
        });

        let res = auto_compact_request(&mut req, 1500);
        assert!(res.compacted);
        let out_msgs = req["messages"].as_array().unwrap();
        assert_tool_pairing_intact(out_msgs);
        assert!(out_msgs.iter().any(|m| m["content"] == "Final question"));
    }

    #[test]
    fn merges_existing_rolling_summary_without_duplicating_headers() {
        let pad = "word ".repeat(500);
        let mut req = json!({
            "model": "qwen",
            "messages": [
                { "role": "system", "content": "Core system" },
                { "role": "system", "content": format!("{ROLLING_SUMMARY_HEADER}\n- User: earlier task") },
                { "role": "user", "content": format!("Middle message {pad}") },
                { "role": "assistant", "content": format!("Middle reply {pad}") },
                { "role": "user", "content": "Newest message" }
            ]
        });

        let res = auto_compact_request(&mut req, 1200);
        assert!(res.compacted);
        let out_msgs = req["messages"].as_array().unwrap();
        let summary_count = out_msgs
            .iter()
            .filter(|m| {
                m["role"] == "system"
                    && m["content"]
                        .as_str()
                        .is_some_and(|s| s.starts_with(ROLLING_SUMMARY_HEADER))
            })
            .count();
        assert_eq!(summary_count, 1);
        let summary_text = out_msgs[1]["content"].as_str().unwrap();
        assert!(summary_text.contains("earlier task"));
        assert!(summary_text.contains("Middle message"));
    }

    #[tokio::test]
    async fn queries_props_and_slots_with_caching_and_offline_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap();
                let req_str = std::str::from_utf8(&buf[..n]).unwrap();
                let body = if req_str.starts_with("GET /props ") {
                    r#"{"default_generation_settings":{"n_ctx":16384},"model_alias":"qwen-14b","is_sleeping":false}"#
                } else if req_str.starts_with("GET /slots ") {
                    r#"[{"id":0,"n_ctx":16384,"is_processing":true,"n_prompt_tokens":1420,"next_token":[{"n_decoded":80}]}]"#
                } else {
                    "{}"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(resp.as_bytes()).await.unwrap();
            }
        });

        let mgr = ContextManager::new(&format!("http://{addr}/v1"))
            .unwrap()
            .with_cache_ttls(Duration::from_secs(30), Duration::from_secs(30));

        let info = mgr.query_server_context().await;
        assert!(info.online);
        assert_eq!(info.context_limit, 16384);
        assert_eq!(info.server_kv_tokens, Some(1420));
        assert!(info.is_processing);
        assert_eq!(info.model_alias.as_deref(), Some("qwen-14b"));

        // Second call uses cache (server task only accepted 2 connections and already exited).
        server.await.unwrap();
        let cached = mgr.query_server_context().await;
        assert_eq!(cached, info);

        // Offline fallback manager uses default_n_ctx gracefully without errors.
        let offline = ContextManager::new("http://127.0.0.1:1/v1")
            .unwrap()
            .with_default_n_ctx(8192);
        let fallback_info = offline.query_server_context().await;
        assert!(!fallback_info.online);
        assert_eq!(fallback_info.context_limit, 8192);
        assert_eq!(fallback_info.server_kv_tokens, None);
    }

    #[tokio::test]
    async fn snapshot_calculates_usage_remaining_and_compaction_fields() {
        let mgr = ContextManager::offline(8192);
        let mut req = json!({
            "model": "qwen",
            "messages": [
                { "role": "system", "content": "System" },
                { "role": "user", "content": "word ".repeat(5000) },
                { "role": "assistant", "content": "ok" },
                { "role": "user", "content": "Latest" }
            ]
        });
        let (compaction, server) = mgr.preflight_compact(&mut req).await;
        assert!(compaction.compacted);
        let breakdown = estimate_request_tokens(&req);
        let snap = mgr.compute_snapshot(&breakdown, Some(&compaction), &server);
        assert_eq!(snap.context_limit, 8192);
        assert_eq!(snap.auto_compact_threshold, 6144);
        assert!(snap.compacted);
        assert_eq!(snap.used_tokens + snap.remaining_tokens, snap.context_limit);
        assert!(snap.percent_used > 0.0 && snap.percent_used <= 100.0);
        assert_eq!(snap.compacted_before_tokens, Some(compaction.before_tokens));
        assert_eq!(snap.compacted_after_tokens, Some(compaction.after_tokens));

        mgr.record_conversation_state("conv-1", breakdown, Some(&compaction));
        let loaded = mgr.get_conversation_snapshot("conv-1", None).await;
        assert!(loaded.compacted);
        assert_eq!(loaded.used_tokens, snap.used_tokens);
    }

    #[test]
    fn compacts_oversized_active_turn_without_splitting_tool_pairs() {
        let huge_output = "line of output data\n".repeat(450);
        let mut req = json!({
            "model": "qwen",
            "messages": [
                { "role": "system", "content": "Core instructions" },
                { "role": "user", "content": "Run two steps" },
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{ "id": "c1", "type": "function", "function": { "name": "step1", "arguments": "{}" } }]
                },
                { "role": "tool", "tool_call_id": "c1", "content": huge_output },
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{ "id": "c2", "type": "function", "function": { "name": "step2", "arguments": "{}" } }]
                },
                { "role": "tool", "tool_call_id": "c2", "content": "short final tool output" }
            ]
        });

        let res = auto_compact_request(&mut req, 2048); // threshold = 1536
        assert!(res.compacted);
        assert!(res.after_tokens < res.before_tokens);
        assert!(res.after_tokens <= res.threshold_tokens);
        let out_msgs = req["messages"].as_array().unwrap();
        assert_tool_pairing_intact(out_msgs);
        assert!(out_msgs.iter().any(|m| m["content"] == "Run two steps"));
    }

    #[test]
    fn handles_empty_or_non_array_messages_gracefully() {
        let mut empty_req = json!({ "model": "qwen", "messages": [] });
        let res1 = auto_compact_request(&mut empty_req, 8192);
        assert!(!res1.compacted);

        let mut zero_ctx = json!({ "model": "qwen", "messages": [{ "role": "user", "content": "hi" }] });
        let res2 = auto_compact_request(&mut zero_ctx, 0);
        assert!(!res2.compacted);
    }

    fn assert_tool_pairing_intact(messages: &[Value]) {
        let mut pending_tool_ids: Vec<String> = Vec::new();
        for msg in messages {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
            if role == "tool" {
                let id = msg
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .expect("tool message must have tool_call_id");
                let pos = pending_tool_ids
                    .iter()
                    .position(|p| p == id)
                    .expect("tool message must match preceding assistant tool_calls");
                pending_tool_ids.remove(pos);
            } else {
                assert!(
                    pending_tool_ids.is_empty(),
                    "assistant tool_calls left unanswered: {pending_tool_ids:?}"
                );
                if role == "assistant" {
                    if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
                        for tc in tcs {
                            if let Some(id) = tc.get("id").and_then(Value::as_str) {
                                pending_tool_ids.push(id.to_owned());
                            }
                        }
                    }
                }
            }
        }
        assert!(
            pending_tool_ids.is_empty(),
            "trailing unanswered assistant tool_calls: {pending_tool_ids:?}"
        );
    }
}
