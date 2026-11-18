use crate::compat_extra::{load_kv, save_kv};
use crate::compat_routes::authorize;
use crate::local_auth::{AuthState, Identity};
use crate::storage::{Storage, StorageError};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

const MAX_BODY_BYTES: usize = 64 * 1024;
const MCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const MCP_CALL_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_APPS_PER_ORG: usize = 64;
const MAX_TOOLS_PER_APP: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMcpTool {
    pub name: String,
    pub description: String,
    #[serde(default = "default_input_schema")]
    pub input_schema: Value,
    pub effect: String,
    #[serde(default)]
    pub destructive: bool,
    #[serde(default)]
    pub granted_to: Vec<String>,
}

fn default_input_schema() -> Value {
    json!({"type": "object", "properties": {}})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMcpApp {
    pub id: String,
    pub title: String,
    pub address: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default = "default_owner_grants")]
    pub owner_grants: String,
    #[serde(default)]
    pub owner_grants_chosen: Option<String>,
    #[serde(default)]
    pub added_by: Option<String>,
    #[serde(default)]
    pub tools_refreshed_at: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub skipped_tools: Vec<String>,
    #[serde(default)]
    pub tools: Vec<StoredMcpTool>,
}

fn default_owner_grants() -> String {
    "any".to_owned()
}

#[derive(Debug, Clone)]
pub struct ResolvedMcpTool {
    pub fn_name: String,
    pub app_id: String,
    pub tool_name: String,
    pub policy_ref: String,
    pub effect: String,
    pub schema: Value,
}

fn apps_kv_scope(org: &str) -> String {
    format!("mcp_apps:{org}")
}

fn epoch_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn iso_now(c: &rusqlite::Connection) -> String {
    c.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", [], |r| r.get(0))
        .unwrap_or_else(|_| "2026-01-01T00:00:00Z".to_owned())
}

fn problem(status: StatusCode, code: &str, detail: &str) -> Response {
    problem_with_extra(status, code, detail, None)
}

fn problem_with_extra(
    status: StatusCode,
    code: &str,
    detail: &str,
    app_id: Option<&str>,
) -> Response {
    let mut body = json!({
        "code": code,
        "error": detail,
        "message": detail,
        "detail": detail,
    });
    if let Some(id) = app_id {
        body["appId"] = Value::String(id.to_owned());
    }
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

fn respond_json(status: StatusCode, value: Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        value.to_string(),
    )
        .into_response()
}

fn is_rfc1918_v4(ip: Ipv4Addr) -> bool {
    let oct = ip.octets();
    oct[0] == 10
        || (oct[0] == 172 && (16..=31).contains(&oct[1]))
        || (oct[0] == 192 && oct[1] == 168)
}

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_disallowed_ip(IpAddr::V4(v4));
            }
            v6.is_unspecified()
                || v6.is_multicast()
                || ((v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn parse_host_ip(host: &str) -> Option<IpAddr> {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed.parse::<IpAddr>().ok()
}

fn is_private_or_local_host(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if let Some(ip) = parse_host_ip(host) {
        return match ip {
            IpAddr::V4(v4) => v4.is_loopback() || is_rfc1918_v4(v4),
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6
                        .to_ipv4_mapped()
                        .is_some_and(|v4| v4.is_loopback() || is_rfc1918_v4(v4))
            }
        };
    }
    let lower = host.to_ascii_lowercase();
    lower == "localhost" || lower.ends_with(".local") || lower.ends_with(".lan")
}

/// Validates an MCP server URL for SSRF safety while allowing explicit LAN HTTP workers
/// (for example PS5 OpenBot talking to a workstation running OpenMontage over LAN).
pub fn validate_mcp_url(raw: &str) -> Result<Url, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 || trimmed.chars().any(char::is_control) {
        return Err("Enter a valid server URL.");
    }
    let parsed = Url::parse(trimmed).map_err(|_| "Enter a valid http:// or https:// URL.")?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("MCP server URL must start with http:// or https://.");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("MCP server URL must not contain credentials in the URL.");
    }
    let Some(host) = parsed.host_str().filter(|h| !h.is_empty()) else {
        return Err("MCP server URL must include a hostname or IP address.");
    };
    if let Some(ip) = parse_host_ip(host) {
        if is_disallowed_ip(ip) {
            return Err("That IP address is not allowed for MCP servers.");
        }
    } else if host.eq_ignore_ascii_case("metadata.google.internal") {
        return Err("That host is not allowed for MCP servers.");
    }
    if scheme == "http" && !is_private_or_local_host(&parsed) {
        return Err(
            "Public MCP servers must use https:// (plain http:// is allowed only on local LAN addresses).",
        );
    }
    Ok(parsed)
}

fn normalize_mcp_url(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_ascii_lowercase()
}

fn is_url_allowlisted(c: &rusqlite::Connection, org: &str, url: &Url) -> bool {
    let scope = format!("org_settings:{org}");
    let Ok(Some(settings)) = load_kv(c, &scope) else {
        return true;
    };
    let Some(allowlist) = settings.get("mcpAllowlist") else {
        return true;
    };
    if allowlist.get("enabled").and_then(Value::as_bool) != Some(true) {
        return true;
    }
    let target_norm = normalize_mcp_url(url);
    let target_host = url.host_str().unwrap_or("").to_ascii_lowercase();
    allowlist
        .get("servers")
        .and_then(Value::as_array)
        .map(|items| {
            items.iter().filter_map(Value::as_str).any(|entry| {
                let e = entry.trim().trim_end_matches('/').to_ascii_lowercase();
                if e.is_empty() {
                    return false;
                }
                e == target_norm
                    || e == target_host
                    || Url::parse(&e)
                        .ok()
                        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
                        .is_some_and(|h| h == target_host && e == target_norm)
            })
        })
        .unwrap_or(false)
}

pub fn load_apps(c: &rusqlite::Connection, org: &str) -> Vec<StoredMcpApp> {
    load_kv(c, &apps_kv_scope(org))
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value::<Vec<StoredMcpApp>>(v).ok())
        .unwrap_or_default()
}

pub fn save_apps(
    c: &rusqlite::Connection,
    org: &str,
    apps: &[StoredMcpApp],
) -> Result<(), StorageError> {
    let val = serde_json::to_value(apps)
        .map_err(|_| StorageError::InvalidDatabase("failed to encode apps"))?;
    save_kv(c, &apps_kv_scope(org), &val)
}

fn to_public_app(app: &StoredMcpApp) -> Value {
    let tools: Vec<Value> = app
        .tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "ref": format!("{}/{}", app.id, t.name),
                "description": t.description,
                "effect": if t.effect == "read" { "read" } else { "write" },
                "destructive": t.destructive,
                "grantedTo": t.granted_to,
            })
        })
        .collect();
    json!({
        "id": app.id,
        "title": app.title,
        "source": "address",
        "directoryEntryId": Value::Null,
        "address": app.address,
        "logo": Value::Null,
        "vendor": app.vendor,
        "summary": "",
        "docsUrl": "",
        "connectsWith": Value::Null,
        "hasCredential": app.token.as_ref().is_some_and(|t| !t.trim().is_empty()),
        "dynamicClient": false,
        "signIn": false,
        "entraScope": Value::Null,
        "accountMode": Value::Null,
        "sharedAccountConnected": false,
        "sharedOnly": false,
        "ownerGrants": app.owner_grants,
        "ownerGrantsChosen": app.owner_grants_chosen,
        "addedBy": app.added_by,
        "toolsRefreshedAt": app.tools_refreshed_at,
        "lastError": app.last_error,
        "skippedTools": app.skipped_tools,
        "tools": tools,
        "withdrawn": []
    })
}

fn slugify_app_id(title: &str, existing: &[StoredMcpApp]) -> String {
    let mut base = String::new();
    let mut prev_dash = false;
    for ch in title.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            base.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !base.is_empty() {
            base.push('-');
            prev_dash = true;
        }
        if base.len() >= 48 {
            break;
        }
    }
    let base = base.trim_matches('-').to_owned();
    let base = if base.is_empty() {
        "mcp-server".to_owned()
    } else {
        base
    };
    if !existing.iter().any(|a| a.id == base) {
        return base;
    }
    for idx in 2..=100 {
        let candidate = format!("{base}-{idx}");
        if !existing.iter().any(|a| a.id == candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", epoch_now())
}

fn is_valid_mcp_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Deterministic, OpenAI-function-name-safe identifier (`[a-zA-Z0-9_-]`, <= 64 chars).
pub fn encode_mcp_tool_name(app_id: &str, tool_name: &str) -> String {
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    let raw = format!("mcp__{}__{}", clean(app_id), clean(tool_name));
    if raw.len() <= 64 {
        return raw;
    }
    let mut hash: u32 = 2166136261;
    for b in format!("{app_id}/{tool_name}").as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(16777619);
    }
    let suffix = format!("_{hash:08x}");
    let prefix_len = 64 - suffix.len();
    format!("{}{}", &raw[..prefix_len], suffix)
}

/// Loads all MCP tools currently granted to `bot_id` in `org`, ready for LLM tool schemas.
pub fn load_bot_mcp_tools(
    c: &rusqlite::Connection,
    org: &str,
    bot_id: &str,
) -> Vec<ResolvedMcpTool> {
    let apps = load_apps(c, org);
    let mut out = Vec::new();
    let mut seen_names = HashSet::new();
    for app in apps {
        for tool in app.tools {
            if !tool.granted_to.iter().any(|b| b == bot_id) {
                continue;
            }
            let fn_name = encode_mcp_tool_name(&app.id, &tool.name);
            if !seen_names.insert(fn_name.clone()) {
                continue;
            }
            let desc = if tool.description.trim().is_empty() {
                format!("MCP tool {} from {}", tool.name, app.title)
            } else {
                format!("[{}] {}", app.title, tool.description.trim())
            };
            let params = if tool.input_schema.is_object() {
                tool.input_schema.clone()
            } else {
                default_input_schema()
            };
            out.push(ResolvedMcpTool {
                schema: json!({
                    "type": "function",
                    "function": {
                        "name": fn_name,
                        "description": desc,
                        "parameters": params,
                    }
                }),
                fn_name,
                policy_ref: format!("mcp/{}/{}", app.id, tool.name),
                app_id: app.id.clone(),
                tool_name: tool.name,
                effect: tool.effect,
            });
        }
    }
    out
}

pub fn resolve_mcp_tool<'a>(
    tools: &'a [ResolvedMcpTool],
    name_or_ref: &str,
) -> Option<&'a ResolvedMcpTool> {
    tools.iter().find(|t| {
        t.fn_name == name_or_ref
            || t.policy_ref == name_or_ref
            || format!("{}/{}", t.app_id, t.tool_name) == name_or_ref
    })
}

pub fn load_bot_skill_instructions(
    c: &rusqlite::Connection,
    org: &str,
    bot_id: &str,
) -> Vec<(String, String, String)> {
    let Ok(skills) = crate::compat_extra::read_skills_for_org(c, org) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for sk in skills {
        let granted = sk
            .get("botIds")
            .and_then(Value::as_array)
            .is_some_and(|arr| arr.iter().filter_map(Value::as_str).any(|id| id == bot_id));
        if !granted {
            continue;
        }
        let slug = sk
            .get("slug")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let title = sk
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or(&slug)
            .to_owned();
        let instructions = sk
            .get("instructions")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned();
        if !slug.is_empty() && !instructions.is_empty() {
            out.push((slug, title, instructions));
        }
    }
    out
}

pub fn list_bot_skill_grants(
    c: &rusqlite::Connection,
    org: &str,
    bot_id: &str,
) -> Vec<Value> {
    let Ok(skills) = crate::compat_extra::read_skills_for_org(c, org) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for sk in skills {
        let granted = sk
            .get("botIds")
            .and_then(Value::as_array)
            .is_some_and(|arr| arr.iter().filter_map(Value::as_str).any(|id| id == bot_id));
        if !granted {
            continue;
        }
        let Some(slug) = sk.get("slug").and_then(Value::as_str) else {
            continue;
        };
        let title = sk.get("title").and_then(Value::as_str).unwrap_or(slug);
        let summary = sk.get("summary").and_then(Value::as_str).unwrap_or("");
        out.push(json!({
            "id": format!("skill:{slug}"),
            "kind": "skill",
            "ref": slug,
            "action": Value::Null,
            "skill": {
                "slug": slug,
                "title": title,
                "summary": summary,
            },
        }));
    }
    out
}

pub fn list_bot_action_grants(
    c: &rusqlite::Connection,
    org: &str,
    bot_id: &str,
) -> Vec<Value> {
    let apps = load_apps(c, org);
    let mut grants = Vec::new();
    for app in apps {
        for tool in app.tools {
            if tool.granted_to.iter().any(|b| b == bot_id) {
                grants.push(json!({
                    "id": format!("action:{}:{}", app.id, tool.name),
                    "kind": "action",
                    "ref": format!("{}/{}", app.id, tool.name),
                    "action": {
                        "appId": app.id,
                        "name": tool.name,
                        "description": tool.description,
                        "destructive": tool.destructive,
                        "read": tool.effect == "read",
                    },
                    "skill": Value::Null,
                }));
            }
        }
    }
    grants
}

pub fn build_bot_apps_json(
    c: &rusqlite::Connection,
    org: &str,
    bot_id: &str,
    _actor_id: &str,
) -> Vec<Value> {
    let apps = load_apps(c, org);
    apps.into_iter()
        .map(|app| {
            let granted = app
                .tools
                .iter()
                .any(|t| t.granted_to.iter().any(|b| b == bot_id));
            let state = if granted {
                "ready"
            } else if app.owner_grants == "any" {
                "owner_grantable"
            } else {
                "not_granted"
            };
            json!({
                "id": app.id,
                "title": app.title,
                "logo": Value::Null,
                "source": "address",
                "account": "none",
                "connect": if app.token.as_ref().is_some_and(|t| !t.is_empty()) { "key" } else { "none" },
                "state": state,
                "unavailable": Value::Null,
                "accountHolder": Value::Null,
                "asksFirst": false,
                "granted": granted,
                "ownerGrants": app.owner_grants,
                "givenByOwner": granted && app.owner_grants == "any",
                "needsConnect": false,
                "connectedAt": Value::Null,
                "requestKind": Value::Null,
                "pendingRequest": Value::Null,
            })
        })
        .collect()
}

fn build_http_client(timeout: Duration) -> Result<Client, String> {
    Client::builder()
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

fn parse_mcp_json_or_sse(
    content_type: &str,
    body: &str,
    expected_id: Option<u64>,
) -> Result<Value, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(Value::Null);
    }
    if content_type.to_ascii_lowercase().contains("text/event-stream")
        || trimmed.starts_with("data:")
        || trimmed.starts_with("event:")
    {
        let mut last_json: Option<Value> = None;
        for line in trimmed.lines() {
            let line = line.trim();
            if let Some(payload) = line.strip_prefix("data:") {
                let p = payload.trim();
                if p.is_empty() || p == "[DONE]" {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(p) {
                    if expected_id.is_some() && v.get("id").and_then(Value::as_u64) == expected_id {
                        return Ok(v);
                    }
                    last_json = Some(v);
                }
            }
        }
        if let Some(v) = last_json {
            return Ok(v);
        }
        return Err("MCP server returned an empty event stream.".to_owned());
    }
    serde_json::from_str::<Value>(trimmed)
        .map_err(|e| format!("MCP server returned invalid JSON: {e}"))
}

async fn post_mcp_rpc(
    client: &Client,
    url: &str,
    token: Option<&str>,
    session_id: &mut Option<String>,
    payload: &Value,
    expected_id: Option<u64>,
) -> Result<Value, String> {
    let mut req = client
        .post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(tok) = token.filter(|t| !t.trim().is_empty()) {
        req = req.bearer_auth(tok.trim());
    }
    if let Some(sid) = session_id.as_deref() {
        req = req.header("Mcp-Session-Id", sid);
    }
    let resp = req
        .body(payload.to_string())
        .send()
        .await
        .map_err(|e| format!("Could not reach MCP server: {e}"))?;

    if let Some(sid) = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        *session_id = Some(sid.to_owned());
    }
    let status = resp.status();
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failed reading MCP server response: {e}"))?;
    if !status.is_success() {
        let preview: String = body.trim().chars().take(240).collect();
        return Err(if preview.is_empty() {
            format!("MCP server returned HTTP {}", status.as_u16())
        } else {
            format!("MCP server returned HTTP {}: {}", status.as_u16(), preview)
        });
    }
    if expected_id.is_none() {
        return Ok(Value::Null);
    }
    let parsed = parse_mcp_json_or_sse(&ct, &body, expected_id)?;
    if let Some(err) = parsed.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Unknown MCP error");
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(-32000);
        return Err(format!("MCP JSON-RPC error ({code}): {msg}"));
    }
    Ok(parsed.get("result").cloned().unwrap_or(Value::Null))
}

async fn mcp_handshake(
    client: &Client,
    url: &str,
    token: Option<&str>,
) -> Result<Option<String>, String> {
    let mut session_id = None;
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "openbot-ps5",
                "version": "1.0.0"
            }
        }
    });
    let _ = post_mcp_rpc(client, url, token, &mut session_id, &init_req, Some(1)).await?;
    let notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let _ = post_mcp_rpc(client, url, token, &mut session_id, &notif, None).await;
    Ok(session_id)
}

/// Discovers tools from a Streamable HTTP MCP server (`initialize` -> `tools/list`).
pub async fn fetch_mcp_tools(
    url: &str,
    token: Option<&str>,
    existing_grants: &HashMap<String, Vec<String>>,
) -> Result<(Vec<StoredMcpTool>, Vec<String>), String> {
    let client = build_http_client(MCP_HANDSHAKE_TIMEOUT)?;
    let mut session_id = mcp_handshake(&client, url, token).await?;

    let mut tools = Vec::new();
    let mut skipped = Vec::new();
    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;

    for page_idx in 0..20 {
        let params = match cursor.as_deref() {
            Some(cur) => json!({ "cursor": cur }),
            None => json!({}),
        };
        let rpc_id = 2 + page_idx as u64;
        let list_req = json!({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "tools/list",
            "params": params
        });
        let result =
            post_mcp_rpc(&client, url, token, &mut session_id, &list_req, Some(rpc_id)).await?;
        if let Some(arr) = result.get("tools").and_then(Value::as_array) {
            for item in arr {
                let Some(name) = item.get("name").and_then(Value::as_str).map(str::trim) else {
                    continue;
                };
                if !is_valid_mcp_tool_name(name) {
                    if !name.is_empty() {
                        skipped.push(name.to_owned());
                    }
                    continue;
                }
                if !seen.insert(name.to_owned()) || tools.len() >= MAX_TOOLS_PER_APP {
                    continue;
                }
                let description = item
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                let input_schema = item
                    .get("inputSchema")
                    .or_else(|| item.get("input_schema"))
                    .filter(|v| v.is_object())
                    .cloned()
                    .unwrap_or_else(default_input_schema);
                let annotations = item.get("annotations");
                let read_only = annotations
                    .and_then(|a| a.get("readOnlyHint"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let destructive = annotations
                    .and_then(|a| a.get("destructiveHint"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let granted_to = existing_grants.get(name).cloned().unwrap_or_default();
                tools.push(StoredMcpTool {
                    name: name.to_owned(),
                    description,
                    input_schema,
                    effect: if read_only {
                        "read".to_owned()
                    } else {
                        "write".to_owned()
                    },
                    destructive,
                    granted_to,
                });
            }
        }
        cursor = result
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    Ok((tools, skipped))
}

/// Calls a single tool on the configured MCP server (`initialize` -> `tools/call`).
pub async fn execute_mcp_tool_call(
    db: &Arc<Storage>,
    org: &str,
    app_id: &str,
    tool_name: &str,
    args: Value,
) -> Result<Value, String> {
    let org_c = org.to_owned();
    let app_c = app_id.to_owned();
    let db_c = db.clone();
    let app = tokio::task::spawn_blocking(move || {
        db_c.try_with_connection(|c| Ok(load_apps(c, &org_c).into_iter().find(|a| a.id == app_c)))
    })
    .await
    .map_err(|_| "Failed to query MCP configuration".to_owned())?
    .map_err(|_| "Database error reading MCP app".to_owned())?
    .ok_or_else(|| format!("MCP server '{app_id}' is no longer connected."))?;

    validate_mcp_url(&app.address).map_err(str::to_owned)?;
    let client = build_http_client(MCP_CALL_TIMEOUT)?;
    let mut session_id = mcp_handshake(&client, &app.address, app.token.as_deref()).await?;

    let call_req = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": if args.is_object() { args } else { json!({}) }
        }
    });
    let result = post_mcp_rpc(
        &client,
        &app.address,
        app.token.as_deref(),
        &mut session_id,
        &call_req,
        Some(100),
    )
    .await?;

    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut texts = Vec::new();
    if let Some(items) = result.get("content").and_then(Value::as_array) {
        for item in items {
            if item.get("type").and_then(Value::as_str) == Some("text") {
                if let Some(t) = item.get("text").and_then(Value::as_str) {
                    texts.push(t.to_owned());
                }
            } else if let Ok(serialized) = serde_json::to_string(item) {
                texts.push(serialized);
            }
        }
    }
    let joined = texts.join("\n");
    if is_error {
        return Ok(json!({
            "ok": false,
            "appId": app_id,
            "tool": tool_name,
            "error": if joined.is_empty() { "MCP tool reported an error".to_owned() } else { joined },
            "structuredContent": result.get("structuredContent").cloned().unwrap_or(Value::Null),
        }));
    }
    if let Some(structured) = result.get("structuredContent").filter(|v| !v.is_null()) {
        return Ok(json!({
            "ok": true,
            "appId": app_id,
            "tool": tool_name,
            "output": joined,
            "result": structured,
        }));
    }
    if let Ok(parsed_json) = serde_json::from_str::<Value>(&joined) {
        if parsed_json.is_object() {
            return Ok(parsed_json);
        }
    }
    Ok(json!({
        "ok": true,
        "appId": app_id,
        "tool": tool_name,
        "output": joined,
    }))
}

// ---------------------------------------------------------------------------
// HTTP Handlers
// ---------------------------------------------------------------------------

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/apps",
            get(list_apps).post(create_app),
        )
        .route(
            "/api/v2/organizations/{organization}/apps/{app_id}",
            get(get_app)
                .patch(update_app)
                .put(replace_app)
                .delete(delete_app),
        )
        .route(
            "/api/v2/organizations/{organization}/apps/{app_id}/refresh",
            post(refresh_app),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/grants/{grant_id}",
            put(replace_bot_grant).delete(delete_bot_grant),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/grants/batch",
            post(batch_update_bot_grants),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/apps/{app_id}/give",
            post(give_bot_app),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/apps/{app_id}/take-back",
            post(take_back_bot_app),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

#[derive(Deserialize, Default)]
struct AppsListQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn list_apps(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<AppsListQuery>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    if q.limit.is_some_and(|n| n == 0 || n > 100) {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid paging limit.",
        );
    }
    let db = s.db.clone();
    let org_c = actor.organization;
    let apps_res =
        tokio::task::spawn_blocking(move || db.try_with_connection(|c| Ok(load_apps(c, &org_c))))
            .await;
    match apps_res {
        Ok(Ok(mut apps)) => {
            apps.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
            let offset = q
                .cursor
                .as_deref()
                .and_then(|c| c.parse::<usize>().ok())
                .unwrap_or(0);
            let limit = q.limit.unwrap_or(100);
            let slice: Vec<Value> = apps
                .iter()
                .skip(offset)
                .take(limit)
                .map(to_public_app)
                .collect();
            let next_cursor = if offset + slice.len() < apps.len() {
                Value::String((offset + slice.len()).to_string())
            } else {
                Value::Null
            };
            respond_json(
                StatusCode::OK,
                json!({ "apps": slice, "nextCursor": next_cursor }),
            )
        }
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed to load apps.",
        ),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateAppBody {
    from: String,
    title: Option<String>,
    url: Option<String>,
    token: Option<String>,
}

async fn create_app(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<CreateAppBody>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    if body.from != "address" {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Only adding an MCP server by its address is supported on PS5 OpenBot.",
        );
    }
    let title = body.title.as_deref().unwrap_or("").trim().to_owned();
    if title.is_empty() || title.chars().count() > 60 {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Server name must be 1 to 60 characters.",
        );
    }
    let raw_url = body.url.as_deref().unwrap_or("").trim().to_owned();
    let parsed_url = match validate_mcp_url(&raw_url) {
        Ok(u) => u,
        Err(msg) => return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", msg),
    };
    let token = body
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned);

    let norm_new = normalize_mcp_url(&parsed_url);
    let url_check = parsed_url.clone();
    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let precheck = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            let apps = load_apps(c, &org_c);
            let duplicate = apps
                .iter()
                .find(|a| {
                    Url::parse(&a.address)
                        .ok()
                        .map(|u| normalize_mcp_url(&u))
                        .as_deref()
                        == Some(norm_new.as_str())
                })
                .map(|a| a.id.clone());
            let allowlisted = is_url_allowlisted(c, &org_c, &url_check);
            Ok((apps.len(), duplicate, allowlisted))
        })
    })
    .await;

    let (count, duplicate, allowlisted) = match precheck {
        Ok(Ok(v)) => v,
        _ => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SERVER_ERROR",
                "Failed checking server list.",
            )
        }
    };
    if let Some(dup_id) = duplicate {
        return problem_with_extra(
            StatusCode::CONFLICT,
            "APP_ALREADY_ADDED",
            "This server address is already connected.",
            Some(&dup_id),
        );
    }
    if !allowlisted {
        return problem(
            StatusCode::FORBIDDEN,
            "APP_NOT_APPROVED",
            "This server is not on the organization's allowlist.",
        );
    }
    if count >= MAX_APPS_PER_ORG {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Maximum number of connected MCP servers reached.",
        );
    }

    let empty_grants = HashMap::new();
    let probe = fetch_mcp_tools(parsed_url.as_str(), token.as_deref(), &empty_grants).await;
    let (tools, skipped, last_error) = match probe {
        Ok((t, s_tools)) => (t, s_tools, None),
        Err(err) => return problem(StatusCode::BAD_GATEWAY, "APP_CONNECT_FAILED", &err),
    };

    let db = s.db.clone();
    let org_c = actor.organization;
    let addr_str = parsed_url.to_string();
    let vendor_host = parsed_url.host_str().map(str::to_owned);
    let actor_email = actor.email;
    let saved = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            let mut apps = load_apps(c, &org_c);
            let id = slugify_app_id(&title, &apps);
            let ts = iso_now(c);
            let app = StoredMcpApp {
                id,
                title,
                address: addr_str,
                token,
                vendor: vendor_host,
                owner_grants: "any".to_owned(),
                owner_grants_chosen: Some("any".to_owned()),
                added_by: Some(actor_email),
                tools_refreshed_at: Some(ts),
                last_error,
                skipped_tools: skipped,
                tools,
            };
            let pub_json = to_public_app(&app);
            apps.push(app);
            save_apps(c, &org_c, &apps)?;
            Ok(pub_json)
        })
    })
    .await;

    match saved {
        Ok(Ok(app_json)) => respond_json(StatusCode::CREATED, app_json),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed to save MCP server.",
        ),
    }
}

async fn get_app(
    State(s): State<AuthState>,
    Path((org, app_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let db = s.db.clone();
    let org_c = actor.organization;
    let res = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            Ok(load_apps(c, &org_c)
                .into_iter()
                .find(|a| a.id == app_id)
                .map(|a| to_public_app(&a)))
        })
    })
    .await;
    match res {
        Ok(Ok(Some(v))) => respond_json(StatusCode::OK, v),
        Ok(Ok(None)) => problem(StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found."),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed loading app.",
        ),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateAppBody {
    owner_grants: Option<Option<String>>,
}

async fn update_app(
    State(s): State<AuthState>,
    Path((org, app_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<UpdateAppBody>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    if let Some(Some(ref og)) = body.owner_grants {
        if og != "any" && og != "admin" {
            return problem(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Invalid ownerGrants.",
            );
        }
    }
    let db = s.db.clone();
    let org_c = actor.organization;
    let res = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            let mut apps = load_apps(c, &org_c);
            let Some(app) = apps.iter_mut().find(|a| a.id == app_id) else {
                return Ok(None);
            };
            if let Some(og_opt) = body.owner_grants {
                match og_opt {
                    Some(og) => {
                        app.owner_grants = og.clone();
                        app.owner_grants_chosen = Some(og);
                    }
                    None => {
                        app.owner_grants = "any".to_owned();
                        app.owner_grants_chosen = None;
                    }
                }
            }
            let out = to_public_app(app);
            save_apps(c, &org_c, &apps)?;
            Ok(Some(out))
        })
    })
    .await;
    match res {
        Ok(Ok(Some(v))) => respond_json(StatusCode::OK, v),
        Ok(Ok(None)) => problem(StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found."),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed updating app.",
        ),
    }
}

#[derive(Deserialize)]
struct ReplaceAppBody {
    title: String,
    url: String,
}

async fn replace_app(
    State(s): State<AuthState>,
    Path((org, app_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<ReplaceAppBody>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let title = body.title.trim().to_owned();
    if title.is_empty() || title.chars().count() > 200 {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Invalid server title.",
        );
    }
    let parsed_url = match validate_mcp_url(&body.url) {
        Ok(u) => u,
        Err(msg) => return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", msg),
    };

    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let app_c = app_id.clone();
    let existing = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| Ok(load_apps(c, &org_c).into_iter().find(|a| a.id == app_c)))
    })
    .await;
    let Some(cur) = (match existing {
        Ok(Ok(v)) => v,
        _ => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SERVER_ERROR",
                "Failed loading app.",
            )
        }
    }) else {
        return problem(StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found.");
    };

    let grants_map: HashMap<String, Vec<String>> = cur
        .tools
        .iter()
        .map(|t| (t.name.clone(), t.granted_to.clone()))
        .collect();
    let probe = fetch_mcp_tools(parsed_url.as_str(), cur.token.as_deref(), &grants_map).await;

    let db = s.db.clone();
    let org_c = actor.organization;
    let addr = parsed_url.to_string();
    let vendor_host = parsed_url.host_str().map(str::to_owned);
    let saved = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            let mut apps = load_apps(c, &org_c);
            let Some(app) = apps.iter_mut().find(|a| a.id == app_id) else {
                return Ok(None);
            };
            app.title = title;
            app.address = addr;
            app.vendor = vendor_host;
            match probe {
                Ok((t, sk)) => {
                    app.tools = t;
                    app.skipped_tools = sk;
                    app.last_error = None;
                    app.tools_refreshed_at = Some(iso_now(c));
                }
                Err(err) => {
                    app.last_error = Some(err);
                }
            }
            let out = to_public_app(app);
            save_apps(c, &org_c, &apps)?;
            Ok(Some(out))
        })
    })
    .await;

    match saved {
        Ok(Ok(Some(v))) => respond_json(StatusCode::OK, v),
        Ok(Ok(None)) => problem(StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found."),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed updating app.",
        ),
    }
}

async fn delete_app(
    State(s): State<AuthState>,
    Path((org, app_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let db = s.db.clone();
    let org_c = actor.organization;
    let res = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            let mut apps = load_apps(c, &org_c);
            let before = apps.len();
            apps.retain(|a| a.id != app_id);
            if apps.len() == before {
                return Ok(false);
            }
            save_apps(c, &org_c, &apps)?;
            Ok(true)
        })
    })
    .await;
    match res {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => problem(StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found."),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed deleting app.",
        ),
    }
}

async fn refresh_app(
    State(s): State<AuthState>,
    Path((org, app_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let app_c = app_id.clone();
    let existing = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| Ok(load_apps(c, &org_c).into_iter().find(|a| a.id == app_c)))
    })
    .await;
    let Some(cur) = (match existing {
        Ok(Ok(v)) => v,
        _ => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SERVER_ERROR",
                "Failed loading app.",
            )
        }
    }) else {
        return problem(StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found.");
    };

    if let Err(msg) = validate_mcp_url(&cur.address) {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", msg);
    }

    let grants_map: HashMap<String, Vec<String>> = cur
        .tools
        .iter()
        .map(|t| (t.name.clone(), t.granted_to.clone()))
        .collect();
    let probe = fetch_mcp_tools(&cur.address, cur.token.as_deref(), &grants_map).await;
    let probe_err = probe.as_ref().err().cloned();

    let db = s.db.clone();
    let org_c = actor.organization;
    let saved = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            let mut apps = load_apps(c, &org_c);
            let Some(app) = apps.iter_mut().find(|a| a.id == app_id) else {
                return Ok(None);
            };
            match probe {
                Ok((t, sk)) => {
                    app.tools = t;
                    app.skipped_tools = sk;
                    app.last_error = None;
                    app.tools_refreshed_at = Some(iso_now(c));
                }
                Err(err) => {
                    app.last_error = Some(err);
                }
            }
            let out = to_public_app(app);
            save_apps(c, &org_c, &apps)?;
            Ok(Some(out))
        })
    })
    .await;

    if let Some(err_msg) = probe_err {
        return problem(StatusCode::CONFLICT, "APP_REFRESH_FAILED", &err_msg);
    }
    match saved {
        Ok(Ok(Some(v))) => respond_json(StatusCode::OK, v),
        Ok(Ok(None)) => problem(StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found."),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed refreshing app.",
        ),
    }
}

fn parse_action_grant_id(grant_id: &str) -> Option<(String, String)> {
    let rest = grant_id.strip_prefix("action:")?;
    let (app_id, tool_name) = rest.split_once(':')?;
    if app_id.is_empty() || tool_name.is_empty() {
        return None;
    }
    Some((app_id.to_owned(), tool_name.to_owned()))
}

fn bot_exists_for_actor(
    c: &rusqlite::Connection,
    org: &str,
    bot_id: &str,
    actor: &Identity,
) -> Result<bool, StorageError> {
    let is_owner_check: Option<String> = c
        .query_row(
            "SELECT owner_id FROM port_bots WHERE id=?1 AND organization_id=?2",
            rusqlite::params![bot_id, org],
            |r| r.get(0),
        )
        .ok();
    let Some(owner_id) = is_owner_check else {
        return Ok(false);
    };
    if owner_id == actor.id {
        return Ok(true);
    }
    let role: Option<String> = c
        .query_row(
            "SELECT role FROM port_users WHERE id=?1",
            rusqlite::params![actor.id],
            |r| r.get(0),
        )
        .ok();
    Ok(role.as_deref() == Some("owner") || role.as_deref() == Some("admin"))
}

async fn replace_bot_grant(
    State(s): State<AuthState>,
    Path((org, bot_id, grant_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    if let Some(slug) = grant_id.strip_prefix("skill:").map(str::to_owned) {
        let db = s.db.clone();
        let org_c = actor.organization.clone();
        let res = tokio::task::spawn_blocking(move || {
            db.try_with_connection(|c| {
                if !bot_exists_for_actor(c, &org_c, &bot_id, &actor)? {
                    return Ok(Err((StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")));
                }
                let mut skills = crate::compat_extra::read_skills_for_org(c, &org_c)?;
                let Some(sk) = skills
                    .iter_mut()
                    .find(|x| x.get("slug").and_then(Value::as_str) == Some(slug.as_str()))
                else {
                    return Ok(Err((
                        StatusCode::NOT_FOUND,
                        "BOT_GRANT_NOT_FOUND",
                        "Skill not found.",
                    )));
                };
                if !sk.get("botIds").is_some_and(Value::is_array) {
                    sk["botIds"] = json!([]);
                }
                if let Some(arr) = sk.get_mut("botIds").and_then(Value::as_array_mut) {
                    if !arr.iter().filter_map(Value::as_str).any(|b| b == bot_id) {
                        arr.push(Value::String(bot_id.clone()));
                    }
                }
                let title = sk
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or(&slug)
                    .to_owned();
                let summary = sk
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                save_kv(c, &format!("skills:{org_c}"), &Value::Array(skills))?;
                Ok(Ok(json!({
                    "id": format!("skill:{slug}"),
                    "kind": "skill",
                    "ref": slug,
                    "action": Value::Null,
                    "skill": { "slug": slug, "title": title, "summary": summary },
                })))
            })
        })
        .await;
        return match res {
            Ok(Ok(Ok(g))) => respond_json(StatusCode::OK, g),
            Ok(Ok(Err((st, code, msg)))) => problem(st, code, msg),
            _ => problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SERVER_ERROR",
                "Failed granting skill.",
            ),
        };
    }
    let Some((app_id, tool_name)) = parse_action_grant_id(&grant_id) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "Only app action grants are supported here.",
        );
    };
    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let res = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            if !bot_exists_for_actor(c, &org_c, &bot_id, &actor)? {
                return Ok(Err((StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")));
            }
            let mut apps = load_apps(c, &org_c);
            let Some(app) = apps.iter_mut().find(|a| a.id == app_id) else {
                return Ok(Err((StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found.")));
            };
            let Some(tool) = app.tools.iter_mut().find(|t| t.name == tool_name) else {
                return Ok(Err((
                    StatusCode::NOT_FOUND,
                    "BOT_GRANT_NOT_FOUND",
                    "Tool not offered by app.",
                )));
            };
            if !tool.granted_to.iter().any(|b| b == &bot_id) {
                tool.granted_to.push(bot_id.clone());
            }
            let grant_json = json!({
                "id": grant_id,
                "kind": "action",
                "ref": format!("{app_id}/{tool_name}"),
                "action": {
                    "appId": app_id,
                    "name": tool_name,
                    "description": tool.description,
                    "destructive": tool.destructive,
                    "read": tool.effect == "read",
                },
                "skill": Value::Null,
            });
            save_apps(c, &org_c, &apps)?;
            Ok(Ok(grant_json))
        })
    })
    .await;
    match res {
        Ok(Ok(Ok(g))) => respond_json(StatusCode::OK, g),
        Ok(Ok(Err((st, code, msg)))) => problem(st, code, msg),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed granting tool.",
        ),
    }
}

async fn delete_bot_grant(
    State(s): State<AuthState>,
    Path((org, bot_id, grant_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    if let Some(slug) = grant_id.strip_prefix("skill:").map(str::to_owned) {
        let db = s.db.clone();
        let org_c = actor.organization.clone();
        let res = tokio::task::spawn_blocking(move || {
            db.try_with_connection(|c| {
                if !bot_exists_for_actor(c, &org_c, &bot_id, &actor)? {
                    return Ok(Err((StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")));
                }
                let mut skills = crate::compat_extra::read_skills_for_org(c, &org_c)?;
                let Some(sk) = skills
                    .iter_mut()
                    .find(|x| x.get("slug").and_then(Value::as_str) == Some(slug.as_str()))
                else {
                    return Ok(Err((
                        StatusCode::NOT_FOUND,
                        "BOT_GRANT_NOT_FOUND",
                        "Grant not found.",
                    )));
                };
                let mut removed = false;
                if let Some(arr) = sk.get_mut("botIds").and_then(Value::as_array_mut) {
                    let before = arr.len();
                    arr.retain(|v| v.as_str() != Some(bot_id.as_str()));
                    removed = arr.len() != before;
                }
                if !removed {
                    return Ok(Err((
                        StatusCode::NOT_FOUND,
                        "BOT_GRANT_NOT_FOUND",
                        "Grant not found.",
                    )));
                }
                save_kv(c, &format!("skills:{org_c}"), &Value::Array(skills))?;
                Ok(Ok(()))
            })
        })
        .await;
        return match res {
            Ok(Ok(Ok(()))) => StatusCode::NO_CONTENT.into_response(),
            Ok(Ok(Err((st, code, msg)))) => problem(st, code, msg),
            _ => problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SERVER_ERROR",
                "Failed revoking skill.",
            ),
        };
    }
    let Some((app_id, tool_name)) = parse_action_grant_id(&grant_id) else {
        return problem(
            StatusCode::NOT_FOUND,
            "BOT_GRANT_NOT_FOUND",
            "Grant not found.",
        );
    };
    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let res = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            if !bot_exists_for_actor(c, &org_c, &bot_id, &actor)? {
                return Ok(Err((StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")));
            }
            let mut apps = load_apps(c, &org_c);
            let Some(app) = apps.iter_mut().find(|a| a.id == app_id) else {
                return Ok(Err((
                    StatusCode::NOT_FOUND,
                    "BOT_GRANT_NOT_FOUND",
                    "Grant not found.",
                )));
            };
            let Some(tool) = app.tools.iter_mut().find(|t| t.name == tool_name) else {
                return Ok(Err((
                    StatusCode::NOT_FOUND,
                    "BOT_GRANT_NOT_FOUND",
                    "Grant not found.",
                )));
            };
            let before = tool.granted_to.len();
            tool.granted_to.retain(|b| b != &bot_id);
            if tool.granted_to.len() == before {
                return Ok(Err((
                    StatusCode::NOT_FOUND,
                    "BOT_GRANT_NOT_FOUND",
                    "Grant not found.",
                )));
            }
            save_apps(c, &org_c, &apps)?;
            Ok(Ok(()))
        })
    })
    .await;
    match res {
        Ok(Ok(Ok(()))) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(Err((st, code, msg)))) => problem(st, code, msg),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed revoking tool.",
        ),
    }
}

async fn batch_update_bot_grants(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let res = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            if !bot_exists_for_actor(c, &org_c, &bot_id, &actor)? {
                return Ok(Err((StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")));
            }
            let mut apps = load_apps(c, &org_c);
            let mut changed = 0usize;
            if let Some(adds) = body.get("add").and_then(Value::as_array) {
                for item in adds {
                    let ref_str = item
                        .get("ref")
                        .or_else(|| item.get("action"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if let Some((aid, tname)) = ref_str.split_once('/') {
                        if let Some(tool) = apps
                            .iter_mut()
                            .find(|a| a.id == aid)
                            .and_then(|a| a.tools.iter_mut().find(|t| t.name == tname))
                        {
                            if !tool.granted_to.iter().any(|b| b == &bot_id) {
                                tool.granted_to.push(bot_id.clone());
                                changed += 1;
                            }
                        }
                    }
                }
            }
            if let Some(removes) = body.get("remove").and_then(Value::as_array) {
                for item in removes {
                    let ref_str = item.as_str().unwrap_or("");
                    if let Some((aid, tname)) = ref_str.split_once('/') {
                        if let Some(tool) = apps
                            .iter_mut()
                            .find(|a| a.id == aid)
                            .and_then(|a| a.tools.iter_mut().find(|t| t.name == tname))
                        {
                            let b = tool.granted_to.len();
                            tool.granted_to.retain(|x| x != &bot_id);
                            if tool.granted_to.len() != b {
                                changed += 1;
                            }
                        }
                    }
                }
            }
            save_apps(c, &org_c, &apps)?;
            Ok(Ok(json!({ "saved": changed })))
        })
    })
    .await;
    match res {
        Ok(Ok(Ok(v))) => respond_json(StatusCode::OK, v),
        Ok(Ok(Err((st, code, msg)))) => problem(st, code, msg),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed updating bot grants.",
        ),
    }
}

async fn give_bot_app(
    State(s): State<AuthState>,
    Path((org, bot_id, app_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let res = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            if !bot_exists_for_actor(c, &org_c, &bot_id, &actor)? {
                return Ok(Err((StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")));
            }
            let mut apps = load_apps(c, &org_c);
            let Some(app) = apps.iter_mut().find(|a| a.id == app_id) else {
                return Ok(Err((StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found.")));
            };
            let mut given = Vec::new();
            for tool in &mut app.tools {
                if !tool.granted_to.iter().any(|b| b == &bot_id) {
                    tool.granted_to.push(bot_id.clone());
                    given.push(format!("{app_id}/{}", tool.name));
                }
            }
            save_apps(c, &org_c, &apps)?;
            Ok(Ok(json!({ "given": given })))
        })
    })
    .await;
    match res {
        Ok(Ok(Ok(v))) => respond_json(StatusCode::OK, v),
        Ok(Ok(Err((st, code, msg)))) => problem(st, code, msg),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed giving app.",
        ),
    }
}

async fn take_back_bot_app(
    State(s): State<AuthState>,
    Path((org, bot_id, app_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let db = s.db.clone();
    let org_c = actor.organization.clone();
    let res = tokio::task::spawn_blocking(move || {
        db.try_with_connection(|c| {
            if !bot_exists_for_actor(c, &org_c, &bot_id, &actor)? {
                return Ok(Err((StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")));
            }
            let mut apps = load_apps(c, &org_c);
            let Some(app) = apps.iter_mut().find(|a| a.id == app_id) else {
                return Ok(Err((StatusCode::NOT_FOUND, "APP_NOT_FOUND", "App not found.")));
            };
            let mut taken = Vec::new();
            for tool in &mut app.tools {
                let before = tool.granted_to.len();
                tool.granted_to.retain(|b| b != &bot_id);
                if tool.granted_to.len() != before {
                    taken.push(format!("{app_id}/{}", tool.name));
                }
            }
            save_apps(c, &org_c, &apps)?;
            Ok(Ok(json!({ "takenBack": taken })))
        })
    })
    .await;
    match res {
        Ok(Ok(Ok(v))) => respond_json(StatusCode::OK, v),
        Ok(Ok(Err((st, code, msg)))) => problem(st, code, msg),
        _ => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SERVER_ERROR",
            "Failed taking back app.",
        ),
    }
}

#[allow(dead_code)]
pub fn summarize_apps_for_vocabulary(
    c: &rusqlite::Connection,
    org: &str,
) -> (Vec<Value>, Vec<Value>) {
    let apps = load_apps(c, org);
    let mut app_items = Vec::new();
    let mut tool_items = Vec::new();
    for app in apps {
        app_items.push(json!({ "id": app.id, "title": app.title }));
        let tools_arr: Vec<Value> = app
            .tools
            .iter()
            .map(|t| {
                let mut m = Map::new();
                m.insert("name".to_owned(), Value::String(t.name.clone()));
                m.insert("effect".to_owned(), Value::String(t.effect.clone()));
                Value::Object(m)
            })
            .collect();
        tool_items.extend(tools_arr);
    }
    (app_items, tool_items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    async fn mock_mcp_server() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = calls.clone();
        let router = Router::new().route(
            "/mcp",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let calls_ref = calls_ref.clone();
                async move {
                    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
                    let id = body.get("id").cloned().unwrap_or(Value::Null);
                    match method {
                        "initialize" => {
                            let auth_ok = headers
                                .get(header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                == Some("Bearer secret-tok");
                            if !auth_ok && headers.get(header::AUTHORIZATION).is_some() {
                                return (StatusCode::UNAUTHORIZED, "bad token").into_response();
                            }
                            (
                                StatusCode::OK,
                                [("Mcp-Session-Id", "sess-123")],
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": {
                                        "protocolVersion": "2025-03-26",
                                        "serverInfo": { "name": "mock-openmontage", "version": "1.0" },
                                        "capabilities": { "tools": {} }
                                    }
                                })),
                            )
                                .into_response()
                        }
                        "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
                        "tools/list" => Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [
                                    {
                                        "name": "openmontage_preflight",
                                        "description": "Check FFmpeg and Node availability",
                                        "inputSchema": { "type": "object", "properties": {} },
                                        "annotations": { "readOnlyHint": true }
                                    },
                                    {
                                        "name": "openmontage_run_tool",
                                        "description": "Run an OpenMontage video tool",
                                        "inputSchema": {
                                            "type": "object",
                                            "properties": { "tool": { "type": "string" } },
                                            "required": ["tool"]
                                        },
                                        "annotations": { "readOnlyHint": false, "destructiveHint": false }
                                    }
                                ]
                            }
                        }))
                        .into_response(),
                        "tools/call" => {
                            calls_ref.fetch_add(1, Ordering::SeqCst);
                            let name = body["params"]["name"].as_str().unwrap_or("");
                            Json(json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [{
                                        "type": "text",
                                        "text": json!({"ok": true, "called": name, "args": body["params"]["arguments"]}).to_string()
                                    }]
                                }
                            }))
                            .into_response()
                        }
                        _ => (StatusCode::BAD_REQUEST, "unknown method").into_response(),
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        (addr, calls, srv)
    }

    async fn authed_test_app() -> (Router, AuthState, String, String, std::path::PathBuf) {
        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).unwrap();
        let p = std::env::temp_dir()
            .join(format!("openbot_mcp_test_{:x}.db", u64::from_le_bytes(rand)));
        let _ = std::fs::remove_file(&p);
        let db = Arc::new(Storage::open(&p).unwrap());
        let state = AuthState::new(
            db,
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let app = crate::local_auth::router(state.clone())
            .merge(crate::bots::router(state.clone()))
            .merge(router(state.clone()));

        let setup_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/port/auth/setup")
                    .header("host", "example.test")
                    .header("origin", "http://example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"a long secure password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(setup_resp.status(), StatusCode::NO_CONTENT);
        let cookie = setup_resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let create_bot = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/organizations/default/bots")
                    .header("host", "example.test")
                    .header("origin", "http://example.test")
                    .header("cookie", &cookie)
                    .header("idempotency-key", "mcp-test-bot")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"Montage","title":"","roleDescription":"Editor","visibility":"private"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_bot.status(), StatusCode::CREATED);
        let bot_json: Value = serde_json::from_slice(
            &to_bytes(create_bot.into_body(), 16384).await.unwrap(),
        )
        .unwrap();
        let bot_id = bot_json["bot"]["id"].as_str().unwrap().to_owned();
        (app, state, cookie, bot_id, p)
    }

    #[test]
    fn url_validation_allows_lan_http_and_blocks_metadata() {
        assert!(validate_mcp_url("http://192.168.10.25:8765/mcp").is_ok());
        assert!(validate_mcp_url("http://127.0.0.1:8765/mcp").is_ok());
        assert!(validate_mcp_url("https://mcp.example.com/mcp").is_ok());
        assert!(validate_mcp_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_mcp_url("http://example.com/mcp").is_err());
        assert!(validate_mcp_url("file:///etc/passwd").is_err());
        assert!(validate_mcp_url("https://user:pass@example.com/mcp").is_err());
    }

    #[tokio::test]
    async fn mcp_app_lifecycle_grant_discovery_and_execution() {
        let (mock_url, calls, srv) = mock_mcp_server().await;
        let (app, state, cookie, bot_id, db_path) = authed_test_app().await;
        let host = "example.test";
        let origin = "http://example.test";

        let create_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v2/organizations/default/apps")
                    .header("host", host)
                    .header("origin", origin)
                    .header("cookie", &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "from": "address",
                            "title": "OpenMontage Studio",
                            "url": format!("{mock_url}/mcp"),
                            "token": "secret-tok"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let created: Value =
            serde_json::from_slice(&to_bytes(create_resp.into_body(), 16384).await.unwrap())
                .unwrap();
        assert_eq!(created["id"], "openmontage-studio");
        assert_eq!(created["hasCredential"], true);
        assert_eq!(created["tools"].as_array().unwrap().len(), 2);
        assert_eq!(created["tools"][0]["effect"], "read");
        assert_eq!(created["tools"][1]["effect"], "write");

        let grant_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!(
                        "/api/v2/organizations/default/bots/{bot_id}/grants/action:openmontage-studio:openmontage_preflight"
                    ))
                    .header("host", host)
                    .header("origin", origin)
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(grant_resp.status(), StatusCode::OK);

        let loaded = state
            .db
            .try_with_connection(|c| Ok(load_bot_mcp_tools(c, "default", &bot_id)))
            .unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].fn_name,
            "mcp__openmontage-studio__openmontage_preflight"
        );

        let exec = execute_mcp_tool_call(
            &state.db,
            "default",
            "openmontage-studio",
            "openmontage_preflight",
            json!({"verbose": true}),
        )
        .await
        .unwrap();
        assert_eq!(exec["ok"], true);
        assert_eq!(exec["called"], "openmontage_preflight");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let del_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v2/organizations/default/apps/openmontage-studio")
                    .header("host", host)
                    .header("origin", origin)
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        srv.abort();
        drop(app);
        drop(state);
        let _ = std::fs::remove_file(db_path);
    }
}
