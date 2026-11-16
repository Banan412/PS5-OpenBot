//! OpenAPI-faithful compatibility & UI support routes for settings,
//! preferences, profile, capabilities, learning, recorder, memory, skills,
//! API keys, sessions, teams, and bot flags.
use crate::{
    compat_routes::{
        authorize, epoch, format_iso_utc, internal, is_admin, parse_empty_list_paging, problem,
        require_person, respond_json, run_db, valid_non_empty_param,
    },
    local_auth::{AuthState, Identity},
    storage::StorageError,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashMap;

const MAX_BODY_BYTES: usize = 128 * 1024;

/// Builds the router covering remaining OpenAPI compatibility & save routes.
pub fn router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/deployment",
            get(get_deployment),
        )
        .route(
            "/api/v2/organizations/{organization}/settings",
            get(get_org_settings).patch(patch_org_settings),
        )
        .route(
            "/api/v2/organizations/{organization}/profile",
            patch(update_organization),
        )
        .route(
            "/api/v2/organizations/{organization}/setup-checklist",
            get(get_setup_checklist),
        )
        .route(
            "/api/v2/organizations/{organization}/setup-checklist/check",
            post(check_setup_checklist),
        )
        .route(
            "/api/v2/organizations/{organization}/product-events",
            post(record_product_event),
        )
        .route(
            "/api/v2/organizations/{organization}/people",
            get(list_people),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}",
            get(get_person).patch(update_person),
        )
        .route(
            "/api/v2/organizations/{organization}/members",
            get(list_org_members),
        )
        .route(
            "/api/v2/organizations/{organization}/members/{person}",
            patch(update_org_member).delete(remove_org_member),
        )
        .route(
            "/api/v2/organizations/{organization}/capabilities",
            get(list_capabilities),
        )
        .route(
            "/api/v2/organizations/{organization}/capabilities/{capability_id}",
            patch(update_capability),
        )
        .route(
            "/api/v2/organizations/{organization}/capabilities/batch-update",
            post(batch_update_capabilities),
        )
        .route(
            "/api/v2/organizations/{organization}/capabilities/translate",
            post(translate_capabilities),
        )
        .route(
            "/api/v2/organizations/{organization}/capabilities/preview",
            post(preview_capabilities),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/capabilities",
            get(get_person_capabilities),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/instructions",
            get(get_instructions)
                .patch(update_instructions)
                .put(update_instructions),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/onboarding/advance",
            post(advance_or_complete_onboarding),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/onboarding/complete",
            post(advance_or_complete_onboarding),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/approval-preferences",
            get(get_approval_preferences)
                .patch(save_approval_preferences)
                .put(save_approval_preferences),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/approval-modes/{conversation_id}",
            get(get_approval_mode),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/questions",
            get(list_questions),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/conversation-grants",
            get(list_conversation_grants),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/conversation-grants/{grant_id}",
            delete(delete_conversation_grant),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/recorder-connections",
            get(list_recorder_connections),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/browser/open",
            post(open_person_browser),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/recorder-connections/{connection_id}",
            delete(delete_recorder_connection),
        )
        .route(
            "/api/v2/organizations/{organization}/recorder-connections/current",
            delete(delete_current_recorder_connection),
        )
        .route(
            "/api/v2/organizations/{organization}/recorder/me",
            get(get_recorder_identity),
        )
        .route(
            "/api/v2/organizations/{organization}/recorder/learning",
            get(get_recorder_learning),
        )
        .route(
            "/api/v2/organizations/{organization}/recorder/activity",
            post(report_recorder_activity),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/recordings",
            get(list_recordings),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/recording-titles",
            get(get_recording_titles),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/learning-settings",
            get(get_person_learning_settings)
                .patch(save_person_learning_settings)
                .put(save_person_learning_settings),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/learning-review",
            get(get_person_learning_review),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/learning-proposals",
            get(list_person_learning_proposals),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/learned-skills/{skill_name}",
            patch(update_learned_skill),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/learned-skills/{skill_name}/share",
            post(request_skill_sharing),
        )
        .route(
            "/api/v2/organizations/{organization}/settings/learning",
            get(get_learning_settings)
                .patch(save_learning_settings)
                .put(save_learning_settings),
        )
        .route(
            "/api/v2/organizations/{organization}/settings/learning/overview",
            get(get_learning_overview),
        )
        .route(
            "/api/v2/organizations/{organization}/settings/learning/skills",
            get(list_published_skills),
        )
        .route(
            "/api/v2/organizations/{organization}/settings/learning/proposals",
            get(list_learning_proposals),
        )
        .route(
            "/api/v2/organizations/{organization}/settings/learning/runs",
            get(list_learning_runs),
        )
        .route(
            "/api/v2/organizations/{organization}/personal-learning-proposals",
            get(list_personal_learning_proposals),
        )
        .route(
            "/api/v2/organizations/{organization}/skill-sharing-requests",
            get(list_skill_sharing_requests),
        )
        .route(
            "/api/v2/organizations/{organization}/skills/{skill_id}",
            get(get_skill).put(replace_skill).delete(delete_skill),
        )
        .route(
            "/api/v2/organizations/{organization}/skills/{skill_id}/team-grants",
            get(get_skill_team_grants).put(replace_skill_team_grants),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/learning-status",
            get(get_bot_learning_status),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/handoff",
            get(get_bot_handoff),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/lifecycle",
            get(get_bot_lifecycle),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/pause",
            post(pause_bot),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/resume",
            post(resume_bot),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/hide",
            post(hide_bot),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/unhide",
            post(unhide_bot),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/pin",
            post(pin_bot),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/unpin",
            post(unpin_bot),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/reset",
            post(reset_bot),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/activity",
            get(get_bot_activity),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/shared-use",
            get(get_bot_shared_use),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/apps",
            get(list_bot_apps),
        )
        .route(
            "/api/v2/organizations/{organization}/bots/{bot_id}/memory-source-tools",
            get(list_bot_memory_source_tools),
        )
        .route(
            "/api/v2/organizations/{organization}/audit-events/vocabulary",
            get(get_audit_event_vocabulary),
        )
        .route(
            "/api/v2/organizations/{organization}/audit-events/export",
            get(export_audit_events),
        )
        .route(
            "/api/v2/organizations/{organization}/what-if/vocabulary",
            get(get_what_if_vocabulary),
        )
        .route(
            "/api/v2/organizations/{organization}/model-key",
            get(get_model_key),
        )
        .route(
            "/api/v2/organizations/{organization}/model-catalogue",
            get(get_model_catalogue),
        )
        .route(
            "/api/v2/organizations/{organization}/model-usage",
            get(get_model_usage),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/model-choices/{conversation_id}",
            get(get_model_choice)
                .put(save_model_choice)
                .patch(save_model_choice),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/notification-settings",
            get(get_notification_settings)
                .patch(save_notification_settings)
                .put(save_notification_settings),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/bot-notification-settings/{bot_id}",
            get(get_bot_notification_settings)
                .patch(save_bot_notification_settings)
                .put(save_bot_notification_settings),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/host-access",
            get(get_host_access),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/devices",
            get(list_devices),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/devices/{device_id}",
            put(register_device).delete(delete_device),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/memories",
            get(list_memories).post(create_memory),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/memories/{memory_id}",
            patch(update_memory).delete(delete_memory),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/memory-sources",
            get(list_memory_sources).post(create_memory_source),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/memory-sources/{source_id}",
            patch(update_memory_source).delete(delete_memory_source),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/memory-sources/{source_id}/sync",
            post(sync_memory_source),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/api-keys",
            get(list_api_keys).post(create_api_key),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/api-keys/{key_id}",
            delete(delete_api_key),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/sessions",
            get(list_person_sessions),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/sessions/{session_id}",
            delete(delete_person_session),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/linked-accounts",
            get(list_linked_accounts),
        )
        .route(
            "/api/v2/organizations/{organization}/linked-account-providers",
            get(list_linked_account_providers),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/connections",
            get(list_connections),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/giveable-apps",
            get(list_giveable_apps),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/destinations",
            get(list_destinations),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/deliveries",
            get(list_deliveries),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/sign-in-requests",
            get(list_sign_in_requests),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/saved-logins",
            get(list_saved_logins),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/clear-team-bot-consents",
            post(clear_team_bot_consents),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/route",
            post(route_conversation_message),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/{conversation_id}/members",
            get(list_conversation_members).post(add_conversation_member),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/{conversation_id}/members/{member_id}",
            delete(remove_conversation_member),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/{conversation_id}/signal-busy",
            post(signal_conversation_busy),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/{conversation_id}/activity",
            post(record_conversation_activity),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/{conversation_id}/mark-read",
            post(mark_conversation_read),
        )
        .route(
            "/api/v2/organizations/{organization}/conversations/{conversation_id}/voice-sessions",
            get(list_voice_sessions),
        )
        .route(
            "/api/v2/organizations/{organization}/voice-configuration",
            get(get_voice_configuration),
        )
        .route(
            "/api/v2/organizations/{organization}/reactions",
            get(list_reactions),
        )
        .route(
            "/api/v2/organizations/{organization}/check-ins",
            get(list_check_ins),
        )
        .route(
            "/api/v2/organizations/{organization}/check-in-items",
            get(list_check_in_items),
        )
        .route(
            "/api/v2/organizations/{organization}/check-in-usage",
            get(get_check_in_usage),
        )
        .route(
            "/api/v2/organizations/{organization}/goals",
            get(list_goals),
        )
        .route(
            "/api/v2/organizations/{organization}/tasks",
            get(list_tasks),
        )
        .route(
            "/api/v2/organizations/{organization}/app-directory",
            get(list_app_directory),
        )
        .route(
            "/api/v2/organizations/{organization}/credentials",
            get(list_credentials),
        )
        .route(
            "/api/v2/organizations/{organization}/identity-providers",
            get(list_identity_providers),
        )
        .route(
            "/api/v2/organizations/{organization}/network-policies",
            get(list_network_policies),
        )
        .route(
            "/api/v2/organizations/{organization}/network-policies/{policy_id}",
            put(replace_network_policy).delete(delete_network_policy),
        )
        .route(
            "/api/v2/organizations/{organization}/network-policies/translate",
            post(translate_network_policy),
        )
        .route(
            "/api/v2/organizations/{organization}/network-policies/replay",
            post(replay_network_policy),
        )
        .route(
            "/api/v2/organizations/{organization}/computers",
            get(list_computers),
        )
        .route(
            "/api/v2/organizations/{organization}/settings/stop-inactive-computers",
            post(stop_computers_noop),
        )
        .route(
            "/api/v2/organizations/{organization}/people/{person}/stop-computers",
            post(stop_computers_noop),
        )
        .route(
            "/api/v2/organizations/{organization}/computers/{bot_id}/page-frames/{tool_call_id}",
            get(get_computer_page_frame),
        )
        .route(
            "/api/v2/organizations/{organization}/computer-actions",
            get(list_computer_actions),
        )
        .route(
            "/api/v2/organizations/{organization}/teams",
            get(list_teams).post(create_team),
        )
        .route(
            "/api/v2/organizations/{organization}/teams/{team_id}",
            get(get_team).patch(update_team).delete(delete_team),
        )
        .route(
            "/api/v2/organizations/{organization}/teams/{team_id}/members",
            get(list_team_members),
        )
        .route(
            "/api/v2/organizations/{organization}/teams/{team_id}/members/{member_id}",
            put(put_team_member).delete(remove_team_member),
        )
        .route(
            "/api/v2/organizations/{organization}/team-bots",
            get(list_team_bots),
        )
        .route(
            "/api/v2/organizations/{organization}/github-event-sources",
            get(list_github_event_sources),
        )
        .route(
            "/api/v2/organizations/{organization}/reviewer-guidance",
            get(get_reviewer_guidance)
                .put(replace_reviewer_guidance)
                .delete(delete_reviewer_guidance),
        )
        .route(
            "/api/v2/organizations/{organization}/reviewer-guidance/check",
            post(check_reviewer_guidance),
        )
        .route(
            "/api/v2/organizations/{organization}/reviewer-guidance/replay",
            get(get_reviewer_guidance_replay).post(replay_reviewer_guidance),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn ensure_kv_table(c: &rusqlite::Connection) -> Result<(), StorageError> {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS port_compat_kv (
           scope TEXT PRIMARY KEY,
           value TEXT NOT NULL,
           updated_at INTEGER NOT NULL
         );",
    )?;
    Ok(())
}

fn load_kv(c: &rusqlite::Connection, scope: &str) -> Result<Option<Value>, StorageError> {
    let res = c
        .query_row(
            "SELECT value FROM port_compat_kv WHERE scope=?1",
            params![scope],
            |r| r.get::<_, String>(0),
        )
        .optional();
    match res {
        Ok(Some(raw)) => Ok(serde_json::from_str(&raw).ok()),
        Ok(None) => Ok(None),
        Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("no such table") => {
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

fn save_kv(c: &rusqlite::Connection, scope: &str, value: &Value) -> Result<(), StorageError> {
    ensure_kv_table(c)?;
    let now = epoch()?;
    let raw = serde_json::to_string(value)
        .map_err(|_| StorageError::InvalidDatabase("json serialization failed"))?;
    c.execute(
        "INSERT INTO port_compat_kv(scope, value, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(scope) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        params![scope, raw, now],
    )?;
    Ok(())
}

fn random_hex(bytes: usize) -> Result<String, StorageError> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|_| StorageError::InvalidDatabase("entropy unavailable"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn now_iso(c: &rusqlite::Connection) -> Result<String, StorageError> {
    let ts = epoch()?;
    Ok(format_iso_utc(c, Some(ts))?.unwrap_or_else(|| "2026-01-01T00:00:00Z".into()))
}

fn person_json(actor: &Identity) -> Value {
    json!({
        "id": actor.id,
        "email": actor.email,
        "name": actor.name,
        "image": Value::Null,
        "role": actor.role,
        "needsName": false,
        "onboarding": Value::Null,
        "providers": [],
        "lastSignedInAt": Value::Null,
        "revoked": false,
        "configuredAdmin": is_admin(actor)
    })
}

fn ensure_bot_exists(
    c: &rusqlite::Connection,
    org: &str,
    owner_id: &str,
    bot_id: &str,
) -> Result<bool, StorageError> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3)",
        params![bot_id, org, owner_id],
        |r| r.get::<_, bool>(0),
    )?)
}

async fn empty_org_page(
    s: &AuthState,
    h: &HeaderMap,
    org: &str,
    q: &HashMap<String, String>,
    key: &str,
) -> Response {
    if let Err(e) = authorize(s, h, org, false).await {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ key: [], "nextCursor": Value::Null }),
    )
}

async fn empty_person_page(
    s: &AuthState,
    h: &HeaderMap,
    org: &str,
    person: &str,
    q: &HashMap<String, String>,
    key: &str,
) -> Response {
    let actor = match authorize(s, h, org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ key: [], "nextCursor": Value::Null }),
    )
}

// ---------------------------------------------------------------------------
// Deployment, Org Settings, Org Profile, Checklist, Telemetry
// ---------------------------------------------------------------------------

async fn get_deployment(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "edition": "team",
            "localEvaluation": false,
            "generativeUi": false,
            "selfHostBanner": false,
            "transcription": false,
            "voice": false,
            "durableHistory": true,
            "authProviders": [],
            "ssoConfigured": false,
            "ssoRequired": false,
            "builtInBots": true,
            "isolatedBots": false,
            "botComputers": true
        }),
    )
}

fn default_org_settings() -> Value {
    json!({
        "context": {
            "builtInModel": Value::Null,
            "directoryGroups": [],
            "apps": [],
            "defaultDestinations": [],
            "scim": {
                "configured": false,
                "connectionId": "scim_default",
                "baseUrl": Value::Null,
                "rotating": false
            },
            "otel": { "configured": false },
            "actionRecordRetentionDays": 30
        },
        "ssoRequired": false,
        "actionRecording": true,
        "inactiveComputerDays": 7,
        "modelAllowlist": { "enabled": false, "models": [] },
        "mcpAllowlist": { "enabled": false, "servers": [] },
        "skillSharing": false,
        "proactiveDailyRuns": 24,
        "modelSelection": true
    })
}

async fn get_org_settings(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = format!("org_settings:{}", actor.organization);
    let Ok(val) = run_db(&s, move |c| Ok(load_kv(c, &key)?.unwrap_or_else(default_org_settings))).await else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn patch_org_settings(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(patch_val): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Only an admin can change organization settings.",
        );
    }
    let Some(patch_obj) = patch_val.as_object() else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Expected object.");
    };
    let key = format!("org_settings:{}", actor.organization);
    let patch_clone = patch_obj.clone();
    let res = run_db(&s, move |c| {
        let mut cur = load_kv(c, &key)?.unwrap_or_else(default_org_settings);
        if let Some(obj) = cur.as_object_mut() {
            for (k, v) in patch_clone {
                if k != "context" {
                    obj.insert(k, v);
                }
            }
        }
        save_kv(c, &key, &cur)?;
        Ok(cur)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::OK, v),
        Err(_) => internal(),
    }
}

async fn update_organization(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Only an admin can update the organization.",
        );
    }
    let Some(name) = body.get("name").and_then(Value::as_str).map(str::trim) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Organization name is required.");
    };
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(|c| c == '\0') {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid organization name.");
    }
    let org_id = actor.organization.clone();
    let new_name = name.to_owned();
    if run_db(&s, move |c| {
        c.execute(
            "UPDATE auth_organizations SET name=?2 WHERE id=?1",
            params![org_id, new_name],
        )?;
        Ok(())
    })
    .await
    .is_err()
    {
        return internal();
    }
    respond_json(
        StatusCode::OK,
        json!({
            "organization": {
                "id": actor.organization,
                "slug": actor.slug,
                "name": name,
                "role": actor.role,
                "active": true,
                "personal": true
            }
        }),
    )
}

fn checklist_payload(actor: &Identity) -> Value {
    let audience = if is_admin(actor) { "admin" } else { "member" };
    json!({
        "audience": audience,
        "rows": [
            {
                "id": "model",
                "scope": "deployment",
                "title": "Model Gateway",
                "required": true,
                "status": "ready",
                "ready": true,
                "detail": "Connected to PS5LM gateway.",
                "fix": Value::Null
            },
            {
                "id": "computer",
                "scope": "deployment",
                "title": "Bot Computer",
                "required": false,
                "status": "ready",
                "ready": true,
                "detail": "PS5 shared virtual workspace active.",
                "fix": Value::Null
            }
        ]
    })
}

async fn get_setup_checklist(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    respond_json(StatusCode::OK, checklist_payload(&actor))
}

async fn check_setup_checklist(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    respond_json(StatusCode::OK, checklist_payload(&actor))
}

async fn record_product_event(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// People, Members, Capabilities, Instructions, Onboarding
// ---------------------------------------------------------------------------

async fn list_people(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "people": [person_json(&actor)],
            "nextCursor": Value::Null
        }),
    )
}

async fn get_person(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if person != "me" && person != actor.id {
        return problem(StatusCode::NOT_FOUND, "PERSON_NOT_FOUND", "Person not found.");
    }
    respond_json(
        StatusCode::OK,
        json!({
            "person": person_json(&actor),
            "openbotVersion": Value::Null
        }),
    )
}

pub(crate) async fn update_person_me(
    state: State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    body: Json<Value>,
) -> Response {
    update_person(state, Path((org, "me".to_owned())), h, body).await
}

async fn update_person(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let Some(obj) = body.as_object() else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Expected object.");
    };
    if obj.is_empty() {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "At least one field is required.");
    }
    let next_name = if let Some(v) = obj.get("name") {
        let Some(raw) = v.as_str().map(str::trim) else {
            return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid name.");
        };
        if raw.is_empty() || raw.chars().count() > 100 || raw.chars().any(|c| c == '\0') {
            return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid name.");
        }
        Some(raw.to_owned())
    } else {
        None
    };
    let next_role = if let Some(v) = obj.get("role") {
        if !is_admin(&actor) {
            return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Only an admin can change roles.");
        }
        match v.as_str() {
            Some(r @ ("admin" | "member")) => Some(r.to_owned()),
            _ => return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid role."),
        }
    } else {
        None
    };
    let uid = actor.id.clone();
    let org_id = actor.organization.clone();
    let name_upd = next_name.clone();
    let role_upd = next_role.clone();
    if run_db(&s, move |c| {
        if let Some(n) = name_upd {
            c.execute("UPDATE auth_users SET display_name=?2 WHERE id=?1", params![uid, n])?;
        }
        if let Some(r) = role_upd {
            c.execute(
                "UPDATE auth_memberships SET role=?3 WHERE user_id=?1 AND organization_id=?2 AND role!='owner'",
                params![uid, org_id, r],
            )?;
        }
        Ok(())
    })
    .await
    .is_err()
    {
        return internal();
    }
    if let Some(n) = next_name {
        actor.name = n;
    }
    if let Some(r) = next_role {
        if actor.role != "owner" {
            actor.role = r;
        }
    }
    respond_json(StatusCode::OK, json!({ "person": person_json(&actor) }))
}

async fn list_org_members(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "members": [{
                "id": actor.id,
                "email": actor.email,
                "name": actor.name,
                "image": Value::Null,
                "role": actor.role,
                "joinedAt": "2026-01-01T00:00:00Z",
                "removable": false,
                "assignableRoles": []
            }],
            "nextCursor": Value::Null
        }),
    )
}

async fn update_org_member(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    update_person(State(s), Path((org, person)), h, Json(body)).await
}

async fn remove_org_member(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if person == actor.id || person == "me" {
        return problem(StatusCode::CONFLICT, "CANNOT_REMOVE_SELF", "Cannot remove yourself.");
    }
    problem(StatusCode::NOT_FOUND, "PERSON_NOT_FOUND", "Member not found.")
}

fn default_capabilities() -> Vec<Value> {
    let defs = [
        ("useBots", "Use Bots", "Allow running and messaging Bots.", true),
        ("cloudBrowser", "Cloud Browser", "Remote browser session integration.", false),
        ("cloudNetwork", "Cloud Network", "Managed network egress.", false),
        ("cloudComputer", "Bot Computer", "Shared PS5 Bot workspace.", true),
        ("localComputer", "Local Computer", "Desktop host folder bridge.", false),
        ("customRules", "Custom Approval Rules", "Allow per-person approval rules.", true),
        ("passwordManager", "Password Manager", "Saved web sign-ins.", false),
        ("slackTeams", "Slack & Teams", "External chat destinations.", false),
        ("teamBots", "Team Bots", "Share Bots across the team.", true),
        ("ownerApps", "Owner Apps", "Connect personal apps.", true),
        ("isolatedComputers", "Isolated Computers", "Per-Bot isolated environments.", false),
        ("proactive", "Proactive Check-ins", "Scheduled check-ins.", true),
    ];
    defs.into_iter()
        .map(|(id, title, description, default_val)| {
            json!({
                "id": id,
                "title": title,
                "description": description,
                "default": default_val,
                "organization": Value::Null,
                "roles": {},
                "groups": {},
                "teams": {}
            })
        })
        .collect()
}

fn load_capabilities_list(c: &rusqlite::Connection, org_id: &str) -> Result<Vec<Value>, StorageError> {
    let key = format!("capabilities:{org_id}");
    let mut defaults = default_capabilities();
    if let Some(saved) = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()) {
        for def in &mut defaults {
            let Some(id) = def.get("id").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            if let Some(prev) = saved
                .iter()
                .find(|x| x.get("id").and_then(Value::as_str) == Some(id.as_str()))
            {
                if let (Some(def_obj), Some(prev_obj)) = (def.as_object_mut(), prev.as_object()) {
                    for field in ["organization", "roles", "groups", "teams"] {
                        if let Some(v) = prev_obj.get(field) {
                            def_obj.insert(field.to_owned(), v.clone());
                        }
                    }
                }
            }
        }
    }
    Ok(defaults)
}

fn cap_allowed_for_actor(
    c: &rusqlite::Connection,
    org_id: &str,
    role: &str,
    cap_id: &str,
) -> Result<bool, StorageError> {
    let items = load_capabilities_list(c, org_id)?;
    let Some(item) = items
        .iter()
        .find(|x| x.get("id").and_then(Value::as_str) == Some(cap_id))
    else {
        return Ok(false);
    };
    Ok(item
        .pointer(&format!("/roles/{role}"))
        .and_then(Value::as_bool)
        .or_else(|| item.get("organization").and_then(Value::as_bool))
        .or_else(|| item.get("default").and_then(Value::as_bool))
        .unwrap_or(false))
}

fn apply_capability_patch(cap: &mut Value, body: &Value) {
    let Some(obj) = cap.as_object_mut() else { return };
    if let Some(org_val) = body.get("organization") {
        obj.insert("organization".into(), org_val.clone());
    }
    for sub in ["roles", "groups", "teams"] {
        if let Some(patch_map) = body.get(sub).and_then(Value::as_object) {
            let entry = obj.entry(sub).or_insert_with(|| json!({}));
            if let Some(existing) = entry.as_object_mut() {
                for (k, v) in patch_map {
                    if v.is_null() {
                        existing.remove(k);
                    } else if v.is_boolean() {
                        existing.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
}

async fn list_capabilities(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let org_id = actor.organization;
    let Ok(items) = run_db(&s, move |c| load_capabilities_list(c, &org_id)).await else {
        return internal();
    };
    respond_json(
        StatusCode::OK,
        json!({ "capabilities": items, "nextCursor": Value::Null }),
    )
}

async fn update_capability(
    State(s): State<AuthState>,
    Path((org, capability_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let org_id = actor.organization;
    let cap_id = capability_id;
    let res = run_db(&s, move |c| {
        let mut list = load_capabilities_list(c, &org_id)?;
        let Some(item) = list.iter_mut().find(|x| x.get("id").and_then(Value::as_str) == Some(&cap_id)) else {
            return Ok(None);
        };
        apply_capability_patch(item, &body);
        let updated = item.clone();
        save_kv(c, &format!("capabilities:{org_id}"), &Value::Array(list))?;
        Ok(Some(updated))
    })
    .await;
    match res {
        Ok(Some(v)) => respond_json(StatusCode::OK, v),
        Ok(None) => problem(StatusCode::NOT_FOUND, "NOT_FOUND", "Unknown capability."),
        Err(_) => internal(),
    }
}

async fn batch_update_capabilities(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let changes = body.get("changes").and_then(Value::as_array).cloned().unwrap_or_default();
    let org_id = actor.organization;
    let saved = changes.clone();
    if run_db(&s, move |c| {
        let mut list = load_capabilities_list(c, &org_id)?;
        for ch in &changes {
            if let Some(cid) = ch.get("capability").and_then(Value::as_str) {
                if let Some(item) = list.iter_mut().find(|x| x.get("id").and_then(Value::as_str) == Some(cid)) {
                    let scope = ch.get("scope").and_then(Value::as_str).unwrap_or("organization");
                    let value = ch.get("value").cloned().unwrap_or(Value::Null);
                    if scope == "organization" {
                        apply_capability_patch(item, &json!({ "organization": value }));
                    } else if let Some(role) = ch.get("role").and_then(Value::as_str) {
                        apply_capability_patch(item, &json!({ "roles": { role: value } }));
                    }
                }
            }
        }
        save_kv(c, &format!("capabilities:{org_id}"), &Value::Array(list))
    })
    .await
    .is_err()
    {
        return internal();
    }
    respond_json(StatusCode::OK, json!({ "saved": saved }))
}

async fn translate_capabilities(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "changes": [], "explanation": "No changes." }))
}

async fn preview_capabilities(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "affectedPeople": 0, "examples": [] }))
}

async fn get_person_capabilities(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let org_id = actor.organization.clone();
    let role = actor.role.clone();
    let Ok(items) = run_db(&s, move |c| load_capabilities_list(c, &org_id)).await else {
        return internal();
    };
    let mut map = serde_json::Map::new();
    for item in items {
        if let Some(id) = item.get("id").and_then(Value::as_str) {
            let eff = item
                .pointer(&format!("/roles/{role}"))
                .and_then(Value::as_bool)
                .or_else(|| item.get("organization").and_then(Value::as_bool))
                .or_else(|| item.get("default").and_then(Value::as_bool))
                .unwrap_or(false);
            map.insert(id.to_owned(), Value::Bool(eff));
        }
    }
    respond_json(
        StatusCode::OK,
        json!({ "capabilities": Value::Object(map), "enforced": false }),
    )
}

async fn get_instructions(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("instructions:{}:{}", actor.organization, actor.id);
    let Ok(val) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.unwrap_or_else(|| json!({ "instructions": "" })))
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn update_instructions(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let Some(raw) = body.get("instructions").and_then(Value::as_str) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "instructions string is required.");
    };
    let trimmed = raw.trim();
    if trimmed.chars().count() > 4000 || trimmed.chars().any(|c| c == '\0') {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid instructions.");
    }
    let val = json!({ "instructions": trimmed });
    let key = format!("instructions:{}:{}", actor.organization, actor.id);
    let val_save = val.clone();
    if run_db(&s, move |c| save_kv(c, &key, &val_save)).await.is_err() {
        return internal();
    }
    respond_json(StatusCode::OK, val)
}

async fn advance_or_complete_onboarding(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "person": person_json(&actor) }))
}

// ---------------------------------------------------------------------------
// Approval Preferences, Conversation Grants, Questions, Approval Modes
// ---------------------------------------------------------------------------

fn default_approval_prefs() -> Value {
    json!({
        "enabled": true,
        "autoReview": false,
        "hostCommands": "ask",
        "effectiveHostCommands": "ask"
    })
}

async fn get_approval_preferences(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("approval_prefs:{}:{}", actor.organization, actor.id);
    let Ok(val) = run_db(&s, move |c| Ok(load_kv(c, &key)?.unwrap_or_else(default_approval_prefs))).await else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn save_approval_preferences(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let Some(patch_obj) = body.as_object() else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Expected object.");
    };
    let key = format!("approval_prefs:{}:{}", actor.organization, actor.id);
    let p_clone = patch_obj.clone();
    let res = run_db(&s, move |c| {
        let mut cur = load_kv(c, &key)?.unwrap_or_else(default_approval_prefs);
        if let Some(enabled) = p_clone.get("enabled").and_then(Value::as_bool) {
            cur["enabled"] = json!(enabled);
        }
        if let Some(auto_review) = p_clone.get("autoReview").and_then(Value::as_bool) {
            cur["autoReview"] = json!(auto_review);
        }
        if let Some(hc) = p_clone.get("hostCommands").and_then(Value::as_str) {
            if matches!(hc, "ask" | "allow" | "never") {
                cur["hostCommands"] = json!(hc);
                cur["effectiveHostCommands"] = json!(hc);
            }
        }
        save_kv(c, &key, &cur)?;
        Ok(cur)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::OK, v),
        Err(_) => internal(),
    }
}

async fn get_approval_mode(
    State(s): State<AuthState>,
    Path((org, person, conversation_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if !valid_non_empty_param(&conversation_id, 200) {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid conversationId.");
    }
    respond_json(StatusCode::OK, json!({ "asksEveryStep": false }))
}

async fn list_questions(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "questions").await
}

async fn list_conversation_grants(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let org_id = actor.organization;
    let actor_id = actor.id;
    let Ok(grants) = run_db(&s, move |c| {
        let mut stmt = c.prepare(
            "SELECT id, thread_id, bot_id, tool_ref, effect, scope, account, kind, created_at
             FROM port_conversation_grants
             WHERE organization_id=?1 AND actor_id=?2
             ORDER BY created_at DESC, id DESC
             LIMIT 100",
        )?;
        let rows = stmt.query_map(params![org_id, actor_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, thread_id, bot_id, tool_ref, effect, scope, account, kind, created_at) = row?;
            let iso = format_iso_utc(c, Some(created_at))?
                .unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
            let mut obj = json!({
                "id": id,
                "threadId": thread_id,
                "botId": bot_id,
                "toolRef": tool_ref,
                "effect": effect,
                "scope": scope,
                "createdAt": iso
            });
            if let (Some(map), Some(acc)) = (obj.as_object_mut(), account) {
                map.insert("account".into(), Value::String(acc));
            }
            if let (Some(map), Some(k)) = (obj.as_object_mut(), kind) {
                map.insert("kind".into(), Value::String(k));
            }
            out.push(obj);
        }
        Ok(out)
    })
    .await
    else {
        return internal();
    };
    respond_json(
        StatusCode::OK,
        json!({ "conversationGrants": grants, "nextCursor": Value::Null }),
    )
}

async fn delete_conversation_grant(
    State(s): State<AuthState>,
    Path((org, person, grant_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let org_id = actor.organization;
    let uid = actor.id;
    let _ = run_db(&s, move |c| {
        c.execute(
            "DELETE FROM port_conversation_grants WHERE id=?1 AND organization_id=?2 AND actor_id=?3",
            params![grant_id, org_id, uid],
        )?;
        Ok(())
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Recorder, Learning, Skills
// ---------------------------------------------------------------------------

async fn list_recorder_connections(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "recorderConnections": [],
            "extensionIds": [],
            "nextCursor": Value::Null
        }),
    )
}

async fn delete_recorder_connection(
    State(s): State<AuthState>,
    Path((org, person, _conn_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn open_person_browser(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "ok": true,
            "computerId": "ps5-virtual",
            "browser": "chromium",
            "window": "screen",
            "narration": "own"
        }),
    )
}

async fn delete_current_recorder_connection(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn get_recorder_identity(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let name = if actor.name.is_empty() {
        &actor.email
    } else {
        &actor.name
    };
    respond_json(
        StatusCode::OK,
        json!({
            "user": { "id": actor.id, "name": name, "email": actor.email },
            "connectionId": "local"
        }),
    )
}

async fn get_recorder_learning(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "learning": { "state": "learning-off", "containerId": Value::Null } }),
    )
}

async fn report_recorder_activity(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn list_recordings(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "recordings").await
}

async fn get_recording_titles(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "recordings": [] }))
}

fn default_person_learning() -> Value {
    json!({
        "mode": "closed",
        "sharingAllowed": false,
        "autoApprove": Value::Null,
        "skills": []
    })
}

async fn get_person_learning_settings(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let org_id = actor.organization.clone();
    let key = format!("person_learning:{}:{}", org_id, actor.id);
    let Ok(val) = run_db(&s, move |c| {
        let mut cur = load_kv(c, &key)?.unwrap_or_else(default_person_learning);
        let org_sharing = load_kv(c, &format!("org_settings:{org_id}"))?
            .and_then(|v| v.get("skillSharing").and_then(Value::as_bool))
            .unwrap_or(false);
        cur["sharingAllowed"] = json!(org_sharing);
        Ok(cur)
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn save_person_learning_settings(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let org_id = actor.organization.clone();
    let key = format!("person_learning:{}:{}", org_id, actor.id);
    let b = body.clone();
    let res = run_db(&s, move |c| {
        let mut cur = load_kv(c, &key)?.unwrap_or_else(default_person_learning);
        if let Some(m) = b.get("mode").and_then(Value::as_str) {
            if matches!(m, "closed" | "open" | "choose") {
                cur["mode"] = json!(m);
            }
        }
        if let Some(a) = b.get("autoApprove") {
            if a.is_boolean() || a.is_null() {
                cur["autoApprove"] = a.clone();
            }
        }
        let org_sharing = load_kv(c, &format!("org_settings:{org_id}"))?
            .and_then(|v| v.get("skillSharing").and_then(Value::as_bool))
            .unwrap_or(false);
        cur["sharingAllowed"] = json!(org_sharing);
        save_kv(c, &key, &cur)?;
        Ok(cur)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::OK, v),
        Err(_) => internal(),
    }
}

async fn get_person_learning_review(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let org_id = actor.organization.clone();
    let user_id = actor.id.clone();
    let actor_is_admin = is_admin(&actor);
    let Ok(val) = run_db(&s, move |c| {
        let org_learning =
            load_kv(c, &format!("org_learning:{org_id}"))?.unwrap_or_else(default_org_learning);
        let personal_review = org_learning
            .pointer("/settings/personalReview")
            .and_then(Value::as_str)
            .unwrap_or("admins");
        let can_review = actor_is_admin || personal_review == "people";
        let pl = load_kv(c, &format!("person_learning:{org_id}:{user_id}"))?
            .unwrap_or_else(default_person_learning);
        let auto_approve = match pl.get("autoApprove").and_then(Value::as_bool) {
            Some(b) => json!(b),
            None if can_review => json!(false),
            None => Value::Null,
        };
        Ok(json!({
            "canReview": can_review,
            "autoApprove": auto_approve,
            "approved": 0,
            "spaces": []
        }))
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn list_person_learning_proposals(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "skills").await
}

async fn update_learned_skill(
    State(s): State<AuthState>,
    Path((org, person, _skill_name)): Path<(String, String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "open": body.get("open").and_then(Value::as_bool).unwrap_or(false) }))
}

async fn request_skill_sharing(
    State(s): State<AuthState>,
    Path((org, person, skill_name)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "requested": true, "skillName": skill_name }))
}

fn default_org_learning() -> Value {
    json!({
        "settings": {
            "enabled": false,
            "defaultTarget": Value::Null,
            "bots": {},
            "personalReview": "admins"
        },
        "automatic": Value::Null,
        "organizationSpaceId": Value::Null
    })
}

async fn get_learning_settings(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = format!("org_learning:{}", actor.organization);
    let Ok(val) = run_db(&s, move |c| Ok(load_kv(c, &key)?.unwrap_or_else(default_org_learning))).await else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn save_learning_settings(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "Only an admin can change learning settings.",
        );
    }
    let key = format!("org_learning:{}", actor.organization);
    let b = body.clone();
    let res = run_db(&s, move |c| {
        let mut cur = load_kv(c, &key)?.unwrap_or_else(default_org_learning);
        if let Some(settings) = cur.get_mut("settings").and_then(Value::as_object_mut) {
            if let Some(enabled) = b.get("enabled").and_then(Value::as_bool) {
                settings.insert("enabled".into(), json!(enabled));
            }
            if let Some(dt) = b.get("defaultTarget") {
                settings.insert("defaultTarget".into(), dt.clone());
            }
            if let Some(bots) = b.get("bots").and_then(Value::as_object) {
                settings.insert("bots".into(), Value::Object(bots.clone()));
            }
            if let Some(pr) = b.get("personalReview").and_then(Value::as_str) {
                if matches!(pr, "admins" | "people") {
                    settings.insert("personalReview".into(), json!(pr));
                }
            }
        }
        save_kv(c, &key, &cur)?;
        Ok(cur)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::OK, v),
        Err(_) => internal(),
    }
}

async fn get_learning_overview(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "configuration": "not_configured",
            "pendingThreadCount": Value::Null,
            "pendingCandidateCount": 0,
            "publishedSkillCount": Value::Null,
            "insightCount": Value::Null,
            "hasActiveRun": false,
            "latestRunStatus": Value::Null,
            "links": {
                "learning": Value::Null,
                "candidates": Value::Null,
                "runs": Value::Null
            }
        }),
    )
}

async fn list_published_skills(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "containerId": Value::Null, "skills": [], "nextCursor": Value::Null }),
    )
}

async fn list_learning_proposals(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "proposals").await
}

async fn list_learning_runs(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "runs").await
}

async fn list_personal_learning_proposals(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "people").await
}

async fn list_skill_sharing_requests(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "requests").await
}

pub(crate) fn read_skills_for_org(c: &rusqlite::Connection, org_id: &str) -> Result<Vec<Value>, StorageError> {
    let key = format!("skills:{org_id}");
    Ok(load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default())
}

async fn get_skill(
    State(s): State<AuthState>,
    Path((org, skill_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = actor.organization;
    let Ok(found) = run_db(&s, move |c| {
        Ok(read_skills_for_org(c, &org_id)?
            .into_iter()
            .find(|x| x.get("slug").and_then(Value::as_str) == Some(&skill_id)))
    })
    .await
    else {
        return internal();
    };
    match found {
        Some(v) => respond_json(StatusCode::OK, v),
        None => problem(StatusCode::NOT_FOUND, "NOT_FOUND", "Skill not found."),
    }
}

async fn replace_skill(
    State(s): State<AuthState>,
    Path((org, skill_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if skill_id.len() < 2 || skill_id.len() > 40 || !skill_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid skill slug.");
    }
    let title = body.get("title").and_then(Value::as_str).map(str::trim).unwrap_or("");
    let instructions = body.get("instructions").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if title.is_empty() || instructions.is_empty() {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "title and instructions are required.");
    }
    let summary = body.get("summary").and_then(Value::as_str).unwrap_or("").to_owned();
    let tools = body.get("tools").and_then(Value::as_array).cloned().unwrap_or_default();
    let owner_id = if body.get("forEveryone").and_then(Value::as_bool) == Some(true) && is_admin(&actor) {
        Value::Null
    } else {
        Value::String(actor.id.clone())
    };
    let skill = json!({
        "slug": skill_id,
        "title": title,
        "summary": summary,
        "instructions": instructions,
        "tools": tools,
        "ownerId": owner_id,
        "botIds": [],
        "usableOnYourBots": true
    });
    let org_id = actor.organization;
    let skill_save = skill.clone();
    if run_db(&s, move |c| {
        let mut list = read_skills_for_org(c, &org_id)?;
        list.retain(|x| x.get("slug").and_then(Value::as_str) != skill_save.get("slug").and_then(Value::as_str));
        list.push(skill_save);
        save_kv(c, &format!("skills:{org_id}"), &Value::Array(list))
    })
    .await
    .is_err()
    {
        return internal();
    }
    respond_json(StatusCode::OK, skill)
}

async fn delete_skill(
    State(s): State<AuthState>,
    Path((org, skill_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = actor.organization;
    let _ = run_db(&s, move |c| {
        let mut list = read_skills_for_org(c, &org_id)?;
        list.retain(|x| x.get("slug").and_then(Value::as_str) != Some(&skill_id));
        save_kv(c, &format!("skills:{org_id}"), &Value::Array(list))
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn get_skill_team_grants(
    State(s): State<AuthState>,
    Path((org, skill_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = format!("skill_teams:{}:{skill_id}", actor.organization);
    let Ok(val) = run_db(&s, move |c| Ok(load_kv(c, &key)?.unwrap_or_else(|| json!({ "teams": [] })))).await else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn replace_skill_team_grants(
    State(s): State<AuthState>,
    Path((org, skill_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let teams = body.get("teams").and_then(Value::as_array).cloned().unwrap_or_default();
    let val = json!({ "teams": teams });
    let key = format!("skill_teams:{}:{skill_id}", actor.organization);
    let val_save = val.clone();
    if run_db(&s, move |c| save_kv(c, &key, &val_save)).await.is_err() {
        return internal();
    }
    respond_json(StatusCode::OK, val)
}

// ---------------------------------------------------------------------------
// Per-Bot Status, Activity, Flags (Pause/Resume/Hide/Pin), Notifications
// ---------------------------------------------------------------------------

async fn verify_bot_for_actor(
    s: &AuthState,
    h: &HeaderMap,
    org: &str,
    bot_id: &str,
    write: bool,
) -> Result<Identity, Response> {
    let actor = authorize(s, h, org, write).await?;
    if !valid_non_empty_param(bot_id, 200) {
        return Err(problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid botId."));
    }
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let bot_owned = bot_id.to_owned();
    let Ok(exists) = run_db(s, move |c| ensure_bot_exists(c, &org_id, &owner_id, &bot_owned)).await else {
        return Err(internal());
    };
    if !exists {
        return Err(problem(StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found."));
    }
    Ok(actor)
}

async fn set_bot_flag(
    s: &AuthState,
    h: &HeaderMap,
    org: &str,
    bot_id: &str,
    field: &'static str,
    val: bool,
) -> Response {
    let actor = match verify_bot_for_actor(s, h, org, bot_id, true).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let key = format!("bot_flags:{}:{}:{}", actor.organization, actor.id, bot_id);
    let res = run_db(s, move |c| {
        let mut flags = load_kv(c, &key)?.unwrap_or_else(|| json!({}));
        flags[field] = json!(val);
        if field == "paused" {
            flags["pausedAt"] = if val { Value::String(now_iso(c)?) } else { Value::Null };
        }
        save_kv(c, &key, &flags)?;
        Ok(flags)
    })
    .await;
    match res {
        Ok(flags) => respond_json(
            StatusCode::OK,
            json!({
                "botId": bot_id,
                "paused": flags.get("paused").and_then(Value::as_bool).unwrap_or(false),
                "pausedAt": flags.get("pausedAt").cloned().unwrap_or(Value::Null),
                "hidden": flags.get("hidden").and_then(Value::as_bool).unwrap_or(false),
                "pinned": flags.get("pinned").and_then(Value::as_bool).unwrap_or(false)
            }),
        ),
        Err(_) => internal(),
    }
}

async fn pause_bot(State(s): State<AuthState>, Path((o, b)): Path<(String, String)>, h: HeaderMap) -> Response {
    set_bot_flag(&s, &h, &o, &b, "paused", true).await
}
async fn resume_bot(State(s): State<AuthState>, Path((o, b)): Path<(String, String)>, h: HeaderMap) -> Response {
    set_bot_flag(&s, &h, &o, &b, "paused", false).await
}
async fn hide_bot(State(s): State<AuthState>, Path((o, b)): Path<(String, String)>, h: HeaderMap) -> Response {
    set_bot_flag(&s, &h, &o, &b, "hidden", true).await
}
async fn unhide_bot(State(s): State<AuthState>, Path((o, b)): Path<(String, String)>, h: HeaderMap) -> Response {
    set_bot_flag(&s, &h, &o, &b, "hidden", false).await
}
async fn pin_bot(State(s): State<AuthState>, Path((o, b)): Path<(String, String)>, h: HeaderMap) -> Response {
    set_bot_flag(&s, &h, &o, &b, "pinned", true).await
}
async fn unpin_bot(State(s): State<AuthState>, Path((o, b)): Path<(String, String)>, h: HeaderMap) -> Response {
    set_bot_flag(&s, &h, &o, &b, "pinned", false).await
}
async fn reset_bot(State(s): State<AuthState>, Path((o, b)): Path<(String, String)>, h: HeaderMap) -> Response {
    if let Err(e) = verify_bot_for_actor(&s, &h, &o, &b, true).await {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn get_bot_learning_status(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = verify_bot_for_actor(&s, &h, &org, &bot_id, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "configured": false, "initialized": false, "stale": false }),
    )
}

async fn get_bot_handoff(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = verify_bot_for_actor(&s, &h, &org, &bot_id, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "enabled": false, "canGrant": false, "reachable": [], "grantable": false }),
    )
}

async fn get_bot_lifecycle(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match verify_bot_for_actor(&s, &h, &org, &bot_id, false).await {
        Ok(a) => a,
        Err(e) => return e,
    };
    let nkey = format!("bot_notify:{}:{}:{}", actor.organization, actor.id, bot_id);
    let fkey = format!("bot_flags:{}:{}:{}", actor.organization, actor.id, bot_id);
    let Ok((notify, paused, paused_at)) = run_db(&s, move |c| {
        let notify = load_kv(c, &nkey)?
            .and_then(|v| v.get("notify").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_else(|| "needs_input".to_owned());
        let flags = load_kv(c, &fkey)?.unwrap_or_else(|| json!({}));
        let paused = flags.get("paused").and_then(Value::as_bool).unwrap_or(false);
        let paused_at = flags.get("pausedAt").cloned().unwrap_or(Value::Null);
        Ok((notify, paused, paused_at))
    })
    .await
    else {
        return internal();
    };
    respond_json(
        StatusCode::OK,
        json!({
            "botId": bot_id,
            "paused": paused,
            "pausedAt": paused_at,
            "notify": notify
        }),
    )
}

async fn get_bot_activity(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = verify_bot_for_actor(&s, &h, &org, &bot_id, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "inProgress": [], "scheduled": [], "onDemand": [], "completed": [] }),
    )
}

async fn get_bot_shared_use(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = verify_bot_for_actor(&s, &h, &org, &bot_id, false).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "apps": [], "pending": [] }))
}

async fn list_bot_apps(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = verify_bot_for_actor(&s, &h, &org, &bot_id, false).await {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "apps": [], "nextCursor": Value::Null }))
}

async fn list_bot_memory_source_tools(
    State(s): State<AuthState>,
    Path((org, bot_id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = verify_bot_for_actor(&s, &h, &org, &bot_id, false).await {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "tools": [], "nextCursor": Value::Null }))
}

// ---------------------------------------------------------------------------
// Audit & What-If Vocabulary, Models, Notifications, Host/Devices
// ---------------------------------------------------------------------------

async fn load_actor_bots(s: &AuthState, actor: &Identity) -> Result<Vec<(String, String)>, Response> {
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    run_db(s, move |c| {
        let mut stmt = c.prepare(
            "SELECT id, name FROM port_bots WHERE organization_id=?1 AND owner_id=?2 ORDER BY created_at ASC, id ASC LIMIT 200",
        )?;
        let rows = stmt.query_map(params![org_id, owner_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    })
    .await
}

async fn get_audit_event_vocabulary(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let Ok(bots) = load_actor_bots(&s, &actor).await else {
        return internal();
    };
    let bot_items: Vec<Value> = bots.into_iter().map(|(id, name)| json!({ "id": id, "name": name })).collect();
    respond_json(
        StatusCode::OK,
        json!({
            "bots": bot_items,
            "people": [{ "id": actor.id, "name": actor.name, "email": actor.email }],
            "apps": [],
            "tools": [],
            "rules": []
        }),
    )
}

async fn export_audit_events(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn get_what_if_vocabulary(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let Ok(bots) = load_actor_bots(&s, &actor).await else {
        return internal();
    };
    let uid = actor.id.clone();
    let bot_items: Vec<Value> = bots
        .into_iter()
        .map(|(id, name)| json!({ "id": id, "name": name, "owner": uid }))
        .collect();
    respond_json(
        StatusCode::OK,
        json!({
            "bots": bot_items,
            "people": [{ "id": actor.id, "name": actor.name, "email": actor.email }],
            "groups": [],
            "teams": [],
            "apps": []
        }),
    )
}

async fn get_model_key(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "provider": "openai", "keyId": "ps5lm", "set": true }),
    )
}

fn normalize_thinking_modes(raw: Option<&Vec<Value>>) -> Vec<String> {
    let mut modes = Vec::new();
    if let Some(arr) = raw {
        for item in arr {
            if let Some(s) = item.as_str() {
                let norm = match s.trim().to_ascii_lowercase().as_str() {
                    "off" => "off",
                    "none" => "none",
                    "minimal" => "minimal",
                    "low" => "low",
                    "medium" => "medium",
                    "high" => "high",
                    "xhigh" | "extra_high" | "extra-high" => "xhigh",
                    "max" => "max",
                    _ => continue,
                };
                if !modes.iter().any(|m: &String| m == norm) {
                    modes.push(norm.to_owned());
                }
            }
        }
    }
    if modes.is_empty() {
        modes = vec![
            "off".to_owned(),
            "low".to_owned(),
            "medium".to_owned(),
            "high".to_owned(),
        ];
    }
    modes
}

fn read_ps5lm_preset(model_id: &str) -> Option<(Option<String>, Vec<String>, Option<String>)> {
    let models_dir = std::env::var("OPENBOT_PS5LM_MODELS_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/data/PS5LM/models".to_owned());
    let base = std::path::Path::new(model_id)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(model_id);
    if base.is_empty() || base.contains("..") || base.contains(['/', '\\', '\0']) {
        return None;
    }
    let preset_path = std::path::Path::new(&models_dir).join(format!("{base}.preset.json"));
    let raw = std::fs::read_to_string(&preset_path).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    let label = val
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let efforts = normalize_thinking_modes(val.get("thinking_modes").and_then(Value::as_array));
    let default_effort = val
        .get("default_reasoning_effort")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && efforts.iter().any(|e| e == s));
    Some((label, efforts, default_effort))
}

async fn fetch_live_ps5lm_catalogue() -> (String, Vec<Value>) {
    let base_url = std::env::var("OPENBOT_MODEL_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            if cfg!(target_vendor = "sie") {
                Some("http://127.0.0.1:8081/v1".to_owned())
            } else {
                None
            }
        });
    let Some(base_url) = base_url else {
        return (
            "auto".to_owned(),
            vec![json!({
                "id": "auto",
                "label": "PS5LM Auto",
                "efforts": ["off", "low", "medium", "high"],
                "defaultEffort": "medium"
            })],
        );
    };
    let url = format!("{}/models", base_url.trim_end_matches('/'));
    if let Ok(client) = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_millis(1200))
        .timeout(std::time::Duration::from_millis(2500))
        .no_proxy()
        .build()
    {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes().await {
                    if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(arr) = val.get("data").and_then(Value::as_array) {
                            let mut models = Vec::new();
                            for entry in arr {
                                let Some(id) = entry
                                    .get("id")
                                    .and_then(Value::as_str)
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                else {
                                    continue;
                                };
                                let preset = read_ps5lm_preset(id);
                                let pretty_name = preset
                                    .as_ref()
                                    .and_then(|(lbl, _, _)| lbl.clone())
                                    .unwrap_or_else(|| {
                                        let base = std::path::Path::new(id)
                                            .file_name()
                                            .and_then(|s| s.to_str())
                                            .unwrap_or(id);
                                        base.strip_suffix(".gguf").unwrap_or(base).to_owned()
                                    });
                                let efforts = preset
                                    .as_ref()
                                    .map(|(_, e, _)| e.clone())
                                    .unwrap_or_else(|| {
                                        vec![
                                            "off".to_owned(),
                                            "low".to_owned(),
                                            "medium".to_owned(),
                                            "high".to_owned(),
                                            "xhigh".to_owned(),
                                        ]
                                    });
                                let default_eff = preset
                                    .as_ref()
                                    .and_then(|(_, _, d)| d.clone())
                                    .unwrap_or_else(|| {
                                        if efforts.iter().any(|e| e == "medium") {
                                            "medium".to_owned()
                                        } else {
                                            efforts[0].clone()
                                        }
                                    });
                                models.push(json!({
                                    "id": id,
                                    "label": pretty_name,
                                    "efforts": efforts,
                                    "defaultEffort": default_eff
                                }));
                            }
                            if !models.is_empty() {
                                let default_id = models[0]["id"]
                                    .as_str()
                                    .unwrap_or("auto")
                                    .to_owned();
                                return (default_id, models);
                            }
                        }
                    }
                }
            }
        }
    }
    (
        "auto".to_owned(),
        vec![json!({
            "id": "auto",
            "label": "PS5LM (No model loaded / Offline)",
            "efforts": ["off", "low", "medium", "high"],
            "defaultEffort": "medium"
        })],
    )
}

async fn get_model_catalogue(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    let (default_id, models) = fetch_live_ps5lm_catalogue().await;
    let mut r = respond_json(
        StatusCode::OK,
        json!({
            "provider": "openai",
            "source": "gateway",
            "exposure": "all",
            "default": default_id,
            "models": models,
            "choosable": true,
            "listed": true
        }),
    );
    r.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    r
}

async fn get_model_usage(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "days": 30, "summary": [], "recent": [] }),
    )
}

async fn get_model_choice(
    State(s): State<AuthState>,
    Path((org, person, conversation_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("model_choice:{}:{}:{}", actor.organization, actor.id, conversation_id);
    let Ok(val) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.unwrap_or_else(|| json!({ "model": Value::Null, "effort": Value::Null })))
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn save_model_choice(
    State(s): State<AuthState>,
    Path((org, person, conversation_id)): Path<(String, String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("model_choice:{}:{}:{}", actor.organization, actor.id, conversation_id);
    let b = body.clone();
    let res = run_db(&s, move |c| {
        let mut cur = load_kv(c, &key)?.unwrap_or_else(|| json!({ "model": Value::Null, "effort": Value::Null }));
        if let Some(m) = b.get("model") {
            cur["model"] = m.clone();
        }
        if let Some(e) = b.get("effort") {
            cur["effort"] = e.clone();
        }
        save_kv(c, &key, &cur)?;
        Ok(cur)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::OK, v),
        Err(_) => internal(),
    }
}

fn default_notification_settings() -> Value {
    json!({
        "routing": {
            "progress": "all",
            "decision": "all",
            "question": "all",
            "attention": "all"
        }
    })
}

async fn get_notification_settings(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("notify_settings:{}:{}", actor.organization, actor.id);
    let Ok(val) = run_db(&s, move |c| Ok(load_kv(c, &key)?.unwrap_or_else(default_notification_settings))).await else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn save_notification_settings(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let Some(routing_patch) = body.get("routing").and_then(Value::as_object) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "routing object is required.");
    };
    let key = format!("notify_settings:{}:{}", actor.organization, actor.id);
    let rp = routing_patch.clone();
    let res = run_db(&s, move |c| {
        let mut cur = load_kv(c, &key)?.unwrap_or_else(default_notification_settings);
        if let Some(routing) = cur.get_mut("routing").and_then(Value::as_object_mut) {
            for k in ["progress", "decision", "question", "attention"] {
                if let Some(v) = rp.get(k) {
                    routing.insert(k.into(), v.clone());
                }
            }
        }
        save_kv(c, &key, &cur)?;
        Ok(cur)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::OK, v),
        Err(_) => internal(),
    }
}

async fn get_bot_notification_settings(
    State(s): State<AuthState>,
    Path((org, person, bot_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("bot_notify:{}:{}:{}", actor.organization, actor.id, bot_id);
    let Ok(val) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?
            .unwrap_or_else(|| json!({ "botId": bot_id, "notify": "needs_input" })))
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn save_bot_notification_settings(
    State(s): State<AuthState>,
    Path((org, person, bot_id)): Path<(String, String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let notify = match body.get("notify").and_then(Value::as_str) {
        Some(v @ ("all" | "needs_input" | "none")) => v,
        _ => return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid notify level."),
    };
    let val = json!({ "botId": bot_id, "notify": notify });
    let key = format!("bot_notify:{}:{}:{}", actor.organization, actor.id, bot_id);
    let val_save = val.clone();
    if run_db(&s, move |c| save_kv(c, &key, &val_save)).await.is_err() {
        return internal();
    }
    respond_json(StatusCode::OK, val)
}

async fn get_host_access(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "connected": false, "desktop": false, "grants": [], "pending": [] }),
    )
}

async fn register_device(
    State(s): State<AuthState>,
    Path((org, person, device_id)): Path<(String, String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let platform = body.get("platform").and_then(Value::as_str).unwrap_or("ios").to_owned();
    let key = format!("devices:{}:{}", actor.organization, actor.id);
    let res = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&device_id));
        let item = json!({ "id": device_id, "platform": platform, "createdAt": now_iso(c)? });
        list.push(item.clone());
        save_kv(c, &key, &Value::Array(list))?;
        Ok(item)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::OK, v),
        Err(_) => internal(),
    }
}

async fn delete_device(
    State(s): State<AuthState>,
    Path((org, person, device_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("devices:{}:{}", actor.organization, actor.id);
    let _ = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&device_id));
        save_kv(c, &key, &Value::Array(list))
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// API Keys, Sessions, Memories, Memory Sources
// ---------------------------------------------------------------------------

async fn list_api_keys(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let key = format!("api_keys:{}:{}", actor.organization, actor.id);
    let Ok(items) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default())
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, json!({ "apiKeys": items, "nextCursor": Value::Null }))
}

async fn create_api_key(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let name = body.get("name").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if name.is_empty() || name.chars().count() > 32 {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid API key name.");
    }
    let key_store = format!("api_keys:{}:{}", actor.organization, actor.id);
    let name_own = name.to_owned();
    let expires_days = body.get("expiresInDays").and_then(Value::as_i64);
    let res = run_db(&s, move |c| {
        let id = format!("key_{}", random_hex(12)?);
        let secret = format!("obk_{}", random_hex(24)?);
        let start = secret.chars().take(8).collect::<String>();
        let now = epoch()?;
        let created_at = format_iso_utc(c, Some(now))?.unwrap_or_else(|| "2026-01-01T00:00:00Z".into());
        let expires_at = match expires_days.filter(|d| (1..=365).contains(d)) {
            Some(d) => Value::String(format_iso_utc(c, Some(now + d * 86_400))?.unwrap_or(created_at.clone())),
            None => Value::Null,
        };
        let entry = json!({
            "id": id,
            "name": name_own,
            "start": start,
            "createdAt": created_at,
            "expiresAt": expires_at,
            "lastUsedAt": Value::Null
        });
        let mut list = load_kv(c, &key_store)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.insert(0, entry.clone());
        save_kv(c, &key_store, &Value::Array(list))?;
        Ok(json!({ "apiKey": entry, "key": secret }))
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::CREATED, v),
        Err(_) => internal(),
    }
}

async fn delete_api_key(
    State(s): State<AuthState>,
    Path((org, person, key_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key_store = format!("api_keys:{}:{}", actor.organization, actor.id);
    let _ = run_db(&s, move |c| {
        let mut list = load_kv(c, &key_store)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&key_id));
        save_kv(c, &key_store, &Value::Array(list))
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn list_person_sessions(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let uid = actor.id;
    let Ok(sessions) = run_db(&s, move |c| {
        let now = epoch()?;
        let mut stmt = c.prepare(
            "SELECT last_seen_at, expires_at FROM auth_sessions WHERE user_id=?1 AND expires_at>?2 ORDER BY last_seen_at DESC LIMIT 20",
        )?;
        let rows = stmt.query_map(params![uid, now], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = Vec::new();
        for (idx, row) in rows.enumerate() {
            let (last_seen, expires) = row?;
            out.push(json!({
                "id": format!("sess_{idx}"),
                "createdAt": format_iso_utc(c, Some(last_seen))?.unwrap_or_else(|| "2026-01-01T00:00:00Z".into()),
                "lastActiveAt": format_iso_utc(c, Some(last_seen))?.unwrap_or_else(|| "2026-01-01T00:00:00Z".into()),
                "expiresAt": format_iso_utc(c, Some(expires))?.unwrap_or_else(|| "2026-01-01T00:00:00Z".into()),
                "ipAddress": Value::Null,
                "userAgent": Value::Null,
                "current": idx == 0
            }));
        }
        Ok(out)
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, json!({ "sessions": sessions, "nextCursor": Value::Null }))
}

async fn delete_person_session(
    State(s): State<AuthState>,
    Path((org, person, _sid)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn list_memories(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let key = format!("memories:{}:{}", actor.organization, actor.id);
    let Ok(items) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default())
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, json!({ "memories": items, "nextCursor": Value::Null }))
}

async fn create_memory(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let content = body.get("content").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if content.is_empty() || content.chars().count() > 6000 {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid memory content.");
    }
    let provenance = body.get("provenance").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).unwrap_or("You").to_owned();
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let c_own = content.to_owned();
    let key = format!("memories:{}:{}", actor.organization, actor.id);
    let res = run_db(&s, move |c| {
        let now = now_iso(c)?;
        let item = json!({
            "id": format!("mem_{}", random_hex(12)?),
            "content": c_own,
            "provenance": provenance,
            "sourceId": Value::Null,
            "enabled": enabled,
            "reviewState": "confirmed",
            "formedBy": "person",
            "formedByBotId": Value::Null,
            "sourceApp": Value::Null,
            "sourceLink": Value::Null,
            "observedAt": now,
            "createdAt": now,
            "updatedAt": now
        });
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.insert(0, item.clone());
        save_kv(c, &key, &Value::Array(list))?;
        Ok(item)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::CREATED, v),
        Err(_) => internal(),
    }
}

async fn update_memory(
    State(s): State<AuthState>,
    Path((org, person, memory_id)): Path<(String, String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("memories:{}:{}", actor.organization, actor.id);
    let b = body.clone();
    let res = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let Some(item) = list.iter_mut().find(|x| x.get("id").and_then(Value::as_str) == Some(&memory_id)) else {
            return Ok(None);
        };
        if let Some(content) = b.get("content").and_then(Value::as_str).map(str::trim) {
            if !content.is_empty() {
                item["content"] = json!(content);
            }
        }
        if let Some(enabled) = b.get("enabled").and_then(Value::as_bool) {
            item["enabled"] = json!(enabled);
        }
        if let Some(rs) = b.get("reviewState").and_then(Value::as_str) {
            item["reviewState"] = json!(rs);
        }
        item["updatedAt"] = Value::String(now_iso(c)?);
        let out = item.clone();
        save_kv(c, &key, &Value::Array(list))?;
        Ok(Some(out))
    })
    .await;
    match res {
        Ok(Some(v)) => respond_json(StatusCode::OK, v),
        Ok(None) => problem(StatusCode::NOT_FOUND, "NOT_FOUND", "Memory not found."),
        Err(_) => internal(),
    }
}

async fn delete_memory(
    State(s): State<AuthState>,
    Path((org, person, memory_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("memories:{}:{}", actor.organization, actor.id);
    let _ = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&memory_id));
        save_kv(c, &key, &Value::Array(list))
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn list_memory_sources(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let key = format!("memory_sources:{}:{}", actor.organization, actor.id);
    let Ok(items) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default())
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, json!({ "sources": items, "nextCursor": Value::Null }))
}

async fn create_memory_source(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let bot_id = body.get("botId").and_then(Value::as_str).unwrap_or("").to_owned();
    let tool_ref = body.get("toolRef").and_then(Value::as_str).unwrap_or("").to_owned();
    let title = body.get("title").and_then(Value::as_str).unwrap_or("").to_owned();
    let args = body.get("args").cloned().unwrap_or_else(|| json!({}));
    let key = format!("memory_sources:{}:{}", actor.organization, actor.id);
    let res = run_db(&s, move |c| {
        let now = now_iso(c)?;
        let src = json!({
            "id": format!("msrc_{}", random_hex(12)?),
            "botId": bot_id,
            "toolRef": tool_ref,
            "title": title,
            "args": args,
            "enabled": true,
            "syncStatus": "idle",
            "syncError": Value::Null,
            "lastSyncAt": Value::Null,
            "nextSyncAt": now,
            "createdAt": now,
            "updatedAt": now
        });
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.insert(0, src.clone());
        save_kv(c, &key, &Value::Array(list))?;
        Ok(json!({ "imported": 0, "source": src }))
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::CREATED, v),
        Err(_) => internal(),
    }
}

async fn update_memory_source(
    State(s): State<AuthState>,
    Path((org, person, source_id)): Path<(String, String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("memory_sources:{}:{}", actor.organization, actor.id);
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let res = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let Some(item) = list.iter_mut().find(|x| x.get("id").and_then(Value::as_str) == Some(&source_id)) else {
            return Ok(None);
        };
        item["enabled"] = json!(enabled);
        item["updatedAt"] = Value::String(now_iso(c)?);
        let out = item.clone();
        save_kv(c, &key, &Value::Array(list))?;
        Ok(Some(out))
    })
    .await;
    match res {
        Ok(Some(v)) => respond_json(StatusCode::OK, v),
        Ok(None) => problem(StatusCode::NOT_FOUND, "NOT_FOUND", "Memory source not found."),
        Err(_) => internal(),
    }
}

async fn delete_memory_source(
    State(s): State<AuthState>,
    Path((org, person, source_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("memory_sources:{}:{}", actor.organization, actor.id);
    let _ = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&source_id));
        save_kv(c, &key, &Value::Array(list))
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn sync_memory_source(
    State(s): State<AuthState>,
    Path((org, person, source_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    let key = format!("memory_sources:{}:{}", actor.organization, actor.id);
    let res = run_db(&s, move |c| {
        let list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        Ok(list.into_iter().find(|x| x.get("id").and_then(Value::as_str) == Some(&source_id)))
    })
    .await;
    match res {
        Ok(Some(src)) => respond_json(StatusCode::OK, json!({ "imported": 0, "source": src })),
        _ => problem(StatusCode::NOT_FOUND, "NOT_FOUND", "Memory source not found."),
    }
}

// ---------------------------------------------------------------------------
// Remaining Endpoints (Network Policies, Reviewer Guidance, Teams, Misc)
// ---------------------------------------------------------------------------

async fn list_devices(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let key = format!("devices:{}:{}", actor.organization, actor.id);
    let Ok(items) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default())
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, json!({ "devices": items, "nextCursor": Value::Null }))
}

async fn list_linked_accounts(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "linkedAccounts").await
}

async fn list_linked_account_providers(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "linkedAccountProviders").await
}

async fn list_connections(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "connections").await
}

async fn list_giveable_apps(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "apps").await
}

async fn list_destinations(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "destinations").await
}

async fn list_deliveries(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "deliveries").await
}

async fn list_sign_in_requests(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_person_page(&s, &h, &org, &person, &q, "signInRequests").await
}

async fn list_saved_logins(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "savedLogins": [], "passwordManager": false, "nextCursor": Value::Null }),
    )
}

async fn clear_team_bot_consents(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = require_person(&actor, &person) {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn route_conversation_message(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let text = body.get("text").and_then(Value::as_str).unwrap_or("").to_owned();
    let explicit_bot = body.get("botId").and_then(Value::as_str).map(str::to_owned);
    let Ok(bots) = load_actor_bots(&s, &actor).await else {
        return internal();
    };
    if bots.is_empty() {
        return problem(StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "No bots available.");
    }
    if let Some(target) = explicit_bot {
        if let Some((id, name)) = bots.iter().find(|(id, _)| id == &target) {
            return respond_json(
                StatusCode::OK,
                json!({
                    "botId": id,
                    "name": name,
                    "reason": "Selected mentioned Bot.",
                    "fallback": false,
                    "viaMention": true
                }),
            );
        }
    }
    let lower = text.to_ascii_lowercase();
    if let Some((id, name)) = bots.iter().find(|(_, name)| lower.contains(&name.to_ascii_lowercase())) {
        return respond_json(
            StatusCode::OK,
            json!({
                "botId": id,
                "name": name,
                "reason": format!("Matched Bot '{name}' from message."),
                "fallback": false,
                "viaMention": false
            }),
        );
    }
    let (id, name) = &bots[0];
    respond_json(
        StatusCode::OK,
        json!({
            "botId": id,
            "name": name,
            "reason": "Default Bot.",
            "fallback": true,
            "viaMention": false
        }),
    )
}

async fn list_conversation_members(
    State(s): State<AuthState>,
    Path((org, conversation_id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let conv_id = conversation_id;
    let Ok(bot_rows) = run_db(&s, move |c| {
        let raw_bots: Option<String> = c
            .query_row(
                "SELECT bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",
                params![conv_id, org_id, owner_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(raw) = raw_bots else {
            return Ok(None);
        };
        let bot_ids: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
        let mut bots_out = Vec::new();
        for bid in bot_ids {
            let bname: Option<String> = c
                .query_row(
                    "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                    params![bid, org_id, owner_id],
                    |r| r.get(0),
                )
                .optional()?;
            bots_out.push((bid, bname));
        }
        Ok(Some(bots_out))
    })
    .await
    else {
        return internal();
    };
    let Some(bots_out) = bot_rows else {
        return problem(StatusCode::NOT_FOUND, "CONVERSATION_NOT_FOUND", "Conversation not found.");
    };
    let mut members = Vec::new();
    for (bid, bname) in bots_out {
        members.push(json!({
            "kind": "bot",
            "id": bid,
            "name": bname
        }));
    }
    members.push(json!({
        "kind": "person",
        "id": actor.id,
        "name": actor.name,
        "email": actor.email,
        "creator": true
    }));
    respond_json(
        StatusCode::OK,
        json!({
            "members": members,
            "nextCursor": Value::Null
        }),
    )
}

async fn add_conversation_member(
    State(s): State<AuthState>,
    Path((org, conversation_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let bot_id = body
        .get("botId")
        .or_else(|| body.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if bot_id.is_empty() {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "botId is required.");
    }
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let conv_id = conversation_id;
    let res = run_db(&s, move |c| {
        let raw_bots: Option<String> = c
            .query_row(
                "SELECT bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",
                params![conv_id, org_id, owner_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(raw) = raw_bots else {
            return Ok(None);
        };
        let bname: Option<String> = c
            .query_row(
                "SELECT name FROM port_bots WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![bot_id, org_id, owner_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(name) = bname else {
            return Ok(Some(json!({ "missing": true })));
        };
        let mut bot_ids: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
        if !bot_ids.contains(&bot_id) {
            bot_ids.push(bot_id.clone());
            let next = serde_json::to_string(&bot_ids).unwrap_or_else(|_| "[]".into());
            c.execute(
                "UPDATE port_conversations SET bot_ids_json=?1 WHERE id=?2",
                params![next, conv_id],
            )?;
        }
        Ok(Some(json!({ "member": { "kind": "bot", "id": bot_id, "name": name } })))
    })
    .await;
    match res {
        Ok(Some(v)) if v.get("missing").is_some() => {
            problem(StatusCode::NOT_FOUND, "BOT_NOT_FOUND", "Bot not found.")
        }
        Ok(Some(v)) => respond_json(StatusCode::CREATED, v),
        Ok(None) => problem(StatusCode::NOT_FOUND, "CONVERSATION_NOT_FOUND", "Conversation not found."),
        Err(_) => internal(),
    }
}

async fn remove_conversation_member(
    State(s): State<AuthState>,
    Path((org, conversation_id, member_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let conv_id = conversation_id;
    let _ = run_db(&s, move |c| {
        let raw_bots: Option<String> = c
            .query_row(
                "SELECT bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",
                params![conv_id, org_id, owner_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(raw) = raw_bots {
            let mut bot_ids: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
            bot_ids.retain(|x| x != &member_id);
            if !bot_ids.is_empty() {
                let next = serde_json::to_string(&bot_ids).unwrap_or_else(|_| "[]".into());
                c.execute(
                    "UPDATE port_conversations SET bot_ids_json=?1 WHERE id=?2",
                    params![next, conv_id],
                )?;
            }
        }
        Ok(())
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn list_voice_sessions(
    State(s): State<AuthState>,
    Path((org, _conv)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "sessions").await
}

async fn get_voice_configuration(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "transport": "websocket" }))
}

async fn list_reactions(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "reactions").await
}

async fn list_check_ins(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let org_id = actor.organization.clone();
    let role = actor.role.clone();
    let Ok(allowed) = run_db(&s, move |c| cap_allowed_for_actor(c, &org_id, &role, "proactive")).await
    else {
        return internal();
    };
    respond_json(
        StatusCode::OK,
        json!({ "checkIns": [], "allowed": allowed, "nextCursor": Value::Null }),
    )
}

async fn list_check_in_items(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "checkInItems").await
}

async fn get_check_in_usage(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "days": 30,
            "dailyRuns": 0,
            "bots": [],
            "pings": { "sent": 0, "itemsPerPing": Value::Null }
        }),
    )
}

async fn list_goals(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "goals").await
}

async fn list_tasks(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "tasks").await
}

async fn list_app_directory(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "entries").await
}

async fn list_credentials(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "credentials").await
}

async fn list_identity_providers(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "identityProviders").await
}

async fn list_network_policies(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let key = format!("network_policies:{}", actor.organization);
    let Ok(items) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default())
    })
    .await
    else {
        return internal();
    };
    respond_json(StatusCode::OK, json!({ "networkPolicies": items, "nextCursor": Value::Null }))
}

async fn replace_network_policy(
    State(s): State<AuthState>,
    Path((org, policy_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let (scope_kind, scope_id) = if policy_id == "organization" {
        ("organization", "")
    } else if let Some(rest) = policy_id.strip_prefix("team:") {
        ("team", rest)
    } else if let Some(rest) = policy_id.strip_prefix("group:") {
        ("group", rest)
    } else {
        ("organization", "")
    };
    let mode = body.get("mode").and_then(Value::as_str).unwrap_or("allow_all").to_owned();
    let rules = body.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
    let locked = body.get("locked").and_then(Value::as_bool).unwrap_or(false);
    let email = actor.email.clone();
    let pid = policy_id.clone();
    let sk = scope_kind.to_owned();
    let si = scope_id.to_owned();
    let key = format!("network_policies:{}", actor.organization);
    let res = run_db(&s, move |c| {
        let entry = json!({
            "id": pid,
            "scopeKind": sk,
            "scopeId": si,
            "mode": mode,
            "rules": rules,
            "locked": locked,
            "updatedBy": email,
            "updatedAt": now_iso(c)?
        });
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.retain(|x| x.get("id").and_then(Value::as_str) != entry.get("id").and_then(Value::as_str));
        list.push(entry.clone());
        save_kv(c, &key, &Value::Array(list))?;
        Ok(entry)
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::OK, v),
        Err(_) => internal(),
    }
}

async fn delete_network_policy(
    State(s): State<AuthState>,
    Path((org, policy_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let key = format!("network_policies:{}", actor.organization);
    let _ = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.retain(|x| x.get("id").and_then(Value::as_str) != Some(&policy_id));
        save_kv(c, &key, &Value::Array(list))
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn translate_network_policy(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "mode": "allow_all", "rules": [] }))
}

async fn replay_network_policy(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "scanned": 0,
            "covered": 0,
            "wouldBlock": 0,
            "wouldAllow": 0,
            "undecided": 0,
            "unchanged": 0,
            "hosts": [],
            "sites": 0
        }),
    )
}

async fn list_computers(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({
            "computers": [{
                "id": "ps5-shared",
                "computer": format!("person:{}", actor.id),
                "kind": "person",
                "personId": actor.id,
                "person": { "name": actor.name, "email": actor.email },
                "running": true,
                "startedAt": "2026-01-01T00:00:00Z"
            }],
            "isolation": "shared",
            "nextCursor": Value::Null
        }),
    )
}

async fn stop_computers_noop(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "stopped": 0 }))
}

async fn get_computer_page_frame(
    State(s): State<AuthState>,
    Path((org, _bot_id, _tool_call_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "frame": Value::Null }))
}

async fn list_computer_actions(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "computerActions").await
}

async fn list_teams(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if let Err(e) = parse_empty_list_paging(&q) {
        return e;
    }
    let key = format!("teams:{}", actor.organization);
    let Ok(items) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default())
    })
    .await
    else {
        return internal();
    };
    respond_json(
        StatusCode::OK,
        json!({ "teams": items, "canCreate": is_admin(&actor), "nextCursor": Value::Null }),
    )
}

async fn create_team(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let name = body.get("name").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if name.is_empty() || name.chars().count() > 100 {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid team name.");
    }
    let desc = body.get("description").and_then(Value::as_str).map(|s| Value::String(s.to_owned())).unwrap_or(Value::Null);
    let parent = body.get("parentTeamId").cloned().unwrap_or(Value::Null);
    let name_own = name.to_owned();
    let key = format!("teams:{}", actor.organization);
    let res = run_db(&s, move |c| {
        let team = json!({
            "id": format!("team_{}", random_hex(12)?),
            "name": name_own,
            "description": desc,
            "parentTeamId": parent,
            "source": "openbot",
            "memberCount": 0,
            "role": Value::Null,
            "canManage": true,
            "canMove": true,
            "canDelete": true,
            "createdAt": now_iso(c)?
        });
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.push(team.clone());
        save_kv(c, &key, &Value::Array(list))?;
        Ok(json!({ "team": team }))
    })
    .await;
    match res {
        Ok(v) => respond_json(StatusCode::CREATED, v),
        Err(_) => internal(),
    }
}

async fn get_team(
    State(s): State<AuthState>,
    Path((org, team_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = format!("teams:{}", actor.organization);
    let Ok(found) = run_db(&s, move |c| {
        Ok(load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default()
            .into_iter().find(|t| t.get("id").and_then(Value::as_str) == Some(&team_id)))
    })
    .await
    else {
        return internal();
    };
    match found {
        Some(team) => respond_json(StatusCode::OK, json!({ "team": team })),
        None => problem(StatusCode::NOT_FOUND, "NOT_FOUND", "Team not found."),
    }
}

async fn update_team(
    State(s): State<AuthState>,
    Path((org, team_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let key = format!("teams:{}", actor.organization);
    let b = body.clone();
    let res = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let Some(team) = list.iter_mut().find(|t| t.get("id").and_then(Value::as_str) == Some(&team_id)) else {
            return Ok(None);
        };
        if let Some(n) = b.get("name").and_then(Value::as_str).map(str::trim) {
            if !n.is_empty() {
                team["name"] = json!(n);
            }
        }
        if let Some(d) = b.get("description") {
            team["description"] = d.clone();
        }
        if let Some(p) = b.get("parentTeamId") {
            team["parentTeamId"] = p.clone();
        }
        let out = team.clone();
        save_kv(c, &key, &Value::Array(list))?;
        Ok(Some(json!({ "team": out })))
    })
    .await;
    match res {
        Ok(Some(v)) => respond_json(StatusCode::OK, v),
        Ok(None) => problem(StatusCode::NOT_FOUND, "NOT_FOUND", "Team not found."),
        Err(_) => internal(),
    }
}

async fn delete_team(
    State(s): State<AuthState>,
    Path((org, team_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let key = format!("teams:{}", actor.organization);
    let _ = run_db(&s, move |c| {
        let mut list = load_kv(c, &key)?.and_then(|v| v.as_array().cloned()).unwrap_or_default();
        list.retain(|t| t.get("id").and_then(Value::as_str) != Some(&team_id));
        save_kv(c, &key, &Value::Array(list))
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn list_team_members(
    State(s): State<AuthState>,
    Path((org, _team_id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "members").await
}

async fn put_team_member(
    State(s): State<AuthState>,
    Path((org, _team_id, _member_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    respond_json(
        StatusCode::OK,
        json!({
            "member": {
                "id": actor.id,
                "email": actor.email,
                "name": actor.name,
                "image": Value::Null,
                "role": "member",
                "isCaller": true,
                "joinedAt": "2026-01-01T00:00:00Z"
            }
        }),
    )
}

async fn remove_team_member(
    State(s): State<AuthState>,
    Path((org, _team_id, _member_id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn signal_conversation_busy(
    State(s): State<AuthState>,
    Path((org, conversation_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let busy = body.get("busy").and_then(Value::as_bool).unwrap_or(false);
    crate::realtime::notify_channel_activity(
        &actor.organization,
        &actor.id,
        json!({ "channelId": conversation_id, "busy": busy }),
    );
    StatusCode::NO_CONTENT.into_response()
}

async fn record_conversation_activity(
    State(s): State<AuthState>,
    Path((org, conversation_id)): Path<(String, String)>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let text = body.get("text").and_then(Value::as_str).unwrap_or("");
    let bot_id = body.get("botId").cloned().unwrap_or(Value::Null);
    let at = body
        .get("at")
        .and_then(Value::as_str)
        .unwrap_or("2026-01-01T00:00:00Z");
    crate::realtime::notify_channel_activity(
        &actor.organization,
        &actor.id,
        json!({
            "channelId": conversation_id,
            "lastMessage": text,
            "lastMessageAt": at,
            "lastMessageAgentId": bot_id,
        }),
    );
    StatusCode::NO_CONTENT.into_response()
}

async fn mark_conversation_read(
    State(s): State<AuthState>,
    Path((org, conversation_id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = actor.organization;
    let owner_id = actor.id;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let _ = run_db(&s, move |c| {
        c.execute(
            "UPDATE port_conversations SET last_read_at=MAX(COALESCE(last_read_at,0),?4) WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
            params![conversation_id, org_id, owner_id, ts],
        )?;
        Ok(())
    })
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn list_team_bots(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "teamBots").await
}

async fn list_github_event_sources(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    empty_org_page(&s, &h, &org, &q, "githubEventSources").await
}

async fn get_reviewer_guidance(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let key = format!("reviewer_guidance:{}", actor.organization);
    let Ok(val) = run_db(&s, move |c| Ok(load_kv(c, &key)?.unwrap_or_else(|| json!({ "guidance": Value::Null })))).await else {
        return internal();
    };
    respond_json(StatusCode::OK, val)
}

async fn replace_reviewer_guidance(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let text = body.get("text").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if text.is_empty() || text.chars().count() > 2000 {
        return problem(StatusCode::BAD_REQUEST, "INVALID_REQUEST", "Invalid guidance text.");
    }
    let key = format!("reviewer_guidance:{}", actor.organization);
    let t_own = text.to_owned();
    if run_db(&s, move |c| save_kv(c, &key, &json!({ "guidance": t_own }))).await.is_err() {
        return internal();
    }
    respond_json(
        StatusCode::OK,
        json!({
            "guidance": text,
            "summary": Value::Null,
            "explanation": "Saved reviewer guidance.",
            "check": { "ok": true }
        }),
    )
}

async fn delete_reviewer_guidance(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !is_admin(&actor) {
        return problem(StatusCode::FORBIDDEN, "PERMISSION_DENIED", "Admin required.");
    }
    let key = format!("reviewer_guidance:{}", actor.organization);
    let _ = run_db(&s, move |c| save_kv(c, &key, &json!({ "guidance": Value::Null }))).await;
    StatusCode::NO_CONTENT.into_response()
}

async fn check_reviewer_guidance(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "ok": true, "summary": Value::Null, "explanation": "Guidance check passed." }),
    )
}

async fn replay_reviewer_guidance(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, true).await {
        return e;
    }
    respond_json(
        StatusCode::OK,
        json!({ "calls": 0, "skippedSafety": 0, "changed": 0, "examples": [] }),
    )
}

async fn get_reviewer_guidance_replay(
    State(s): State<AuthState>,
    Path(org): Path<String>,
    h: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &h, &org, false).await {
        return e;
    }
    respond_json(StatusCode::OK, json!({ "calls": 0, "skippedSafety": 0 }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use axum::{body::{to_bytes, Body}, http::Request};
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn read_json(res: Response) -> Value {
        let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn post_or_patch(method: &str, uri: &str, cookie: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "example.test")
            .header("origin", "http://example.test")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    #[tokio::test]
    async fn settings_and_preferences_saves_persist_and_merge() {
        let mut rand = [0u8; 8];
        getrandom::getrandom(&mut rand).unwrap();
        let path = std::env::temp_dir().join(format!("openbot-extra-{:x}.db", u64::from_le_bytes(rand)));
        let db = Arc::new(Storage::open(&path).unwrap());
        let state = AuthState::new(db.clone(), "http://example.test", Some("0123456789abcdef0123456789abcdef")).unwrap();
        let app = crate::local_auth::router(state.clone())
            .merge(crate::bots::router(state.clone()))
            .merge(crate::compat_routes::router(state));

        let setup = app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/port/auth/setup")
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"a long secure password"}"#))
                .unwrap(),
        ).await.unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);
        let cookie = setup.headers()[axum::http::header::SET_COOKIE]
            .to_str().unwrap().split(';').next().unwrap().to_owned();

        let orgs = app.clone().oneshot(
            Request::builder().uri("/api/v2/people/me/organizations").header("cookie", &cookie).body(Body::empty()).unwrap()
        ).await.unwrap();
        let org_id = read_json(orgs).await["organizations"][0]["id"].as_str().unwrap().to_owned();

        // 1. Profile name update persists in SQLite & reflects on /people/me
        let upd_person = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/people/me"), &cookie, r#"{"name":"Renamed Owner"}"#)).await.unwrap();
        assert_eq!(upd_person.status(), StatusCode::OK);
        assert_eq!(read_json(upd_person).await["person"]["name"], "Renamed Owner");
        let me = app.clone().oneshot(Request::builder().uri(&format!("/api/v2/organizations/{org_id}/people/me")).header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(read_json(me).await["person"]["name"], "Renamed Owner");

        // 2. Partial PATCH approval-preferences preserves sibling fields
        let ap1 = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/people/me/approval-preferences"), &cookie, r#"{"autoReview":true}"#)).await.unwrap();
        assert_eq!(ap1.status(), StatusCode::OK);
        let ap1_j = read_json(ap1).await;
        assert_eq!(ap1_j["autoReview"], true);
        assert_eq!(ap1_j["enabled"], true);
        let ap2 = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/people/me/approval-preferences"), &cookie, r#"{"hostCommands":"never"}"#)).await.unwrap();
        assert_eq!(ap2.status(), StatusCode::OK);
        let ap2_j = read_json(ap2).await;
        assert_eq!(ap2_j["autoReview"], true);
        assert_eq!(ap2_j["hostCommands"], "never");

        // 3. PATCH notification-settings merges routing cleanly
        let ns = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/people/me/notification-settings"), &cookie, r#"{"routing":{"progress":[]}}"#)).await.unwrap();
        assert_eq!(ns.status(), StatusCode::OK);
        let ns_j = read_json(ns).await;
        assert_eq!(ns_j["routing"]["progress"], json!([]));
        assert_eq!(ns_j["routing"]["decision"], json!("all"));

        // 4. PATCH person & org learning-settings & capabilities
        let pls = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/people/me/learning-settings"), &cookie, r#"{"mode":"open"}"#)).await.unwrap();
        assert_eq!(pls.status(), StatusCode::OK);
        assert_eq!(read_json(pls).await["mode"], "open");
        let ols = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/settings/learning"), &cookie, r#"{"enabled":true}"#)).await.unwrap();
        assert_eq!(ols.status(), StatusCode::OK);
        assert_eq!(read_json(ols).await["settings"]["enabled"], true);
        let cap = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/capabilities/proactive"), &cookie, r#"{"organization":true}"#)).await.unwrap();
        assert_eq!(cap.status(), StatusCode::OK);
        assert_eq!(read_json(cap).await["organization"], true);

        // 5. Organization profile, API keys, memories, skills roundtrip
        let op = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/profile"), &cookie, r#"{"name":"My PS5 Org"}"#)).await.unwrap();
        assert_eq!(op.status(), StatusCode::OK);
        assert_eq!(read_json(op).await["organization"]["name"], "My PS5 Org");

        let ak = app.clone().oneshot(post_or_patch("POST", &format!("/api/v2/organizations/{org_id}/people/me/api-keys"), &cookie, r#"{"name":"dev"}"#)).await.unwrap();
        assert_eq!(ak.status(), StatusCode::CREATED);
        let ak_j = read_json(ak).await;
        assert!(ak_j["key"].as_str().unwrap().starts_with("obk_"));

        let mem = app.clone().oneshot(post_or_patch("POST", &format!("/api/v2/organizations/{org_id}/people/me/memories"), &cookie, r#"{"content":"Likes Rust"}"#)).await.unwrap();
        assert_eq!(mem.status(), StatusCode::CREATED);
        let sk = app.clone().oneshot(post_or_patch("PUT", &format!("/api/v2/organizations/{org_id}/skills/daily-notes"), &cookie, r#"{"title":"Daily Notes","instructions":"Summarize the day.","tools":[]}"#)).await.unwrap();
        assert_eq!(sk.status(), StatusCode::OK);
        let list_sk = app.clone().oneshot(Request::builder().uri(&format!("/api/v2/organizations/{org_id}/skills")).header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(read_json(list_sk).await["skills"][0]["slug"], "daily-notes");

        // 6. Check-ins allowed reflects proactive capability & learning review reflects autoApprove
        let ci = app.clone().oneshot(Request::builder().uri(&format!("/api/v2/organizations/{org_id}/check-ins")).header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(read_json(ci).await["allowed"], true);
        let cap_off = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/capabilities/proactive"), &cookie, r#"{"organization":false}"#)).await.unwrap();
        assert_eq!(cap_off.status(), StatusCode::OK);
        let ci_off = app.clone().oneshot(Request::builder().uri(&format!("/api/v2/organizations/{org_id}/check-ins")).header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(read_json(ci_off).await["allowed"], false);

        let aa = app.clone().oneshot(post_or_patch("PATCH", &format!("/api/v2/organizations/{org_id}/people/me/learning-settings"), &cookie, r#"{"autoApprove":true}"#)).await.unwrap();
        assert_eq!(aa.status(), StatusCode::OK);
        let rev = app.clone().oneshot(Request::builder().uri(&format!("/api/v2/organizations/{org_id}/people/me/learning-review")).header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
        let rev_j = read_json(rev).await;
        assert_eq!(rev_j["canReview"], true);
        assert_eq!(rev_j["autoApprove"], true);

        // 7. Group conversation members list both bots & person and route resolves cleanly
        db.try_with_connection(|c| {
            c.execute_batch("INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot-a','default',id,'Alpha','','a',0 FROM auth_users LIMIT 1; INSERT INTO port_bots(id,organization_id,owner_id,name,title,role_description,created_at) SELECT 'bot-b','default',id,'Beta','','b',0 FROM auth_users LIMIT 1; INSERT INTO port_conversations(id,organization_id,owner_id,thread_id,bot_ids_json,name,created_at) SELECT 'grp-1','default',id,'t-grp','[\"bot-a\",\"bot-b\"]','Alpha, Beta',0 FROM auth_users LIMIT 1;")?;
            Ok(())
        }).unwrap();
        let mems = app.clone().oneshot(Request::builder().uri(&format!("/api/v2/organizations/{org_id}/conversations/grp-1/members")).header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
        let mems_j = read_json(mems).await;
        let arr = mems_j["members"].as_array().unwrap();
        assert!(arr.iter().any(|m| m["kind"] == "bot" && m["id"] == "bot-a"));
        assert!(arr.iter().any(|m| m["kind"] == "bot" && m["id"] == "bot-b"));
        assert!(arr.iter().any(|m| m["kind"] == "person" && m["creator"] == true));

        let rt = app.clone().oneshot(post_or_patch("POST", &format!("/api/v2/organizations/{org_id}/conversations/route"), &cookie, r#"{"text":"ask @Alpha to check"}"#)).await.unwrap();
        assert_eq!(rt.status(), StatusCode::OK);
        assert_eq!(read_json(rt).await["botId"], "bot-a");

        let _ = std::fs::remove_file(path);
    }
}
