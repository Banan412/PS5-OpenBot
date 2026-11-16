//! Persistent scheduled routines (CRUD + manual run + background cron ticker).
use crate::{
    compat_routes::{authorize, epoch, format_iso_utc, internal, problem, respond_json, run_db},
    local_auth::AuthState,
    runs::{self, RunState},
    storage::StorageError,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Clone)]
struct RoutineState {
    auth: AuthState,
    runs: Option<RunState>,
}

pub fn router(auth: AuthState, runs: Option<RunState>) -> Router {
    let state = RoutineState { auth, runs };
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/routines",
            get(list_routines).post(create_routine),
        )
        .route(
            "/api/v2/organizations/{organization}/routines/{routine_id}",
            delete(delete_routine),
        )
        .route(
            "/api/v2/organizations/{organization}/routines/{routine_id}/pause",
            post(pause_routine),
        )
        .route(
            "/api/v2/organizations/{organization}/routines/{routine_id}/resume",
            post(resume_routine),
        )
        .route(
            "/api/v2/organizations/{organization}/routines/{routine_id}/run",
            post(run_routine),
        )
        .route(
            "/api/v2/organizations/{organization}/routines/{routine_id}/runs",
            get(list_routine_runs),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

fn routine_id() -> Result<String, StorageError> {
    let mut b = [0u8; 10];
    getrandom::getrandom(&mut b)
        .map_err(|_| StorageError::InvalidDatabase("entropy unavailable"))?;
    Ok(format!(
        "rt_{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    ))
}

fn cron_interval_secs(cron: &str) -> Result<i64, &'static str> {
    let fields: Vec<&str> = cron.split_whitespace().collect();
    if fields.len() != 5 {
        return Err("Cron must have 5 fields (minute hour day month weekday).");
    }
    let min = fields[0];
    let hour = fields[1];
    let dow = fields[4];
    if let Some(step) = min.strip_prefix("*/") {
        let n: i64 = step.parse().map_err(|_| "Invalid cron minute step.")?;
        if n <= 0 {
            return Err("Invalid cron minute step.");
        }
        return Ok((n * 60).max(3600));
    }
    if dow != "*" {
        return Ok(7 * 86400);
    }
    if fields[2] != "*" {
        return Ok(30 * 86400);
    }
    if hour == "*" {
        return Ok(3600);
    }
    if let Some(step) = hour.strip_prefix("*/") {
        let n: i64 = step.parse().map_err(|_| "Invalid cron hour step.")?;
        if n <= 0 {
            return Err("Invalid cron hour step.");
        }
        return Ok(n * 3600);
    }
    Ok(86400)
}

fn load_routine_json(
    c: &Connection,
    org: &str,
    owner: &str,
    id: &str,
) -> Result<Option<Value>, StorageError> {
    let row: Option<(
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        Option<String>,
        i64,
        Option<i64>,
        Option<String>,
        i64,
        i64,
        String,
        Option<String>,
    )> = c
        .query_row(
            "SELECT r.id, r.bot_id, r.conversation_id, r.title, r.instruction, r.cron, r.timezone, r.goal_id,
                    r.enabled, r.last_run_at, r.last_run_status, r.next_run_at, r.created_at,
                    COALESCE(c.title, c.name, 'Conversation'), c.thread_id
               FROM port_routines r
               LEFT JOIN port_conversations c ON c.id = r.conversation_id
              WHERE r.id=?1 AND r.organization_id=?2 AND r.owner_id=?3",
            params![id, org, owner],
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
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                ))
            },
        )
        .optional()?;
    let Some((
        id,
        bot_id,
        conv_id,
        title,
        instruction,
        cron,
        timezone,
        goal_id,
        enabled,
        last_run_at,
        last_status,
        next_run_at,
        created_at,
        conv_name,
        _thread_id,
    )) = row
    else {
        return Ok(None);
    };
    let last_run = match (last_run_at, last_status) {
        (Some(ts), Some(st)) => json!({
            "startedAt": format_iso_utc(c, Some(ts))?,
            "status": st,
        }),
        _ => Value::Null,
    };
    Ok(Some(json!({
        "id": id,
        "botId": bot_id,
        "schedule": cron,
        "timezone": timezone,
        "instruction": instruction,
        "title": title,
        "conversation": {
            "id": conv_id,
            "name": conv_name,
        },
        "enabled": enabled == 1,
        "nextRunAt": format_iso_utc(c, Some(next_run_at))?,
        "lastRun": last_run,
        "goalId": goal_id,
        "createdAt": format_iso_utc(c, Some(created_at))?,
    })))
}

async fn list_routines(
    State(s): State<RoutineState>,
    Path(org): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s.auth, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let bot_filter = q.get("botId").cloned().filter(|v| !v.is_empty());
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let Ok(items) = run_db(&s.auth, move |c| {
        let mut st = c.prepare(
            "SELECT id FROM port_routines WHERE organization_id=?1 AND owner_id=?2 AND (?3 IS NULL OR bot_id=?3) ORDER BY created_at DESC, id DESC LIMIT 100",
        )?;
        let ids: Vec<String> = st
            .query_map(params![org_id, owner_id, bot_filter], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(st);
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(item) = load_routine_json(c, &org_id, &owner_id, &id)? {
                out.push(item);
            }
        }
        Ok(out)
    })
    .await
    else {
        return internal();
    };
    respond_json(
        StatusCode::OK,
        json!({ "routines": items, "nextCursor": Value::Null }),
    )
}

async fn create_routine(
    State(s): State<RoutineState>,
    Path(org): Path<String>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize(&s.auth, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let Some(bot_id) = body.get("botId").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty() && s.len() <= 200) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_ROUTINE", "Bot is required.");
    };
    let Some(conversation_id) = body.get("conversationId").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty() && s.len() <= 200) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_ROUTINE", "Conversation is required.");
    };
    let Some(instruction) = body.get("instruction").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty() && s.chars().count() <= 2000) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_ROUTINE", "Instruction is required.");
    };
    let Some(cron) = body.get("cron").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty() && s.len() <= 200) else {
        return problem(StatusCode::BAD_REQUEST, "INVALID_ROUTINE", "Cron schedule is required.");
    };
    let interval = match cron_interval_secs(cron) {
        Ok(v) => v,
        Err(msg) => return problem(StatusCode::BAD_REQUEST, "INVALID_ROUTINE", msg),
    };
    let title = body
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(100).collect::<String>());
    let timezone = body
        .get("timezone")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 100)
        .unwrap_or("UTC")
        .to_owned();
    let goal_id = body
        .get("goalId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 200)
        .map(str::to_owned);

    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let bot_c = bot_id.to_owned();
    let conv_c = conversation_id.to_owned();
    let instr_c = instruction.to_owned();
    let cron_c = cron.to_owned();
    let res = run_db(&s.auth, move |c| {
        let conv_bots_opt: Option<String> = c
            .query_row(
                "SELECT bot_ids_json FROM port_conversations WHERE id=?1 AND organization_id=?2 AND owner_id=?3 AND deleted=0",
                params![conv_c, org_id, owner_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(conv_bots_json) = conv_bots_opt else {
            return Ok(json!({"err": "conversation_not_found"}));
        };
        let conv_bots: Vec<String> = serde_json::from_str(&conv_bots_json).unwrap_or_default();
        if !conv_bots.contains(&bot_c) {
            return Ok(json!({"err": "bot_not_in_conversation"}));
        }
        let now = epoch()?;
        let id = routine_id()?;
        let next = now + interval;
        c.execute(
            "INSERT INTO port_routines(id,organization_id,owner_id,bot_id,conversation_id,title,instruction,cron,timezone,goal_id,enabled,next_run_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12)",
            params![id, org_id, owner_id, bot_c, conv_c, title, instr_c, cron_c, timezone, goal_id, next, now],
        )?;
        let item = load_routine_json(c, &org_id, &owner_id, &id)?
            .ok_or(StorageError::InvalidDatabase("missing created routine"))?;
        Ok(json!({ "routine": item }))
    })
    .await;
    match res {
        Ok(v) if v.get("err").and_then(Value::as_str) == Some("conversation_not_found") => {
            problem(StatusCode::NOT_FOUND, "CONVERSATION_NOT_FOUND", "Conversation not found.")
        }
        Ok(v) if v.get("err").and_then(Value::as_str) == Some("bot_not_in_conversation") => {
            problem(StatusCode::BAD_REQUEST, "INVALID_ROUTINE", "Selected Bot is not in this conversation.")
        }
        Ok(v) => respond_json(StatusCode::CREATED, v),
        Err(_) => internal(),
    }
}

async fn delete_routine(
    State(s): State<RoutineState>,
    Path((org, rid)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s.auth, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    match run_db(&s.auth, move |c| {
        Ok(c.execute(
            "DELETE FROM port_routines WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
            params![rid, org_id, owner_id],
        )?)
    })
    .await
    {
        Ok(0) => problem(StatusCode::NOT_FOUND, "ROUTINE_NOT_FOUND", "Routine not found."),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => internal(),
    }
}

async fn toggle_routine(
    s: &RoutineState,
    org: &str,
    rid: &str,
    h: &HeaderMap,
    enable: bool,
) -> Response {
    let actor = match authorize(&s.auth, h, org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let rid_s = rid.to_owned();
    let res = run_db(&s.auth, move |c| {
        let now = epoch()?;
        let val = i64::from(enable);
        let updated = if enable {
            let cron_opt: Option<String> = c
                .query_row(
                    "SELECT cron FROM port_routines WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                    params![rid_s, org_id, owner_id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(cron) = cron_opt else {
                return Ok(None);
            };
            let interval = cron_interval_secs(&cron).unwrap_or(86400);
            c.execute(
                "UPDATE port_routines SET enabled=?4, next_run_at=?5 WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![rid_s, org_id, owner_id, val, now + interval],
            )?;
            1
        } else {
            c.execute(
                "UPDATE port_routines SET enabled=0 WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![rid_s, org_id, owner_id],
            )?
        };
        if updated == 0 {
            return Ok(None);
        }
        load_routine_json(c, &org_id, &owner_id, &rid_s)
    })
    .await;
    match res {
        Ok(Some(item)) => respond_json(StatusCode::OK, json!({ "routine": item })),
        Ok(None) => problem(StatusCode::NOT_FOUND, "ROUTINE_NOT_FOUND", "Routine not found."),
        Err(_) => internal(),
    }
}

async fn pause_routine(
    State(s): State<RoutineState>,
    Path((org, rid)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    toggle_routine(&s, &org, &rid, &h, false).await
}

async fn resume_routine(
    State(s): State<RoutineState>,
    Path((org, rid)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    toggle_routine(&s, &org, &rid, &h, true).await
}

async fn run_routine(
    State(s): State<RoutineState>,
    Path((org, rid)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s.auth, &h, &org, true).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let rid_c = rid.clone();
    let Ok(info) = run_db(&s.auth, move |c| {
        let row: Option<(String, String, String, String)> = c
            .query_row(
                "SELECT bot_id, conversation_id, instruction, cron FROM port_routines WHERE id=?1 AND organization_id=?2 AND owner_id=?3",
                params![rid_c, org_id, owner_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((bot_id, conv_id, instr, _cron)) = row else {
            return Ok(None);
        };
        let now = epoch()?;
        let run_id = routine_id()?;
        c.execute(
            "INSERT INTO port_routine_runs(id,routine_id,conversation_id,status,started_at) VALUES(?1,?2,?3,'running',?4)",
            params![run_id, rid_c, conv_id, now],
        )?;
        c.execute(
            "UPDATE port_routines SET last_run_at=?2, last_run_status='running' WHERE id=?1",
            params![rid_c, now],
        )?;
        let iso = format_iso_utc(c, Some(now))?;
        Ok(Some((run_id, bot_id, conv_id, instr, iso)))
    })
    .await
    else {
        return internal();
    };
    let Some((run_id, bot_id, conv_id, instr, iso)) = info else {
        return problem(StatusCode::NOT_FOUND, "ROUTINE_NOT_FOUND", "Routine not found.");
    };
    let mut final_st = "completed";
    if let Some(ref runs_state) = s.runs {
        if runs::trigger_scheduled_message(runs_state, &actor.organization, &actor.id, &conv_id, &bot_id, &instr)
            .await
            .is_err()
        {
            final_st = "failed";
        }
    }
    let run_c = run_id.clone();
    let rid_c2 = rid;
    let st_s = final_st.to_owned();
    let _ = run_db(&s.auth, move |c| {
        let now = epoch()?;
        c.execute(
            "UPDATE port_routine_runs SET status=?2, finished_at=?3 WHERE id=?1",
            params![run_c, st_s, now],
        )?;
        c.execute(
            "UPDATE port_routines SET last_run_status=?2 WHERE id=?1",
            params![rid_c2, st_s],
        )?;
        Ok(())
    })
    .await;
    respond_json(
        StatusCode::ACCEPTED,
        json!({ "runId": run_id, "startedAt": iso }),
    )
}

async fn list_routine_runs(
    State(s): State<RoutineState>,
    Path((org, rid)): Path<(String, String)>,
    Query(_q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    let actor = match authorize(&s.auth, &h, &org, false).await {
        Ok(i) => i,
        Err(e) => return e,
    };
    let org_id = actor.organization.clone();
    let owner_id = actor.id.clone();
    let Ok(items) = run_db(&s.auth, move |c| {
        let exists: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM port_routines WHERE id=?1 AND organization_id=?2 AND owner_id=?3)",
            params![rid, org_id, owner_id],
            |r| r.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
        let mut st = c.prepare(
            "SELECT id, conversation_id, status, started_at, finished_at FROM port_routine_runs WHERE routine_id=?1 ORDER BY started_at DESC, id DESC LIMIT 50",
        )?;
        let rows = st
            .query_map(params![rid], |r| {
                let id: String = r.get(0)?;
                let conv: String = r.get(1)?;
                let status: String = r.get(2)?;
                let started: i64 = r.get(3)?;
                let finished: Option<i64> = r.get(4)?;
                Ok((id, conv, status, started, finished))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(st);
        let mut out = Vec::with_capacity(rows.len());
        for (id, conv, status, started, finished) in rows {
            out.push(json!({
                "id": id,
                "conversationId": conv,
                "status": status,
                "startedAt": format_iso_utc(c, Some(started))?,
                "finishedAt": match format_iso_utc(c, finished)? { Some(s) => Value::String(s), None => Value::Null },
            }));
        }
        Ok(Some(out))
    })
    .await
    else {
        return internal();
    };
    let Some(runs) = items else {
        return problem(StatusCode::NOT_FOUND, "ROUTINE_NOT_FOUND", "Routine not found.");
    };
    respond_json(
        StatusCode::OK,
        json!({ "runs": runs, "nextCursor": Value::Null }),
    )
}

pub fn spawn_scheduler(auth: AuthState, runs: Option<RunState>) {
    let Some(runs_state) = runs else {
        return;
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(20));
        loop {
            interval.tick().await;
            let db = auth.db.clone();
            let due = tokio::task::spawn_blocking(move || {
                db.try_with_connection(|c| {
                    let now = epoch()?;
                    let mut st = c.prepare(
                        "SELECT id, organization_id, owner_id, bot_id, conversation_id, instruction, cron FROM port_routines WHERE enabled=1 AND next_run_at <= ?1 ORDER BY next_run_at ASC LIMIT 8",
                    )?;
                    let rows = st
                        .query_map(params![now], |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, String>(2)?,
                                r.get::<_, String>(3)?,
                                r.get::<_, String>(4)?,
                                r.get::<_, String>(5)?,
                                r.get::<_, String>(6)?,
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    drop(st);
                    for (id, _, _, _, _, _, cron) in &rows {
                        let step = cron_interval_secs(cron).unwrap_or(3600);
                        let _ = c.execute(
                            "UPDATE port_routines SET next_run_at=?2, last_run_at=?3, last_run_status='running' WHERE id=?1",
                            params![id, now + step, now],
                        );
                    }
                    Ok(rows)
                })
            })
            .await;
            if let Ok(Ok(items)) = due {
                for (rid, org, owner, bot_id, conv_id, instr, _) in items {
                    let ok = runs::trigger_scheduled_message(
                        &runs_state,
                        &org,
                        &owner,
                        &conv_id,
                        &bot_id,
                        &instr,
                    )
                    .await
                    .is_ok();
                    let db2 = auth.db.clone();
                    let status = if ok { "completed" } else { "failed" };
                    let _ = tokio::task::spawn_blocking(move || {
                        db2.try_with_connection(|c| {
                            let now = epoch()?;
                            let _ = c.execute(
                                "UPDATE port_routines SET last_run_status=?2 WHERE id=?1",
                                params![rid, status],
                            );
                            if let Ok(run_id) = routine_id() {
                                let _ = c.execute(
                                    "INSERT INTO port_routine_runs(id,routine_id,conversation_id,status,started_at,finished_at) VALUES(?1,?2,?3,?4,?5,?5)",
                                    params![run_id, rid, conv_id, status, now],
                                );
                            }
                            Ok(())
                        })
                    })
                    .await;
                }
            }
        }
    });
}
