//! Personal preferences, scoped to the signed-in person and organization.
use crate::local_auth::{identity, AuthState};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/people/{person}/preferences",
            get(read).patch(update),
        )
        .layer(DefaultBodyLimit::max(4096))
        .with_state(state)
}
fn response(status: StatusCode, value: Value) -> Response {
    let mut r = (status, Json(value)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    r
}
fn failure(status: StatusCode, title: &str) -> Response {
    response(
        status,
        json!({"type":"about:blank","title":title,"status":status.as_u16()}),
    )
}
async fn authorize(
    s: &AuthState,
    h: &HeaderMap,
    org: &str,
    person: &str,
    write: bool,
) -> Result<String, Response> {
    if write && !s.valid_origin(h).await {
        return Err(failure(StatusCode::FORBIDDEN, "Forbidden"));
    }
    match identity(s, h).await {
        Ok(Some(i)) if org != i.organization && org != i.slug => {
            Err(failure(StatusCode::NOT_FOUND, "Organization not found"))
        }
        Ok(Some(i)) if person != "me" && person != i.id => {
            Err(failure(StatusCode::FORBIDDEN, "Own preferences only"))
        }
        Ok(Some(i)) => Ok(i.id),
        Ok(None) => Err(failure(StatusCode::UNAUTHORIZED, "Sign in required")),
        Err(_) => Err(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service unavailable",
        )),
    }
}
fn current(c: &rusqlite::Connection, user: &str) -> rusqlite::Result<Value> {
    let row=c.query_row("SELECT message_emphasis,banner_dismissed,narration,skin,proactive FROM port_preferences WHERE user_id=?1",params![user],|r|Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?))).optional()?;
    let (emphasis, banner, narration, skin, proactive) =
        row.unwrap_or(("thread".into(), false, None, "openbot".into(), "on".into()));
    Ok(
        json!({"messageListEmphasis":emphasis,"selfHostBannerDismissed":banner,"narration":narration,"skin":skin,"proactive":proactive}),
    )
}
async fn read(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    let user = match authorize(&s, &h, &org, &person, false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable");
    };
    let db = s.db.clone();
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        db.try_with_connection(|c| Ok(current(c, &user)?))
    })
    .await
    {
        Ok(Ok(value)) => response(StatusCode::OK, value),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    }
}
fn valid(v: &Value) -> bool {
    let Some(m) = v.as_object() else { return false };
    !m.is_empty()
        && m.iter().all(|(k, v)| match k.as_str() {
            "messageListEmphasis" => matches!(v.as_str(), Some("agent" | "thread")),
            "selfHostBannerDismissed" => v.is_boolean(),
            "narration" | "proactive" => matches!(v.as_str(), Some("on" | "off")),
            "skin" => matches!(
                v.as_str(),
                Some("openbot" | "openduet" | "opendots" | "openfuse")
            ),
            _ => false,
        })
}
async fn update(
    State(s): State<AuthState>,
    Path((org, person)): Path<(String, String)>,
    h: HeaderMap,
    Json(value): Json<Value>,
) -> Response {
    let user = match authorize(&s, &h, &org, &person, true).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !valid(&value) {
        return failure(StatusCode::BAD_REQUEST, "Invalid preferences");
    }
    let Some(key) = h
        .get("idempotency-key")
        .and_then(|x| x.to_str().ok())
        .filter(|x| !x.is_empty() && x.len() <= 128)
        .map(str::to_owned)
    else {
        return failure(StatusCode::BAD_REQUEST, "Idempotency-Key required");
    };
    let hash = Sha256::digest(value.to_string().as_bytes()).to_vec();
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(t) => t.as_secs() as i64,
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "Clock unavailable"),
    };
    let Ok(permit) = s.db_jobs.clone().try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable");
    };
    let db = s.db.clone();
    let result=tokio::task::spawn_blocking(move||{let _permit=permit;db.try_with_connection(|c|{
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM port_preference_requests WHERE created_at<?1",params![now-86400])?;
        let old=tx.query_row("SELECT fingerprint,response FROM port_preference_requests WHERE user_id=?1 AND request_key=?2",params![user,key],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?))).optional()?;
        if let Some((fingerprint,body))=old {return Ok(if fingerprint==hash {Some(body)} else {None});}
        let mut result=current(&tx,&user)?;
        for (k,v) in value.as_object().unwrap(){result[k]=v.clone();}
        tx.execute("INSERT INTO port_preferences(user_id,message_emphasis,banner_dismissed,narration,skin,proactive) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(user_id) DO UPDATE SET message_emphasis=excluded.message_emphasis,banner_dismissed=excluded.banner_dismissed,narration=excluded.narration,skin=excluded.skin,proactive=excluded.proactive",params![user,result["messageListEmphasis"].as_str(),result["selfHostBannerDismissed"].as_bool(),result["narration"].as_str(),result["skin"].as_str(),result["proactive"].as_str()])?;
        let body=result.to_string();tx.execute("INSERT INTO port_preference_requests(user_id,request_key,fingerprint,response,created_at) VALUES(?1,?2,?3,?4,?5)",params![user,key,hash,body,now])?;tx.commit()?;Ok(Some(body))
    })}).await;
    match result {
        Ok(Ok(Some(body))) => match serde_json::from_str(&body) {
            Ok(v) => response(StatusCode::OK, v),
            Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
        },
        Ok(Ok(None)) => failure(StatusCode::CONFLICT, "Idempotency key conflict"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
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
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn preferences_require_session_persist_and_replay_idempotently() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path =
            std::env::temp_dir().join(format!("openbot-pref-{:x}.db", u64::from_le_bytes(random)));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let app = router(auth.clone()).merge(crate::local_auth::router(auth));
        let uri = "/api/v2/organizations/default/people/me/preferences";
        let empty = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(empty.status(), StatusCode::UNAUTHORIZED);
        let setup=app.clone().oneshot(Request::builder().method("POST").uri("/api/port/auth/setup").header("host","example.test").header("origin","http://example.test").header("content-type","application/json").body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#)).unwrap()).await.unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);
        let cookie = setup.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let req = |body: &str, key: &str| {
            Request::builder()
                .method("PATCH")
                .uri(uri)
                .header("host", "example.test")
                .header("origin", "http://example.test")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body.to_owned()))
                .unwrap()
        };
        let first = app
            .clone()
            .oneshot(req(r#"{"skin":"opendots"}"#, "one"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<Value>(&to_bytes(first.into_body(), 4096).await.unwrap())
                .unwrap()["skin"],
            "opendots"
        );
        let replay = app
            .clone()
            .oneshot(req(r#"{"skin":"opendots"}"#, "one"))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let conflict = app
            .clone()
            .oneshot(req(r#"{"skin":"openfuse"}"#, "one"))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let other = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/organizations/default/people/someone/preferences")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::FORBIDDEN);
        let read = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&to_bytes(read.into_body(), 4096).await.unwrap())
                .unwrap()["skin"],
            "opendots"
        );
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
