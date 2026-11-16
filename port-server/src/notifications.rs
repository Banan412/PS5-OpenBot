//! Discover configured external notification transports.
use crate::local_auth::{identity, AuthState};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route(
            "/api/v2/organizations/{organization}/notification-transports",
            get(list),
        )
        .with_state(state)
}

#[derive(Deserialize)]
struct Page {
    limit: Option<String>,
    cursor: Option<String>,
}

fn reply(status: StatusCode, body: serde_json::Value) -> Response {
    let mut r = (status, Json(body)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    r
}

fn failure(status: StatusCode, title: &str) -> Response {
    reply(
        status,
        json!({"type":"about:blank","title":title,"status":status.as_u16()}),
    )
}

async fn list(
    State(state): State<AuthState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Response {
    match identity(&state, &headers).await {
        Ok(Some(i)) if org != i.organization && org != i.slug => {
            return failure(StatusCode::NOT_FOUND, "Organization not found")
        }
        Ok(Some(_)) => (),
        Ok(None) => return failure(StatusCode::UNAUTHORIZED, "Sign in required"),
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "Service unavailable"),
    }
    // This deployment supports no external notification transports and thus
    // never issues continuation cursors.
    if page.cursor.is_some()
        || page
            .limit
            .as_ref()
            .is_some_and(|s| s.parse::<u32>().map_or(true, |n| !(1..=100).contains(&n)))
    {
        return failure(StatusCode::BAD_REQUEST, "Invalid pagination");
    }
    reply(
        StatusCode::OK,
        json!({"notificationTransports":[],"nextCursor":null}),
    )
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
    async fn discovery_requires_session_and_reports_only_configured_transports() {
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "openbot-transports-{:x}.db",
            u64::from_le_bytes(random)
        ));
        let db = Arc::new(Storage::open(&path).unwrap());
        let auth = AuthState::new(
            db.clone(),
            "http://example.test",
            Some("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();
        let app = router(auth.clone()).merge(crate::local_auth::router(auth));
        let uri = "/api/v2/organizations/default/notification-transports";
        let anonymous = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        let setup = app.clone().oneshot(Request::builder().method("POST").uri("/api/port/auth/setup").header("host","example.test").header("origin","http://example.test").header("content-type","application/json").body(Body::from(r#"{"setupToken":"0123456789abcdef0123456789abcdef","email":"owner@example.test","name":"Owner","password":"valid password 123"}"#)).unwrap()).await.unwrap();
        assert_eq!(setup.status(), StatusCode::NO_CONTENT);
        let cookie = setup.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        for (url, expected) in [
            (uri, StatusCode::OK),
            (
                "/api/v2/organizations/default/notification-transports?limit=0",
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/v2/organizations/default/notification-transports?cursor=bogus",
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/v2/organizations/other/notification-transports",
                StatusCode::NOT_FOUND,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(url)
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
            if expected == StatusCode::OK {
                let value: serde_json::Value =
                    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                        .unwrap();
                assert_eq!(
                    value,
                    json!({"notificationTransports":[],"nextCursor":null})
                );
            }
        }
        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
