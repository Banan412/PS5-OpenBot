//! Public capability discovery for the incomplete port.
//!
//! This router deliberately answers only for the unauthenticated `default`
//! organization. Once sessions are added, the deployment endpoint must enforce
//! the specification's authenticated membership rules before being expanded.
use axum::{
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

/// The capabilities this build advertises for the `default` organization.
const DEPLOYMENT: &str = r#"{"edition":"team","localEvaluation":false,"generativeUi":false,"selfHostBanner":false,"transcription":false,"voice":false,"durableHistory":true,"authProviders":[],"ssoConfigured":false,"ssoRequired":false,"builtInBots":true,"isolatedBots":false,"botComputers":true}"#;

pub(crate) fn router() -> Router {
    Router::new().route("/api/v2/organizations/default/deployment", get(deployment))
}

async fn deployment() -> Response {
    let mut response = DEPLOYMENT.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn public_deployment_reports_only_available_capabilities() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/organizations/default/deployment")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            to_bytes(response.into_body(), 4096).await.unwrap(),
            DEPLOYMENT
        );
        let other = router()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/organizations/other/deployment")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::NOT_FOUND);
    }
}
