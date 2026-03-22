use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub enum AuthError {
    Unauthorized(String),
    Forbidden(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, msg) = match self {
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", m),
        };
        let body = json!({ "error": code, "message": msg });
        (status, axum::Json(body)).into_response()
    }
}
