use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::AppState;

/// returns the jwks
pub async fn jwks(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(serde_json::to_value(&state.jwks).unwrap())
}

/// oidc discovery stub
pub async fn openid() -> Json<Value> {
    Json(json!({
        "issuer": "https://auth.osdg.in",
        "jwks_uri": "https://auth.osdg.in/jwks.json",
        "token_endpoint": "https://auth.osdg.in/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

/// returns blocked jtis
pub async fn blocklist(State(state): State<Arc<AppState>>) -> Json<Value> {
    let jtis = state.blocklist.list();
    Json(json!({ "jti": jtis }))
}
