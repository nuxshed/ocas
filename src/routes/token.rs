use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::jwt;
use crate::models::{RefreshToken, User};
use crate::routes::login::{genrefresh, hashtoken};
use crate::AppState;

#[derive(Deserialize)]
pub struct RefreshBody {
    pub refresh: String,
}

/// rotates the refresh token and issues a new access token
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RefreshBody>,
) -> Result<Json<Value>, AppError> {
    let hash = hashtoken(&body.refresh);

    let old: RefreshToken = sqlx::query_as(
        "delete from refreshtokens where tokenhash = $1 and expiresat > now() returning *",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("invalid or expired refresh token".into()))?;

    let user: User = sqlx::query_as("select * from users where id = $1")
        .bind(old.userid)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("user not found".into()))?;

    if user.banned {
        return Err(AppError::Forbidden("account banned".into()));
    }

    let (access, _jti) = jwt::sign(&user, &state.config.privatekey)?;
    let newrefresh = genrefresh();
    let newhash = hashtoken(&newrefresh);

    let expiry = Utc::now() + Duration::days(30);
    sqlx::query("insert into refreshtokens (tokenhash, userid, expiresat) values ($1, $2, $3)")
        .bind(&newhash)
        .bind(user.id)
        .bind(expiry)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({
        "access": access,
        "refresh": newrefresh,
        "type": "bearer",
        "expires": 900,
    })))
}

/// revokes a refresh token. always returns 200
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RefreshBody>,
) -> Result<Json<Value>, AppError> {
    let hash = hashtoken(&body.refresh);
    sqlx::query("delete from refreshtokens where tokenhash = $1")
        .bind(&hash)
        .execute(&state.db)
        .await?;

    Ok(Json(json!({ "status": "ok" })))
}
