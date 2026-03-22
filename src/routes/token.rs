use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::hash::{gentoken, hashtoken, verifypw};
use crate::jwt;
use crate::models::{AuthCode, Client, User};
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

    let old: crate::models::RefreshToken = sqlx::query_as(
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
    let newrefresh = gentoken();
    let newhash = hashtoken(&newrefresh);

    let expiry = Utc::now() + Duration::days(30);
    sqlx::query(
        "insert into refreshtokens (tokenhash, userid, clientid, expiresat) values ($1, $2, $3, $4)",
    )
    .bind(&newhash)
    .bind(user.id)
    .bind(&old.clientid)
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

#[derive(Deserialize)]
pub struct TokenExchangeBody {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
}

/// exchanges an authorization code for tokens (OAuth2 token endpoint)
pub async fn exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::Form(body): axum::Form<TokenExchangeBody>,
) -> Result<Json<Value>, AppError> {
    let (cid, csecret) = parsebasic(&headers)?;

    let client: Client = sqlx::query_as("select * from clients where clientid = $1")
        .bind(&cid)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid client".into()))?;

    if !verifypw(&csecret, &client.secrethash)? {
        return Err(AppError::Unauthorized("invalid client credentials".into()));
    }

    if body.grant_type != "authorization_code" {
        return Err(AppError::BadRequest("unsupported grant_type".into()));
    }

    let authcode: AuthCode = sqlx::query_as(
        "update authcodes set used = true
         where code = $1 and used = false and expiresat > now()
         returning *",
    )
    .bind(&body.code)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("invalid or expired code".into()))?;

    if authcode.clientid != cid {
        return Err(AppError::BadRequest("code was issued to a different client".into()));
    }

    if authcode.redirecturi != body.redirect_uri {
        return Err(AppError::BadRequest("redirect_uri mismatch".into()));
    }

    let challenge = pkcechallenge(&body.code_verifier);
    if challenge != authcode.codechallenge {
        return Err(AppError::BadRequest("PKCE verification failed".into()));
    }

    let user: User = sqlx::query_as("select * from users where id = $1")
        .bind(authcode.userid)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("user not found".into()))?;

    if user.banned {
        return Err(AppError::Forbidden("account banned".into()));
    }

    let (access, _jti) = jwt::sign(&user, &state.config.privatekey)?;
    let refresh = gentoken();
    let refreshhash = hashtoken(&refresh);

    let expiry = Utc::now() + Duration::days(30);
    sqlx::query(
        "insert into refreshtokens (tokenhash, userid, clientid, expiresat) values ($1, $2, $3, $4)",
    )
    .bind(&refreshhash)
    .bind(user.id)
    .bind(&cid)
    .bind(expiry)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({
        "access": access,
        "refresh": refresh,
        "type": "bearer",
        "expires": 900,
    })))
}

/// parses HTTP Basic auth header into (client_id, client_secret)
fn parsebasic(headers: &HeaderMap) -> Result<(String, String), AppError> {
    let val = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing authorization header".into()))?;

    let encoded = val
        .strip_prefix("Basic ")
        .ok_or_else(|| AppError::Unauthorized("expected Basic auth".into()))?;

    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized("invalid base64".into()))?;

    let pair = String::from_utf8(decoded)
        .map_err(|_| AppError::Unauthorized("invalid utf8".into()))?;

    let (id, secret) = pair
        .split_once(':')
        .ok_or_else(|| AppError::Unauthorized("malformed credentials".into()))?;

    Ok((id.to_string(), secret.to_string()))
}

/// computes PKCE S256 challenge from verifier
fn pkcechallenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}
