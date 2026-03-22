use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::hash::{gentoken, hashtoken, verifypw};
use crate::jwt;
use crate::models::User;
use crate::AppState;

#[derive(Deserialize)]
pub struct LoginBody {
    pub email: String,
    pub password: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginBody>,
) -> Result<Json<Value>, AppError> {
    let email = body.email.trim().to_lowercase();

    let user: User = sqlx::query_as("select * from users where email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid credentials".into()))?;

    if user.banned {
        return Err(AppError::Forbidden("account banned".into()));
    }

    if !user.verified {
        return Err(AppError::Forbidden("email not verified".into()));
    }

    if !verifypw(&body.password, &user.passhash)? {
        return Err(AppError::Unauthorized("invalid credentials".into()));
    }

    let (access, _jti) = jwt::sign(&user, &state.config.privatekey)?;
    let refresh = gentoken();
    let refreshhash = hashtoken(&refresh);

    let expiry = Utc::now() + Duration::days(30);
    sqlx::query("insert into refreshtokens (tokenhash, userid, expiresat) values ($1, $2, $3)")
        .bind(&refreshhash)
        .bind(user.id)
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
