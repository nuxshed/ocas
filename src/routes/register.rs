use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::extract::parseemail;
use crate::hash::hashpw;
use crate::AppState;

#[derive(Deserialize)]
pub struct RegisterBody {
    pub email: String,
    pub password: String,
    pub branch: Option<String>,
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterBody>,
) -> Result<(axum::http::StatusCode, Json<Value>), AppError> {
    let email = body.email.trim().to_lowercase();

    if body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "password must be at least 8 characters".into(),
        ));
    }

    let info = parseemail(&email)?;

    if info.usertype == "student" && info.rollnum.is_some() && body.branch.is_none() {
        return Err(AppError::BadRequest(
            "branch is required for students".into(),
        ));
    }

    let passhash = hashpw(&body.password)?;

    let row = sqlx::query_scalar::<_, uuid::Uuid>(
        "insert into users (email, rollnum, passhash, batch, branch, type, verified)
         values ($1, $2, $3, $4, $5, $6, true)
         returning id",
    )
    .bind(&email)
    .bind(&info.rollnum)
    .bind(&passhash)
    .bind(info.batch)
    .bind(&body.branch)
    .bind(&info.usertype)
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref dbe) if dbe.constraint() == Some("users_email_key") => {
            AppError::Conflict("email already registered".into())
        }
        _ => AppError::from(e),
    })?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "id": row,
            "email": email,
            "type": info.usertype,
        })),
    ))
}
