use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::hash::{genclientid, gensecret, hashpw};
use crate::AppState;

#[derive(Deserialize)]
pub struct CreateClientBody {
    pub name: String,
    pub redirecturis: Vec<String>,
}

/// registers a new OAuth2 client
pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateClientBody>,
) -> Result<(axum::http::StatusCode, Json<Value>), AppError> {
    if body.name.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }

    if body.redirecturis.is_empty() {
        return Err(AppError::BadRequest("at least one redirect uri is required".into()));
    }

    let clientid = genclientid();
    let secret = gensecret();
    let secrethash = hashpw(&secret)?;

    sqlx::query(
        "insert into clients (clientid, secrethash, redirecturis, name) values ($1, $2, $3, $4)",
    )
    .bind(&clientid)
    .bind(&secrethash)
    .bind(&body.redirecturis)
    .bind(&body.name)
    .execute(&state.db)
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "clientid": clientid,
            "secret": secret,
            "name": body.name,
        })),
    ))
}
