use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::error::AppError;
use crate::hash::{gentoken, verifypw};
use crate::models::{Client, User};
use crate::AppState;

#[derive(Deserialize)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub response_type: String,
}

#[derive(Deserialize)]
pub struct AuthorizeForm {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub response_type: String,
    pub email: String,
    pub password: String,
}

/// validates the common OAuth2 authorize parameters
async fn validateparams(
    db: &sqlx::PgPool,
    clientid: &str,
    redirecturi: &str,
    method: &str,
    responsetype: &str,
) -> Result<Client, AppError> {
    if responsetype != "code" {
        return Err(AppError::BadRequest("response_type must be code".into()));
    }

    if method != "S256" {
        return Err(AppError::BadRequest("code_challenge_method must be S256".into()));
    }

    let client: Client = sqlx::query_as("select * from clients where clientid = $1")
        .bind(clientid)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| AppError::BadRequest("unknown client_id".into()))?;

    if !client.redirecturis.contains(&redirecturi.to_string()) {
        return Err(AppError::BadRequest("redirect_uri not registered".into()));
    }

    Ok(client)
}

/// GET /authorize — renders login form
pub async fn show(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, AppError> {
    validateparams(
        &state.db,
        &params.client_id,
        &params.redirect_uri,
        &params.code_challenge_method,
        &params.response_type,
    )
    .await?;

    let html = loginform(
        &params.client_id,
        &params.redirect_uri,
        &params.state,
        &params.code_challenge,
        &params.code_challenge_method,
        &params.response_type,
        None,
    );

    Ok(Html(html).into_response())
}

/// POST /authorize — authenticates and redirects with auth code
pub async fn submit(
    State(state): State<Arc<AppState>>,
    Form(form): Form<AuthorizeForm>,
) -> Result<Response, AppError> {
    validateparams(
        &state.db,
        &form.client_id,
        &form.redirect_uri,
        &form.code_challenge_method,
        &form.response_type,
    )
    .await?;

    let email = form.email.trim().to_lowercase();

    let user: User = match sqlx::query_as("select * from users where email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?
    {
        Some(u) => u,
        None => return Ok(formerror(&form, "invalid credentials")),
    };

    if user.banned {
        return Err(AppError::Forbidden("account banned".into()));
    }

    if !user.verified {
        return Err(AppError::Forbidden("email not verified".into()));
    }

    if !verifypw(&form.password, &user.passhash)? {
        return Ok(formerror(&form, "invalid credentials"));
    }

    let code = gentoken();
    let expiry = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "insert into authcodes (code, clientid, userid, redirecturi, codechallenge, expiresat)
         values ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&code)
    .bind(&form.client_id)
    .bind(user.id)
    .bind(&form.redirect_uri)
    .bind(&form.code_challenge)
    .bind(expiry)
    .execute(&state.db)
    .await?;

    let sep = if form.redirect_uri.contains('?') { "&" } else { "?" };
    let location = format!("{}{}code={}&state={}", form.redirect_uri, sep, code, form.state);

    Ok(Redirect::to(&location).into_response())
}

/// re-renders the login form with an error message
fn formerror(form: &AuthorizeForm, msg: &str) -> Response {
    let html = loginform(
        &form.client_id,
        &form.redirect_uri,
        &form.state,
        &form.code_challenge,
        &form.code_challenge_method,
        &form.response_type,
        Some(msg),
    );
    (StatusCode::UNAUTHORIZED, Html(html)).into_response()
}

/// generates the login form HTML
fn loginform(
    clientid: &str,
    redirecturi: &str,
    state: &str,
    codechallenge: &str,
    method: &str,
    responsetype: &str,
    error: Option<&str>,
) -> String {
    let errmsg = error
        .map(|e| format!(r#"<p style="color:#e74c3c">{e}</p>"#))
        .unwrap_or_default();

    format!(
        r#"<!doctype html>
<html>
<head><title>ocas — login</title></head>
<body>
<form method="post" action="/authorize">
<h2>sign in</h2>
{errmsg}
<input type="hidden" name="client_id" value="{clientid}">
<input type="hidden" name="redirect_uri" value="{redirecturi}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{codechallenge}">
<input type="hidden" name="code_challenge_method" value="{method}">
<input type="hidden" name="response_type" value="{responsetype}">
<input type="email" name="email" placeholder="email" required>
<input type="password" name="password" placeholder="password" required>
<button type="submit">login</button>
</form>
</body>
</html>"#
    )
}
