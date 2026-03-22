use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::OcasClient;

#[derive(Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access: String,
    refresh: String,
}

/// builds the /auth router with login, callback, logout
pub fn authrouter(client: Arc<OcasClient>) -> Router {
    Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/logout", get(logout))
        .with_state(client)
}

/// GET /auth/login — generates pkce + state, redirects to ocas /authorize
async fn login(State(client): State<Arc<OcasClient>>) -> Response {
    let verifier = genverifier();
    let challenge = pkcechallenge(&verifier);
    let state = genstate();

    let authurl = format!(
        "{}/authorize?client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256&response_type=code",
        client.config.url,
        client.config.clientid,
        client.config.callbackurl,
        state,
        challenge,
    );

    let mut resp = Redirect::to(&authurl).into_response();
    let headers = resp.headers_mut();
    headers.append(SET_COOKIE, cookie("ocas_verifier", &verifier, 600));
    headers.append(SET_COOKIE, cookie("ocas_state", &state, 600));
    resp
}

/// GET /auth/callback — exchanges code for tokens, sets cookies
async fn callback(
    State(client): State<Arc<OcasClient>>,
    Query(params): Query<CallbackParams>,
    headers: axum::http::HeaderMap,
) -> Result<Response, Response> {
    let cookies = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let savedstate = getcookie(cookies, "ocas_state")
        .ok_or_else(|| autherror("missing state cookie"))?;

    if savedstate != params.state {
        return Err(autherror("state mismatch"));
    }

    let verifier = getcookie(cookies, "ocas_verifier")
        .ok_or_else(|| autherror("missing verifier cookie"))?;

    let creds = STANDARD.encode(format!("{}:{}", client.config.clientid, client.config.clientsecret));

    let tokenresp = client
        .http
        .post(format!("{}/token", client.config.url))
        .header("authorization", format!("Basic {creds}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
            params.code, client.config.callbackurl, verifier,
        ))
        .send()
        .await
        .map_err(|e| autherror(&e.to_string()))?;

    if !tokenresp.status().is_success() {
        let body = tokenresp.text().await.unwrap_or_default();
        tracing::error!("token exchange failed: {body}");
        return Err(autherror("token exchange failed"));
    }

    let tokens: TokenResponse = tokenresp
        .json()
        .await
        .map_err(|e| autherror(&e.to_string()))?;

    let mut resp = Redirect::to(&client.config.afterlogin).into_response();
    let h = resp.headers_mut();
    h.append(SET_COOKIE, cookie("ocas_access", &tokens.access, 900));
    h.append(SET_COOKIE, cookie("ocas_refresh", &tokens.refresh, 30 * 86400));
    h.append(SET_COOKIE, clearcookie("ocas_state"));
    h.append(SET_COOKIE, clearcookie("ocas_verifier"));
    Ok(resp)
}

/// GET /auth/logout — revokes refresh token, clears cookies
async fn logout(
    State(client): State<Arc<OcasClient>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let cookies = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(refresh) = getcookie(cookies, "ocas_refresh") {
        let _ = client
            .http
            .post(format!("{}/token/revoke", client.config.url))
            .header("content-type", "application/json")
            .body(format!(r#"{{"refresh":"{refresh}"}}"#))
            .send()
            .await;
    }

    let mut resp = Redirect::to(&client.config.afterlogout).into_response();
    let h = resp.headers_mut();
    h.append(SET_COOKIE, clearcookie("ocas_access"));
    h.append(SET_COOKIE, clearcookie("ocas_refresh"));
    resp
}

fn genverifier() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkcechallenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

fn genstate() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(bytes)
}

fn cookie(name: &str, value: &str, maxage: i64) -> axum::http::HeaderValue {
    format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={maxage}")
        .parse()
        .unwrap()
}

fn clearcookie(name: &str) -> axum::http::HeaderValue {
    format!("{name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
        .parse()
        .unwrap()
}

fn getcookie(cookies: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    cookies
        .split(';')
        .map(|c| c.trim())
        .find(|c| c.starts_with(&prefix))?
        .strip_prefix(&prefix)
        .map(|s| s.to_string())
}

fn autherror(msg: &str) -> Response {
    let body = serde_json::json!({ "error": "unauthorized", "message": msg });
    (axum::http::StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
}
