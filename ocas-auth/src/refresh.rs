use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use axum::extract::Request;
use axum::http::header::SET_COOKIE;
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use serde::Deserialize;

use crate::OcasClient;

#[derive(Deserialize)]
struct RefreshResponse {
    access: String,
    refresh: String,
}

#[derive(Deserialize)]
struct AccessClaims {
    exp: i64,
}

/// middleware that silently refreshes expired access tokens
pub async fn refreshmw(mut req: Request, next: Next) -> Response {
    let client = req.extensions().get::<Arc<OcasClient>>().cloned();

    let cookies = req
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let accesstoken = extractcookie(&cookies, "ocas_access");
    let refreshneeded = accesstoken
        .as_deref()
        .map(accessexpired)
        .unwrap_or(true);

    if !refreshneeded || client.is_none() {
        return next.run(req).await;
    }

    let client = client.unwrap();

    let refreshtoken = match extractcookie(&cookies, "ocas_refresh") {
        Some(t) => t,
        None => return next.run(req).await,
    };

    let result = client
        .http
        .post(format!("{}/token/refresh", client.config.url))
        .header("content-type", "application/json")
        .body(format!(r#"{{"refresh":"{refreshtoken}"}}"#))
        .send()
        .await;

    let tokenresp = match result {
        Ok(r) if r.status().is_success() => match r.json::<RefreshResponse>().await {
            Ok(t) => t,
            Err(_) => return next.run(req).await,
        },
        _ => return next.run(req).await,
    };

    setcookies(req.headers_mut(), &cookies, &tokenresp.access, &tokenresp.refresh);

    let mut resp = next.run(req).await;
    let h = resp.headers_mut();

    let access_cookie = format!(
        "ocas_access={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900",
        tokenresp.access,
    );
    let refresh_cookie = format!(
        "ocas_refresh={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        tokenresp.refresh,
        30 * 86400,
    );

    if let Ok(v) = access_cookie.parse() {
        h.append(SET_COOKIE, v);
    }
    if let Ok(v) = refresh_cookie.parse() {
        h.append(SET_COOKIE, v);
    }

    resp
}

fn accessexpired(token: &str) -> bool {
    let payload = match token.split('.').nth(1) {
        Some(part) => part,
        None => return true,
    };

    let bytes = match URL_SAFE_NO_PAD.decode(payload) {
        Ok(bytes) => bytes,
        Err(_) => return true,
    };

    let claims: AccessClaims = match serde_json::from_slice(&bytes) {
        Ok(claims) => claims,
        Err(_) => return true,
    };

    claims.exp <= Utc::now().timestamp()
}

fn setcookies(headers: &mut axum::http::HeaderMap, cookies: &str, access: &str, refresh: &str) {
    let mut values = Vec::new();
    let mut hasaccess = false;
    let mut hasrefresh = false;

    for cookie in cookies.split(';').map(|c| c.trim()).filter(|c| !c.is_empty()) {
        if cookie.starts_with("ocas_access=") {
            values.push(format!("ocas_access={access}"));
            hasaccess = true;
        } else if cookie.starts_with("ocas_refresh=") {
            values.push(format!("ocas_refresh={refresh}"));
            hasrefresh = true;
        } else {
            values.push(cookie.to_string());
        }
    }

    if !hasaccess {
        values.push(format!("ocas_access={access}"));
    }
    if !hasrefresh {
        values.push(format!("ocas_refresh={refresh}"));
    }

    if let Ok(value) = values.join("; ").parse() {
        headers.insert(axum::http::header::COOKIE, value);
    }
}

fn extractcookie(cookies: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    cookies
        .split(';')
        .map(|c| c.trim())
        .find(|c| c.starts_with(&prefix))?
        .strip_prefix(&prefix)
        .map(|s| s.to_string())
}
