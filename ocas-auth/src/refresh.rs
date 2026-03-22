use std::sync::Arc;

use axum::extract::Request;
use axum::http::header::SET_COOKIE;
use axum::middleware::Next;
use axum::response::Response;
use serde::Deserialize;

use crate::OcasClient;

#[derive(Deserialize)]
struct RefreshResponse {
    access: String,
    refresh: String,
}

/// middleware that silently refreshes expired access tokens
pub async fn refreshmw(
    req: Request,
    next: Next,
) -> Response {
    let client = req.extensions().get::<Arc<OcasClient>>().cloned();

    let cookies = req
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let hasaccess = cookies
        .split(';')
        .any(|c| c.trim().starts_with("ocas_access="));

    if hasaccess || client.is_none() {
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

fn extractcookie(cookies: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    cookies
        .split(';')
        .map(|c| c.trim())
        .find(|c| c.starts_with(&prefix))?
        .strip_prefix(&prefix)
        .map(|s| s.to_string())
}
