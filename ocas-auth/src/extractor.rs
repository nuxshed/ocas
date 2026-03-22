use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::claims::{Claims, Faculty, PersonType, Student};
use crate::error::AuthError;
use crate::OcasClient;

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let client = parts
            .extensions
            .get::<Arc<OcasClient>>()
            .ok_or_else(|| AuthError::Unauthorized("ocas client not configured".into()))?
            .clone();

        let token = tokenfrombearerparts(parts)
            .or_else(|| tokenfromcookie(parts))
            .ok_or_else(|| AuthError::Unauthorized("no access token".into()))?;

        let claims = client
            .jwks
            .verify(&token)
            .await
            .map_err(AuthError::Unauthorized)?;

        if client.config.blocklist && client.blocklist.contains(&claims.jti).await {
            return Err(AuthError::Unauthorized("token revoked".into()));
        }

        Ok(claims)
    }
}

impl<S> FromRequestParts<S> for Student
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;
        if claims.r#type != PersonType::Student {
            return Err(AuthError::Forbidden("students only".into()));
        }
        Ok(Student(claims))
    }
}

impl<S> FromRequestParts<S> for Faculty
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;
        if claims.r#type != PersonType::Faculty {
            return Err(AuthError::Forbidden("faculty only".into()));
        }
        Ok(Faculty(claims))
    }
}

/// extracts bearer token from Authorization header
fn tokenfrombearerparts(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

/// extracts access token from cookie
fn tokenfromcookie(parts: &Parts) -> Option<String> {
    let cookies = parts.headers.get("cookie")?.to_str().ok()?;
    cookies
        .split(';')
        .map(|c| c.trim())
        .find(|c| c.starts_with("ocas_access="))?
        .strip_prefix("ocas_access=")
        .map(|s| s.to_string())
}
