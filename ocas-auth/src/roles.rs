use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::claims::Claims;
use crate::error::AuthError;

/// trait for loading app-specific roles from the local database
pub trait AppRoleLoader: Send + Sync {
    type Role: Send + Sync;
    type Error: IntoResponse + Send;

    fn loadrole(
        &self,
        userid: Uuid,
    ) -> impl std::future::Future<Output = Result<Self::Role, Self::Error>> + Send;
}

/// an authenticated user with claims and an app-specific role
pub struct AuthenticatedUser<R> {
    pub claims: Claims,
    pub role: R,
}

impl<S, R> FromRequestParts<S> for AuthenticatedUser<R>
where
    S: AppRoleLoader<Role = R> + Send + Sync,
    R: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;

        let role = state
            .loadrole(claims.sub)
            .await
            .map_err(|_| AuthError::Unauthorized("failed to load role".into()))?;

        Ok(AuthenticatedUser { claims, role })
    }
}
