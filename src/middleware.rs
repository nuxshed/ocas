use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::AppError;
use crate::AppState;

/// rate limiting middleware extracts ip from connectinfo
pub async fn ratelimit(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if !state.limiter.check(addr.ip()) {
        return Err(AppError::TooManyRequests);
    }
    Ok(next.run(req).await)
}
