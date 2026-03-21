mod blocklist;
mod config;
mod db;
mod error;
mod extract;
mod hash;
mod jwt;
mod middleware;
mod models;
mod ratelimit;
mod routes;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::{middleware as axummw, Router};
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::blocklist::Blocklist;
use crate::config::Config;
use crate::jwt::JwksResponse;
use crate::ratelimit::RateLimiter;

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub blocklist: Blocklist,
    pub jwks: JwksResponse,
    pub limiter: RateLimiter,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::load();
    let db = db::initpool(&config.dburl).await;
    let jwks = jwt::jwks(&config.publickeypem);
    let blocklist = Blocklist::new();
    let limiter = RateLimiter::new(10, Duration::from_secs(60));

    let addr = format!("{}:{}", config.host, config.port);

    let state = Arc::new(AppState {
        db,
        config,
        blocklist,
        jwks,
        limiter,
    });

    let limited = Router::new()
        .route("/register", post(routes::register::register))
        .route("/login", post(routes::login::login))
        .layer(axummw::from_fn_with_state(
            state.clone(),
            middleware::ratelimit,
        ));

    let open = Router::new()
        .route("/token/refresh", post(routes::token::refresh))
        .route("/token/revoke", post(routes::token::revoke))
        .route("/jwks.json", get(routes::discovery::jwks))
        .route(
            "/.well-known/openid-configuration",
            get(routes::discovery::openid),
        )
        .route("/blocklist", get(routes::discovery::blocklist))
        .route("/health", get(routes::health::health));

    let app = Router::new()
        .merge(limited)
        .merge(open)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("listening on {addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
