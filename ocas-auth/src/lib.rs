pub mod blocklist;
pub mod claims;
pub mod config;
pub mod error;
mod extractor;
pub mod jwks;
#[cfg(feature = "mock")]
pub mod mock;
pub mod refresh;
pub mod roles;
pub mod router;

use std::sync::Arc;
use std::time::Duration;

pub use claims::{Claims, Faculty, PersonType, Student};
pub use config::OcasConfig;
pub use error::AuthError;
pub use roles::{AppRoleLoader, AuthenticatedUser};

/// the main client — holds config, jwks cache, blocklist cache, http client
pub struct OcasClient {
    pub config: OcasConfig,
    pub jwks: Arc<jwks::JwksCache>,
    pub blocklist: Arc<blocklist::BlocklistCache>,
    pub http: reqwest::Client,
}

impl OcasClient {
    /// creates a new client and fetches the initial jwks
    pub async fn new(config: OcasConfig) -> Arc<Self> {
        let http = reqwest::Client::new();
        let jwks = Arc::new(jwks::JwksCache::new(&config.url, http.clone()));
        let blocklist = Arc::new(blocklist::BlocklistCache::new(&config.url, http.clone()));

        if let Err(e) = jwks.fetch().await {
            tracing::warn!("initial jwks fetch failed: {e}");
        }

        if config.blocklist {
            if let Err(e) = blocklist.fetch().await {
                tracing::warn!("initial blocklist fetch failed: {e}");
            }
            blocklist.startpolling(Duration::from_secs(60));
        }

        Arc::new(Self {
            config,
            jwks,
            blocklist,
            http,
        })
    }

    /// returns the drop-in auth router for /auth/*
    pub fn authrouter(self: &Arc<Self>) -> axum::Router {
        router::authrouter(Arc::clone(self))
    }

    /// returns a layer that injects OcasClient into request extensions
    pub fn layer(self: &Arc<Self>) -> axum::Extension<Arc<Self>> {
        axum::Extension(Arc::clone(self))
    }
}
