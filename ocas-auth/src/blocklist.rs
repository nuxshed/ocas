use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Deserialize)]
struct BlocklistResponse {
    jti: Vec<Uuid>,
}

/// caches blocked jtis fetched from /blocklist
pub struct BlocklistCache {
    jtis: RwLock<HashSet<Uuid>>,
    url: String,
    http: reqwest::Client,
}

impl BlocklistCache {
    pub fn new(baseurl: &str, http: reqwest::Client) -> Self {
        Self {
            jtis: RwLock::new(HashSet::new()),
            url: format!("{baseurl}/blocklist"),
            http,
        }
    }

    /// fetches the blocklist from ocas
    pub async fn fetch(&self) -> Result<(), String> {
        let resp: BlocklistResponse = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;

        *self.jtis.write().await = resp.jti.into_iter().collect();
        Ok(())
    }

    /// checks if a jti is in the blocklist
    pub async fn contains(&self, jti: &Uuid) -> bool {
        self.jtis.read().await.contains(jti)
    }

    /// starts a background task that polls the blocklist every interval
    pub fn startpolling(self: &Arc<Self>, interval: Duration) {
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = cache.fetch().await {
                    tracing::warn!("blocklist fetch failed: {e}");
                }
            }
        });
    }
}
