use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::claims::Claims;

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
struct JwkKey {
    n: String,
    e: String,
}

/// caches the ocas public key fetched from /jwks.json
pub struct JwksCache {
    key: RwLock<Option<DecodingKey>>,
    url: String,
    http: reqwest::Client,
}

impl JwksCache {
    pub fn new(baseurl: &str, http: reqwest::Client) -> Self {
        Self {
            key: RwLock::new(None),
            url: format!("{baseurl}/jwks.json"),
            http,
        }
    }

    /// fetches the jwks and caches the decoding key
    pub async fn fetch(&self) -> Result<(), String> {
        let resp: JwksResponse = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;

        let jwk = resp.keys.first().ok_or("no keys in jwks")?;

        let n = URL_SAFE_NO_PAD
            .decode(&jwk.n)
            .map_err(|e| e.to_string())?;
        let e = URL_SAFE_NO_PAD
            .decode(&jwk.e)
            .map_err(|e| e.to_string())?;

        let key = DecodingKey::from_rsa_raw_components(&n, &e);
        *self.key.write().await = Some(key);
        Ok(())
    }

    /// verifies a jwt against the cached key, refetching once on failure
    pub async fn verify(&self, token: &str) -> Result<Claims, String> {
        if self.key.read().await.is_none() {
            self.fetch().await?;
        }

        match self.trydecode(token).await {
            Ok(claims) => Ok(claims),
            Err(_) => {
                self.fetch().await?;
                self.trydecode(token).await
            }
        }
    }

    async fn trydecode(&self, token: &str) -> Result<Claims, String> {
        let guard = self.key.read().await;
        let key = guard.as_ref().ok_or("no jwks key cached")?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "sub"]);

        jsonwebtoken::decode::<Claims>(token, key, &validation)
            .map(|data| data.claims)
            .map_err(|e| e.to_string())
    }
}
