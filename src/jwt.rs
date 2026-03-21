use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::models::User;

const ACCESS_TTL: i64 = 900; // 15 min

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollnum: Option<String>,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub r#type: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: Uuid,
}

/// signs a jwt for the given user. returns (token, jti)
pub fn sign(user: &User, key: &EncodingKey) -> Result<(String, Uuid), AppError> {
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4();

    let claims = Claims {
        sub: user.id,
        rollnum: user.rollnum.clone(),
        email: user.email.clone(),
        batch: user.batch,
        branch: user.branch.clone(),
        r#type: user.r#type.clone(),
        exp: now + ACCESS_TTL,
        iat: now,
        jti,
    };

    let header = Header::new(Algorithm::RS256);
    let token = encode(&header, &claims, key)?;
    Ok((token, jti))
}

/// verifies and decodes a jwt
#[allow(dead_code)]
pub fn verify(token: &str, key: &DecodingKey) -> Result<Claims, AppError> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "sub"]);

    decode::<Claims>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|e| AppError::Unauthorized(e.to_string()))
}

#[derive(Serialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

#[derive(Serialize)]
pub struct Jwk {
    pub kty: String,
    pub r#use: String,
    pub alg: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

/// builds the jwks response from the pem-encoded public key
pub fn jwks(pem: &str) -> JwksResponse {
    let pubkey = RsaPublicKey::from_public_key_pem(pem).expect("invalid public key PEM");

    let n = URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());

    JwksResponse {
        keys: vec![Jwk {
            kty: "RSA".into(),
            r#use: "sig".into(),
            alg: "RS256".into(),
            kid: "ocas-1".into(),
            n,
            e,
        }],
    }
}
