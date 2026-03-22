#![cfg(feature = "mock")]

use axum::routing::get;
use axum::{Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Serialize;
use std::sync::LazyLock;
use uuid::Uuid;

use crate::claims::{Claims, PersonType};

struct DevKeypair {
    encoding: EncodingKey,
    publicpem: String,
    publicn: String,
    publice: String,
}

#[derive(Serialize)]
struct MockJwks {
    keys: Vec<MockJwk>,
}

#[derive(Serialize)]
struct MockJwk {
    kty: &'static str,
    alg: &'static str,
    #[serde(rename = "use")]
    use_: &'static str,
    n: String,
    e: String,
}

static DEVKEYS: LazyLock<DevKeypair> = LazyLock::new(|| {
    let mut rng = rand::thread_rng();
    let privkey = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate dev key");
    let privpem = privkey
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("failed to encode private key");
    let pubpem = privkey
        .to_public_key()
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("failed to encode public key");
    let publickey = privkey.to_public_key();

    DevKeypair {
        encoding: EncodingKey::from_rsa_pem(privpem.as_bytes()).unwrap(),
        publicpem: pubpem,
        publicn: URL_SAFE_NO_PAD.encode(publickey.n().to_bytes_be()),
        publice: URL_SAFE_NO_PAD.encode(publickey.e().to_bytes_be()),
    }
});

/// mock claims builder for testing
pub struct MockClaims {
    pub claims: Claims,
}

/// creates mock student claims
pub fn student(rollnum: &str, branch: &str) -> MockClaims {
    let batch: i32 = rollnum
        .get(..4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2021);

    MockClaims {
        claims: Claims {
            sub: Uuid::new_v4(),
            rollnum: Some(rollnum.to_string()),
            email: format!("test.{rollnum}@students.iiit.ac.in"),
            batch: Some(batch),
            branch: Some(branch.to_string()),
            r#type: PersonType::Student,
            exp: chrono::Utc::now().timestamp() + 900,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::new_v4(),
        },
    }
}

/// creates mock faculty claims
pub fn faculty(email: &str) -> MockClaims {
    MockClaims {
        claims: Claims {
            sub: Uuid::new_v4(),
            rollnum: None,
            email: email.to_string(),
            batch: None,
            branch: None,
            r#type: PersonType::Faculty,
            exp: chrono::Utc::now().timestamp() + 900,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::new_v4(),
        },
    }
}

impl MockClaims {
    /// signs the claims into a jwt using the dev key
    pub fn token(&self) -> String {
        let header = Header::new(Algorithm::RS256);
        encode(&header, &self.claims, &DEVKEYS.encoding).expect("failed to sign mock token")
    }

    /// returns an authorization header value
    pub fn header(&self) -> (axum::http::HeaderName, axum::http::HeaderValue) {
        let token = self.token();
        (
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        )
    }
}

/// returns the dev public key pem for building a mock jwks
pub fn publickeypem() -> &'static str {
    &DEVKEYS.publicpem
}

/// returns a mock jwks router for local testing
pub fn mockjwks() -> Router {
    Router::new().route("/jwks.json", get(jwks))
}

async fn jwks() -> Json<MockJwks> {
    Json(MockJwks {
        keys: vec![mockjwk()],
    })
}

fn mockjwk() -> MockJwk {
    MockJwk {
        kty: "RSA",
        alg: "RS256",
        use_: "sig",
        n: DEVKEYS.publicn.clone(),
        e: DEVKEYS.publice.clone(),
    }
}
