use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// hashes a password with argon2id
pub fn hashpw(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AppError::Internal(e.to_string()))
}

/// verifies a password against an argon2id hash
pub fn verifypw(password: &str, hash: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(hash).map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// generates a random 32-byte hex token
pub fn gentoken() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// sha256 hash for storing tokens
pub fn hashtoken(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

/// generates a readable client id (8 hex chars)
pub fn genclientid() -> String {
    let bytes: [u8; 4] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// generates a random client secret (32 bytes, hex)
pub fn gensecret() -> String {
    gentoken()
}
