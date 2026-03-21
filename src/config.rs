use std::env;

use jsonwebtoken::{DecodingKey, EncodingKey};

pub struct Config {
    pub dburl: String,
    pub host: String,
    pub port: u16,
    pub privatekey: EncodingKey,
    pub publickey: DecodingKey,
    pub publickeypem: String,
}

impl Config {
    pub fn load() -> Self {
        let privpem = env::var("JWT_PRIVATE_KEY")
            .expect("JWT_PRIVATE_KEY must be set")
            .replace("\\n", "\n");
        let pubpem = env::var("JWT_PUBLIC_KEY")
            .expect("JWT_PUBLIC_KEY must be set")
            .replace("\\n", "\n");

        Self {
            dburl: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "3000".into())
                .parse()
                .expect("PORT must be a number"),
            privatekey: EncodingKey::from_rsa_pem(privpem.as_bytes())
                .expect("invalid RSA private key"),
            publickey: DecodingKey::from_rsa_pem(pubpem.as_bytes())
                .expect("invalid RSA public key"),
            publickeypem: pubpem,
        }
    }
}
