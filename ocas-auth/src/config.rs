use std::env;

/// configuration for the ocas auth client
pub struct OcasConfig {
    pub url: String,
    pub clientid: String,
    pub clientsecret: String,
    pub callbackurl: String,
    pub blocklist: bool,
    pub afterlogin: String,
    pub afterlogout: String,
}

impl OcasConfig {
    /// loads config from environment variables
    pub fn fromenv() -> Self {
        Self {
            url: env::var("OCAS_URL").expect("OCAS_URL must be set"),
            clientid: env::var("OCAS_CLIENT_ID").expect("OCAS_CLIENT_ID must be set"),
            clientsecret: env::var("OCAS_CLIENT_SECRET").expect("OCAS_CLIENT_SECRET must be set"),
            callbackurl: env::var("OCAS_CALLBACK_URL").expect("OCAS_CALLBACK_URL must be set"),
            blocklist: env::var("OCAS_BLOCKLIST")
                .map(|v| v != "false")
                .unwrap_or(true),
            afterlogin: env::var("OCAS_AFTER_LOGIN").unwrap_or_else(|_| "/".into()),
            afterlogout: env::var("OCAS_AFTER_LOGOUT").unwrap_or_else(|_| "/".into()),
        }
    }
}
