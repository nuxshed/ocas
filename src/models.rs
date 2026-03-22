use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub rollnum: Option<String>,
    pub passhash: String,
    pub batch: Option<i32>,
    pub branch: Option<String>,
    pub r#type: String,
    pub verified: bool,
    pub banned: bool,
    pub createdat: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub struct RefreshToken {
    pub id: Uuid,
    pub tokenhash: String,
    pub userid: Uuid,
    pub clientid: Option<String>,
    pub expiresat: DateTime<Utc>,
    pub createdat: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub struct Client {
    pub clientid: String,
    pub secrethash: String,
    pub redirecturis: Vec<String>,
    pub name: String,
    pub createdat: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub struct AuthCode {
    pub code: String,
    pub clientid: String,
    pub userid: Uuid,
    pub redirecturi: String,
    pub codechallenge: String,
    pub expiresat: DateTime<Utc>,
    pub used: bool,
}
