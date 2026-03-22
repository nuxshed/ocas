use serde::{Deserialize, Serialize};
use std::ops::Deref;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PersonType {
    Student,
    Faculty,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claims {
    pub sub: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollnum: Option<String>,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub r#type: PersonType,
    pub exp: i64,
    pub iat: i64,
    pub jti: Uuid,
}

/// extractor that rejects non-student users
pub struct Student(pub Claims);

impl Deref for Student {
    type Target = Claims;
    fn deref(&self) -> &Claims {
        &self.0
    }
}

/// extractor that rejects non-faculty users
pub struct Faculty(pub Claims);

impl Deref for Faculty {
    type Target = Claims;
    fn deref(&self) -> &Claims {
        &self.0
    }
}
