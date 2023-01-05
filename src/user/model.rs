use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password: String,
    pub email: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Debug, Default)]
pub struct GetUserDto {
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct CreateUserDto {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct LoginDto {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct IgnoreResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    pub username: String,
    pub roles: Vec<String>,
}
