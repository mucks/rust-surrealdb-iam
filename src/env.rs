use crate::user::CreateUserDto;

pub fn jwt_secret() -> String {
    std::env::var("JWT_SECRET").expect("NO JWT_SECRET SET")
}

pub fn validate_envs() {
    jwt_secret();
    salt();
    database_connection_info();
    admin_user();
}

pub fn salt() -> String {
    std::env::var("SALT").expect("NO SALT SET")
}

pub fn admin_user() -> CreateUserDto {
    use std::env::var;
    CreateUserDto {
        username: var("ADMIN_USERNAME").expect("NO ADMIN_USERNAME SET"),
        password: var("ADMIN_PASSWORD").expect("NO ADMIN_PASSWORD SET"),
        email: var("ADMIN_EMAIL").expect("NO ADMIN_EMAIL SET"),
    }
}

pub struct DatabaseConnectionInfo {
    pub host: String,
    pub username: String,
    pub password: String,
    pub namespace: String,
    pub database: String,
}

pub fn database_connection_info() -> DatabaseConnectionInfo {
    DatabaseConnectionInfo {
        host: std::env::var("DB_HOST").expect("NO DB_HOST SET"),
        username: std::env::var("DB_USERNAME").expect("NO DB_USERNAME SET"),
        password: std::env::var("DB_PASSWORD").expect("NO DB_PASSWORD SET"),
        namespace: std::env::var("DB_NAMESPACE").expect("NO DB_NAMESPACE SET"),
        database: std::env::var("DB_DATABASE").expect("NO DB_DATABASE SET"),
    }
}
