use env::validate_envs;

mod db;
mod env;
mod error;
mod role;
mod user;
mod web_server;

#[tokio::main]
async fn main() {
    // load environment variables from .env file
    dotenvy::dotenv().ok();
    validate_envs();
    web_server::start().await.unwrap();
}
