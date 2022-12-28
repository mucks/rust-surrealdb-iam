use env::validate_envs;
use user::User;

mod db;
mod env;
mod role;
mod user;
mod web_server;

#[tokio::main]
async fn main() {
    // load environment variables from .env file
    dotenvy::dotenv().ok();
    validate_envs();
}
