use db::init_client;
use env::validate_envs;
use user::UserApi;

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
    let client = init_client().await.unwrap();
    let api = UserApi::new(client);
    api.create("test", "test").await.unwrap();
}
