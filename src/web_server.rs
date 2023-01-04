use axum::Router;
use std::net::SocketAddr;

use crate::{db::init_client, user::UserApi};

#[derive(Clone)]
pub struct AppState {
    pub user_api: UserApi,
}

pub async fn start() -> anyhow::Result<()> {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let state = AppState {
        user_api: UserApi::new(init_client().await?).await?,
    };

    let api = Router::new().nest("/:namespace/user", UserApi::routes());

    let app = Router::new().nest("/api/v1", api).with_state(state);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}
