use axum::Router;
use std::net::SocketAddr;

use crate::{
    db::init_client,
    role::{RoleApi, RoleBinding, RoleController},
    user::{UserApi, UserController},
};

#[derive(Clone)]
pub struct AppState {
    pub user_ctrl: UserController,
    pub role_ctrl: RoleController,
}

pub async fn init_state() -> anyhow::Result<AppState> {
    let client = init_client().await?;
    RoleBinding::init(&client).await?;
    let role_ctrl = RoleController::new(client.clone()).await?;
    role_ctrl.add_default_roles().await;
    let user_ctrl = UserController::new(client.clone()).await?;
    let state = AppState {
        user_ctrl,
        role_ctrl,
    };
    Ok(state)
}

pub async fn start() -> anyhow::Result<()> {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // initialize state
    let state = init_state().await?;

    let api = Router::new()
        .nest("/:namespace/user", UserApi::routes())
        .nest("/:namespace/role", RoleApi::routes());
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
