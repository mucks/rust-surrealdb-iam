use hyper::StatusCode;

use super::model::*;
use crate::{error::MyResult, web_server::AppState};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

pub struct RoleApi;

impl RoleApi {
    pub fn routes() -> Router<AppState> {
        Router::new()
            .route("/add", post(Self::add))
            .route("/:id", get(Self::get).delete(Self::delete))
            .route("/all", get(Self::get_all))
    }

    async fn add(
        State(mut state): State<AppState>,
        Path(realm): Path<String>,
        Json(payload): Json<CreateRoleDto>,
    ) -> MyResult<impl IntoResponse> {
        state.role_ctrl.set_realm(&realm);
        let role = state.role_ctrl.create(&payload).await?;
        Ok((StatusCode::OK, Json(role)))
    }

    async fn get(
        State(mut state): State<AppState>,
        Path((realm, id)): Path<(String, String)>,
    ) -> MyResult<impl IntoResponse> {
        state.role_ctrl.set_realm(&realm);
        let user = state.role_ctrl.get(&id).await?;
        Ok((StatusCode::OK, Json(user)))
    }

    async fn delete(
        State(mut state): State<AppState>,
        Path((realm, id)): Path<(String, String)>,
    ) -> MyResult<impl IntoResponse> {
        state.role_ctrl.set_realm(&realm);
        state.role_ctrl.delete(&id).await?;
        Ok((StatusCode::OK, id))
    }

    async fn get_all(
        State(mut state): State<AppState>,
        Path(realm): Path<String>,
    ) -> MyResult<impl IntoResponse> {
        state.role_ctrl.set_realm(&realm);
        let role = state.role_ctrl.get_all().await?;
        Ok((StatusCode::OK, Json(role)))
    }
}
