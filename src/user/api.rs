use hyper::StatusCode;

use super::model::*;
use crate::{error::MyResult, web_server::AppState};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

pub struct UserApi;

impl UserApi {
    pub fn routes() -> Router<AppState> {
        Router::new()
            .route("/add", post(Self::add))
            .route("/login", post(Self::login))
            .route("/:id", get(Self::get).delete(Self::delete))
            .route("/all", get(Self::get_all))
    }

    async fn add(
        State(mut state): State<AppState>,
        Path(realm): Path<String>,
        Json(payload): Json<CreateUserDto>,
    ) -> MyResult<impl IntoResponse> {
        state.user_ctrl.set_realm(&realm);
        let user = state.user_ctrl.create(&payload).await?;
        Ok((StatusCode::OK, Json(user)))
    }

    async fn login(
        State(mut state): State<AppState>,
        Path(realm): Path<String>,
        Json(payload): Json<LoginDto>,
    ) -> MyResult<impl IntoResponse> {
        state.user_ctrl.set_realm(&realm);
        let user = state
            .user_ctrl
            .login(&payload.username, &payload.password)
            .await?;
        Ok((StatusCode::OK, Json(user)))
    }

    async fn get(
        State(mut state): State<AppState>,
        Path((realm, id)): Path<(String, String)>,
    ) -> MyResult<impl IntoResponse> {
        state.user_ctrl.set_realm(&realm);
        let user = state.user_ctrl.get(&id).await?;
        Ok((StatusCode::OK, Json(user)))
    }

    async fn delete(
        State(mut state): State<AppState>,
        Path((realm, id)): Path<(String, String)>,
    ) -> MyResult<impl IntoResponse> {
        state.user_ctrl.set_realm(&realm);
        state.user_ctrl.delete(&id).await?;
        Ok((StatusCode::OK, id))
    }

    async fn get_all(
        State(mut state): State<AppState>,
        Path(realm): Path<String>,
    ) -> MyResult<impl IntoResponse> {
        state.user_ctrl.set_realm(&realm);
        let user = state.user_ctrl.get_all().await?;
        Ok((StatusCode::OK, Json(user)))
    }
}

#[cfg(test)]
mod test {
    use axum::{
        extract::{Path, State},
        response::IntoResponse,
        Json,
    };

    use crate::{
        user::{
            api::UserApi,
            model::{CreateUserDto, User},
        },
        web_server::init_state,
    };

    #[tokio::test]
    async fn api_user_add() {
        dotenvy::dotenv().ok();

        let state = init_state().await.unwrap();
        let dto = CreateUserDto {
            username: "api_user_add_test".into(),
            email: "api_user_add_test@localhost".into(),
            password: "test".into(),
        };

        let user = UserApi::add(State(state.clone()), Path("test".into()), Json(dto.clone()))
            .await
            .unwrap();

        let bytes = hyper::body::to_bytes(user.into_response().into_body())
            .await
            .unwrap();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        let user: User = serde_json::from_str(&s).unwrap();

        assert_eq!(&user.username, &dto.username);
        assert_eq!(&user.email, &dto.email);

        UserApi::delete(State(state), Path(("test".into(), user.id)))
            .await
            .unwrap();
    }
}
