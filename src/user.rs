use anyhow::{anyhow, Result};
use argon2::Config;
use hyper::StatusCode;
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use surrealdb_rs::{net::HttpClient, param::PatchOp, Surreal};

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post, MethodRouter},
    Json, Router,
};

use crate::{error::MyResult, web_server::AppState};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct User {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    pub username: String,
    pub password: String,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct CreateUserDto {
    pub username: String,
    pub password: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct IgnoreResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    pub username: String,
    pub roles: Vec<String>,
}

#[derive(Clone)]
pub struct UserApi {
    client: Surreal<HttpClient>,
    namespace: String,
}

impl UserApi {
    pub fn routes() -> Router<AppState> {
        Router::new()
            .route("/add", post(Self::add))
            .route("/:username", get(Self::api_get))
    }

    async fn add(
        State(mut state): State<AppState>,
        Path(namespace): Path<String>,
        Json(payload): Json<CreateUserDto>,
    ) -> MyResult<impl IntoResponse> {
        state.user_api.set_namespace(&namespace);
        let user = state.user_api.create(&payload).await?;
        Ok((StatusCode::OK, Json(user)))
    }

    async fn api_get(
        State(mut state): State<AppState>,
        Path((namespace, username)): Path<(String, String)>,
    ) -> MyResult<impl IntoResponse> {
        state.user_api.set_namespace(&namespace);
        let user = state.user_api.get(&username).await?;
        Ok((StatusCode::OK, Json(user)))
    }

    pub fn new(client: Surreal<HttpClient>) -> Self {
        Self {
            client,
            namespace: "master".into(),
        }
    }
    pub fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.into();
    }
    fn table_name(&self) -> String {
        format!("{}_user", &self.namespace)
    }

    pub async fn create(&self, dto: &CreateUserDto) -> Result<User> {
        //TODO: the squery binding here is buggy and needs to be fixed in the library
        //
        // self.client
        //     .query(
        //         "
        //     DEFINE FIELD email ON TABLE $t TYPE string;
        //     DEFINE FIELD created_at ON TABLE $t VALUE time::now();
        //     DEFINE INDEX email_unique ON TABLE $t COLUMNS email UNIQUE;
        //         ",
        //     )
        //     .bind("table", &self.table_name())
        //     .await?;

        let password_hash = argon2::hash_encoded(
            dto.password.as_bytes(),
            crate::env::salt().as_bytes(),
            &Config::default(),
        )?;

        let user: User = self
            .client
            .create((self.table_name(), dto.username.clone()))
            .content(User {
                id: None,
                username: dto.username.clone(),
                password: password_hash,
                email: "".to_string(),
                roles: vec![],
            })
            .await?;

        println!("user: {:?}", user);

        Ok(user)
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<String> {
        let user: Option<User> = self.client.select(("user", username)).await?;

        if user.is_none() {
            return Err(anyhow!("Invalid username or password"));
        }
        let user = user.unwrap();

        let is_valid = argon2::verify_encoded(&user.password, password.as_bytes())?;

        if !is_valid {
            return Err(anyhow!("Invalid username or password"));
        }

        let claims = Claims {
            username: user.username,
            roles: user.roles,
        };

        let secret = crate::env::jwt_secret();
        let key = EncodingKey::from_secret(secret.as_bytes());

        let jwt = jsonwebtoken::encode(&Header::default(), &claims, &key)?;

        Ok(jwt)
    }

    pub async fn get(&self, username: &str) -> Result<User> {
        let user: User = self.client.select((self.table_name(), username)).await?;
        Ok(user)
    }

    pub async fn add_role(&self, username: &str, role_id: &str) -> Result<()> {
        let user_role_update: IgnoreResponse = self
            .client
            .update((self.table_name(), username))
            .patch(PatchOp::add("/roles", [role_id]))
            .await?;
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        self.client.delete((self.table_name(), id)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::db::init_client;

    use super::*;

    #[tokio::test]
    async fn user() {
        dotenvy::dotenv().ok();
        let mut api = UserApi::new(init_client().await.unwrap());
        api.set_namespace("test");
        let name = "cargotest_user";

        let user = api
            .create(&CreateUserDto {
                username: name.to_string(),
                password: name.to_string(),
                email: name.to_string(),
            })
            .await
            .unwrap();
        api.add_role(&user.username, "role:admin").await.unwrap();
        let user = api.get(&user.username).await.unwrap();

        assert!(user.roles.iter().any(|r| r == "role:admin"));
        assert_eq!(user.username, name);

        api.delete(&user.username).await.unwrap();

        assert!(api.get(&user.username).await.is_err());
    }

    #[tokio::test]
    async fn user_login() {
        dotenvy::dotenv().ok();
        let mut api = UserApi::new(init_client().await.unwrap());
        api.set_namespace("test");
        let name = "cargotest_user_login";

        let user = api
            .create(&CreateUserDto {
                username: name.to_string(),
                password: name.to_string(),
                email: name.to_string(),
            })
            .await
            .unwrap();
        let token = api.login(name, name).await.unwrap();
        assert!(token.len() > 10);
        api.delete(&user.username).await.unwrap();
    }
}
