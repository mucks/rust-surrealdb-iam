use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use surrealdb_http_client_rs::{Client, ResponseExt};

use crate::{error::MyResult, web_server::AppState};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password: String,
    pub email: String,
    pub roles: Vec<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Debug, Default)]
pub struct GetUserDto {
    pub username: String,
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
    client: Client,
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

    pub async fn new(client: Client) -> Result<Self> {
        let s = Self {
            client,
            namespace: "master".into(),
        };
        s.init().await?;
        Ok(s)
    }
    pub fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.into();
    }

    pub async fn init(&self) -> Result<()> {
        self.client
            .query(
                "
            DEFINE TABLE user SCHEMAFULL;

            DEFINE FIELD username ON TABLE user TYPE string;
            DEFINE FIELD email ON TABLE user TYPE string;
            DEFINE FIELD namespace ON TABLE user TYPE string;
            DEFINE FIELD password ON TABLE user TYPE string;
            DEFINE FIELD roles ON TABLE user TYPE array;
            DEFINE FIELD roles.* ON TABLE user TYPE string;

            DEFINE FIELD created_at ON TABLE user VALUE time::now();
            DEFINE INDEX email_unique ON TABLE user FIELDS email, namespace UNIQUE;
            DEFINE INDEX username_unique ON TABLE user FIELDS username, namespace UNIQUE;
                ",
            )
            .send()
            .await?;
        Ok(())
    }

    pub async fn create(&self, dto: &CreateUserDto) -> Result<User> {
        let resp = self
            .client
            .query("CREATE user SET username = $username, email = $email, namespace = $namespace, password = crypto::argon2::generate($password), roles = [];")
            .bind("username", &dto.username)
            .bind("email", &dto.email)
            .bind("namespace", &self.namespace)
            .bind("password", &dto.password)
            .send()
            .await?;
        println!("resp: {:?}", resp);
        let user: User = resp.get_result()?;

        println!("user: {:?}", user);

        Ok(user)
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<String> {
        let user: User = self
            .client
            .query("SELECT * FROM user WHERE $username = username AND crypto::argon2::compare(password, $password);")
            .bind("username", username)
            .bind("password", password)
            .send()
            .await?
            .get_result().map_err(|_| anyhow!("Invalid username or password"))?;

        let claims = Claims {
            username: user.username,
            roles: user.roles,
        };

        let secret = crate::env::jwt_secret();
        let key = EncodingKey::from_secret(secret.as_bytes());

        let jwt = jsonwebtoken::encode(&Header::default(), &claims, &key)?;

        Ok(jwt)
    }

    pub async fn get_by_username(&self, username: &str) -> Result<User> {
        let user: User = self
            .client
            .query("SELECT * FROM user WHERE username = $username AND namespace = $namespace;")
            .bind("username", username)
            .bind("namespace", &self.namespace)
            .send()
            .await?
            .get_result()?;
        println!("username_user: {:?}", user);
        Ok(user)
    }

    pub async fn get(&self, id: &str) -> Result<User> {
        let user: User = self
            .client
            .query("SELECT * FROM $id;")
            .bind("id", id)
            .send()
            .await?
            .get_result()?;
        Ok(user)
    }

    pub async fn add_role(&self, id: &str, role_id: &str) -> Result<()> {
        println!("add_role: {}", id);
        self.client
            .query("UPDATE $id SET roles += $role_id;")
            .bind("id", id)
            .bind("role_id", role_id)
            .send()
            .await?;
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        self.client
            .query("DELETE $id;")
            .bind("id", id)
            .send()
            .await?;
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
        let mut api = UserApi::new(init_client().await.unwrap()).await.unwrap();
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
        api.add_role(&user.id, "role:admin").await.unwrap();
        let user = api.get(&user.id).await.unwrap();

        assert!(user.roles.iter().any(|r| r == "role:admin"));
        assert_eq!(user.username, name);

        api.delete(&user.id).await.unwrap();

        assert!(api.get_by_username(&user.username).await.is_err());
    }

    #[tokio::test]
    async fn user_login() {
        dotenvy::dotenv().ok();
        let mut api = UserApi::new(init_client().await.unwrap()).await.unwrap();
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
        api.delete(&user.id).await.unwrap();
    }
}
