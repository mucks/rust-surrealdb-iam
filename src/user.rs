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

use crate::{error::MyResult, role::RoleBinding, web_server::AppState};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password: String,
    pub email: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Debug, Default)]
pub struct GetUserDto {
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Deserialize, Debug, Default, Clone)]
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

pub struct UserApiHandler;

impl UserApiHandler {
    pub fn routes() -> Router<AppState> {
        Router::new()
            .route("/add", post(Self::add))
            .route("/:id", get(Self::get).delete(Self::delete))
            .route("/all", get(Self::get_all))
    }

    async fn add(
        State(mut state): State<AppState>,
        Path(realm): Path<String>,
        Json(payload): Json<CreateUserDto>,
    ) -> MyResult<impl IntoResponse> {
        state.user_api.set_realm(&realm);
        let user = state.user_api.create(&payload).await?;
        Ok((StatusCode::OK, Json(user)))
    }

    async fn get(
        State(mut state): State<AppState>,
        Path((realm, id)): Path<(String, String)>,
    ) -> MyResult<impl IntoResponse> {
        state.user_api.set_realm(&realm);
        let user = state.user_api.get(&id).await?;
        Ok((StatusCode::OK, Json(user)))
    }

    async fn delete(
        State(mut state): State<AppState>,
        Path((realm, id)): Path<(String, String)>,
    ) -> MyResult<impl IntoResponse> {
        state.user_api.set_realm(&realm);
        state.user_api.delete(&id).await?;
        Ok((StatusCode::OK, id))
    }

    async fn get_all(
        State(mut state): State<AppState>,
        Path(realm): Path<String>,
    ) -> MyResult<impl IntoResponse> {
        state.user_api.set_realm(&realm);
        let user = state.user_api.get_all().await?;
        Ok((StatusCode::OK, Json(user)))
    }
}

#[derive(Clone)]
pub struct UserApi {
    client: Client,
    realm: String,
}

impl UserApi {
    pub async fn new(client: Client) -> Result<Self> {
        let s = Self {
            client,
            realm: "master".into(),
        };
        s.init().await?;
        let _ = s.init_admin().await;
        Ok(s)
    }
    pub fn set_realm(&mut self, realm: &str) {
        self.realm = realm.into();
    }

    async fn init_admin(&self) -> Result<()> {
        let user = self.create(&crate::env::admin_user()).await?;
        RoleBinding::add_role_to_user(&self.client, &user.id, "role:admin").await?;
        Ok(())
    }

    pub async fn init(&self) -> Result<()> {
        self.client
            .query(
                "
            DEFINE TABLE user SCHEMAFULL;

            DEFINE FIELD username ON TABLE user TYPE string;
            DEFINE FIELD email ON TABLE user TYPE string;
            DEFINE FIELD realm ON TABLE user TYPE string;
            DEFINE FIELD password ON TABLE user TYPE string;
            DEFINE FIELD created_at ON TABLE user VALUE time::now();

            DEFINE INDEX email_unique ON TABLE user FIELDS email, realm UNIQUE;
            DEFINE INDEX username_unique ON TABLE user FIELDS username, realm UNIQUE;
                ",
            )
            .send()
            .await?;
        Ok(())
    }

    pub async fn create(&self, dto: &CreateUserDto) -> Result<User> {
        let resp = self
            .client
            .query("CREATE user SET username = $username, email = $email, realm = $realm, password = crypto::argon2::generate($password), roles = [];")
            .bind("username", &dto.username)
            .bind("email", &dto.email)
            .bind("realm", &self.realm)
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
            roles: RoleBinding::get_roles_from_user(&self.client, &user.id).await?,
        };

        let secret = crate::env::jwt_secret();
        let key = EncodingKey::from_secret(secret.as_bytes());

        let jwt = jsonwebtoken::encode(&Header::default(), &claims, &key)?;

        Ok(jwt)
    }

    pub async fn get_by_username(&self, username: &str) -> Result<User> {
        let user: User = self
            .client
            .query("SELECT * FROM user WHERE username = $username AND realm = $realm;")
            .bind("username", username)
            .bind("realm", &self.realm)
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

    pub async fn get_all(&self) -> Result<User> {
        let user: User = self
            .client
            .query("SELECT * FROM user WHERE realm = $realm;")
            .bind("realm", &self.realm)
            .send()
            .await?
            .get_result()?;
        Ok(user)
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        RoleBinding::delete_by_user(&self.client, id).await?;
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
    use crate::{db::init_client, role::RoleApi, web_server::init_state};

    use super::*;

    #[tokio::test]
    async fn api_user_add() {
        dotenvy::dotenv().ok();

        let state = init_state().await.unwrap();
        let dto = CreateUserDto {
            username: "api_user_add_test".into(),
            email: "api_user_add_test@localhost".into(),
            password: "test".into(),
        };

        let user =
            UserApiHandler::add(State(state.clone()), Path("test".into()), Json(dto.clone()))
                .await
                .unwrap();

        let bytes = hyper::body::to_bytes(user.into_response().into_body())
            .await
            .unwrap();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        let user: User = serde_json::from_str(&s).unwrap();

        assert_eq!(&user.username, &dto.username);
        assert_eq!(&user.email, &dto.email);

        UserApiHandler::delete(State(state), Path(("test".into(), user.id)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn user() {
        dotenvy::dotenv().ok();

        let mut api = UserApi::new(init_client().await.unwrap()).await.unwrap();
        let mut role_api = RoleApi::new(init_client().await.unwrap()).await.unwrap();
        RoleBinding::init(&api.client).await.unwrap();

        api.set_realm("test");
        role_api.set_realm("test");
        role_api.add_default_roles().await;
        let name = "cargotest_user";

        let user = api
            .create(&CreateUserDto {
                username: name.to_string(),
                password: name.to_string(),
                email: name.to_string(),
            })
            .await
            .unwrap();

        let role = role_api.get_by_name("admin").await.unwrap();
        RoleBinding::add_role_to_user(&api.client, &user.id, &role.id)
            .await
            .unwrap();

        //adding same role twice should fail
        assert!(
            RoleBinding::add_role_to_user(&api.client, &user.id, &role.id)
                .await
                .is_err()
        );

        let roles = RoleBinding::get_roles_from_user(&api.client, &user.id)
            .await
            .unwrap();

        println!("roles: {:?}", roles);

        assert!(roles.iter().any(|r| r == &role.id));
        assert_eq!(user.username, name);

        api.delete(&user.id).await.unwrap();

        assert!(api.get_by_username(&user.username).await.is_err());
    }

    #[tokio::test]
    async fn user_login() {
        dotenvy::dotenv().ok();
        let mut api = UserApi::new(init_client().await.unwrap()).await.unwrap();
        api.set_realm("test");
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
