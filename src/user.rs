use anyhow::{anyhow, Result};
use argon2::Config;
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use surrealdb_rs::{net::HttpClient, param::PatchOp, Surreal};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct User {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    pub username: String,
    pub password: String,
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct IgnoreResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    pub username: String,
    pub roles: Vec<String>,
}

pub struct UserApi {
    client: Surreal<HttpClient>,
}

impl UserApi {
    pub fn new(client: Surreal<HttpClient>) -> Self {
        Self { client }
    }
    pub async fn create(&self, username: &str, password: &str) -> Result<User> {
        let password_hash = argon2::hash_encoded(
            password.as_bytes(),
            crate::env::salt().as_bytes(),
            &Config::default(),
        )?;

        let user: User = self
            .client
            .create(("user", username))
            .content(User {
                id: None,
                username: username.to_string(),
                password: password_hash,
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
        println!("get user: {}", username);
        let user: User = self.client.select(("user", username)).await?;
        Ok(user)
    }

    pub async fn add_role(&self, username: &str, role_id: &str) -> Result<()> {
        let user_role_update: IgnoreResponse = self
            .client
            .update(("user", username))
            .patch(PatchOp::add("/roles", [role_id]))
            .await?;
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        self.client.delete(("user", id)).await?;
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
        let api = UserApi::new(init_client().await.unwrap());
        let name = "cargotest_user";

        let user = api.create(name, name).await.unwrap();
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
        let api = UserApi::new(init_client().await.unwrap());
        let name = "cargotest_user_login";

        let user = api.create(name, name).await.unwrap();
        let token = api.login(name, name).await.unwrap();
        assert!(token.len() > 10);
        api.delete(&user.username).await.unwrap();
    }
}
