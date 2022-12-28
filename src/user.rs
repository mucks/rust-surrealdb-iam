use anyhow::{anyhow, Result};
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::db::query;

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password: String,
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Claims {
    pub user_id: String,
    pub roles: Vec<String>,
}

impl User {
    pub async fn create(username: &str, password: &str) -> Result<Self> {
        let index = format!("user:{}", username);
        let sql =
            "CREATE {0} SET username = {1}, password = crypto::argon2::generate({2}), roles = [];";
        let resp = query(sql, vec![&index, username, password]).await?;
        Ok(Self {
            id: index,
            username: username.into(),
            password: password.into(),
            roles: vec![],
        })
    }

    pub async fn login(username: &str, password: &str) -> Result<String> {
        let user_id = format!("user:{}", username);
        let user = User::get(&user_id).await?;
        let sql = "
            LET $user_pass = (SELECT password FROM {0});
            SELECT * FROM crypto::argon2::compare($user_pass[0], {1});";
        let resp = query(sql, vec![&user.id, password]).await?;
        let is_valid = resp[1].get_first_result()?.as_bool();

        if is_valid != Some(true) {
            return Err(anyhow!("Invalid password"));
        }

        let claims = Claims {
            user_id: user.id,
            roles: user.roles,
        };

        let secret = crate::env::jwt_secret();
        let key = EncodingKey::from_secret(secret.as_bytes());

        let jwt = jsonwebtoken::encode(&Header::default(), &claims, &key)?;

        Ok(jwt)
    }

    pub async fn get(id: &str) -> Result<Self> {
        let resp = query("SELECT * FROM {0}", vec![id]).await?;

        let user_result = resp[0].get_first_result()?;
        let user = serde_json::from_value(user_result)?;
        Ok(user)
    }

    pub async fn add_role(&mut self, role_id: String) -> Result<()> {
        query("UPDATE {0} SET roles += {1};", vec![&self.id, &role_id]).await?;
        self.roles.push(role_id);
        Ok(())
    }

    pub async fn delete(self) -> Result<()> {
        let sql = query("DELETE {0};", vec![&self.id]).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn user() {
        let name = "cargotest_user";
        let user_id = format!("user:{}", name);

        //delete user if it already exists
        if let Ok(user) = User::get(&user_id).await {
            user.delete().await.unwrap();
        }

        let _ = User::create(name, name).await.unwrap();
        let mut user = User::get(&user_id).await.unwrap();
        user.add_role("role:admin".to_string()).await.unwrap();

        assert!(user.roles.iter().any(|r| r == "role:admin"));
        assert_eq!(user.username, name);

        user.delete().await.unwrap();

        assert!(User::get(name).await.is_err());
    }

    #[tokio::test]
    async fn user_login() {
        let name = "cargotest_user_login";

        dotenvy::dotenv().ok();
        let user_id = format!("user:{}", name);

        let _ = User::create(name, name).await.unwrap();
        let token = User::login(name, name).await.unwrap();
        assert!(token.len() > 10);
        let user = User::get(&user_id).await.unwrap();
        user.delete().await.unwrap();
    }
}
