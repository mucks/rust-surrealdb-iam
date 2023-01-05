use super::model::*;
use anyhow::{anyhow, Result};
use jsonwebtoken::{EncodingKey, Header};

use surrealdb_http_client_rs::{Client, ResponseExt};

use crate::role::RoleBinding;

#[derive(Clone)]
pub struct UserController {
    client: Client,
    realm: String,
}

impl UserController {
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
    use crate::{db::init_client, role::RoleController};

    use super::*;

    #[tokio::test]
    async fn user() {
        dotenvy::dotenv().ok();

        let mut ctrl = UserController::new(init_client().await.unwrap())
            .await
            .unwrap();
        let mut role_ctrl = RoleController::new(init_client().await.unwrap())
            .await
            .unwrap();
        RoleBinding::init(&ctrl.client).await.unwrap();

        ctrl.set_realm("test");
        role_ctrl.set_realm("test");
        role_ctrl.add_default_roles().await;
        let name = "cargotest_user";

        let user = ctrl
            .create(&CreateUserDto {
                username: name.to_string(),
                password: name.to_string(),
                email: name.to_string(),
            })
            .await
            .unwrap();

        let role = role_ctrl.get_by_name("admin").await.unwrap();
        RoleBinding::add_role_to_user(&ctrl.client, &user.id, &role.id)
            .await
            .unwrap();

        //adding same role twice should fail
        assert!(
            RoleBinding::add_role_to_user(&ctrl.client, &user.id, &role.id)
                .await
                .is_err()
        );

        let roles = RoleBinding::get_roles_from_user(&ctrl.client, &user.id)
            .await
            .unwrap();

        println!("roles: {:?}", roles);

        assert!(roles.iter().any(|r| r == &role.id));
        assert_eq!(user.username, name);

        ctrl.delete(&user.id).await.unwrap();

        assert!(ctrl.get_by_username(&user.username).await.is_err());
    }

    #[tokio::test]
    async fn user_login() {
        dotenvy::dotenv().ok();
        let mut ctrl = UserController::new(init_client().await.unwrap())
            .await
            .unwrap();
        ctrl.set_realm("test");
        let name = "cargotest_user_login";

        let user = ctrl
            .create(&CreateUserDto {
                username: name.to_string(),
                password: name.to_string(),
                email: name.to_string(),
            })
            .await
            .unwrap();
        let token = ctrl.login(name, name).await.unwrap();
        assert!(token.len() > 10);
        ctrl.delete(&user.id).await.unwrap();
    }
}
