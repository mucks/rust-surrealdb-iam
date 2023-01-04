use anyhow::Result;
use serde::{Deserialize, Serialize};
use surrealdb_http_client_rs::{Client, ResponseExt};

#[derive(Serialize, Deserialize, Debug)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub realm: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RoleBinding {
    pub id: String,
    #[serde(rename = "in")]
    pub role_id: String,
    #[serde(rename = "out")]
    pub user_id: String,
}

pub struct CreateRoleDto {
    pub name: String,
    pub description: String,
}

impl RoleBinding {
    pub async fn init(client: &Client) -> Result<()> {
        client
            .query("DEFINE INDEX role_binding_unique ON role_binding FIELDS in, out UNIQUE")
            .send()
            .await?;
        Ok(())
    }
    pub async fn delete_by_role(client: &Client, role_id: &str) -> Result<()> {
        client
            .query("DELETE role_binding WHERE in = $role_id")
            .bind("role_id", role_id)
            .send()
            .await?;
        Ok(())
    }
    pub async fn delete_by_user(client: &Client, user_id: &str) -> Result<()> {
        client
            .query("DELETE role_binding WHERE out = $user_id")
            .bind("user_id", user_id)
            .send()
            .await?;
        Ok(())
    }

    pub async fn get_roles_from_user(client: &Client, user_id: &str) -> Result<Vec<String>> {
        let role_ids: Vec<RoleBinding> = client
            .query("SELECT * from role_binding where out = $user_id")
            .bind("user_id", user_id)
            .send()
            .await?
            .get_results()?;
        Ok(role_ids.iter().map(|r| r.role_id.clone()).collect())
    }

    pub async fn add_role_to_user(client: &Client, user_id: &str, role_id: &str) -> Result<()> {
        client
            .query("RELATE $role_id->role_binding->$user_id")
            .bind("role_id", role_id)
            .bind("user_id", user_id)
            .send()
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct RoleApi {
    client: Client,
    realm: String,
}

impl RoleApi {
    pub async fn new(client: Client) -> Result<Self> {
        let s = Self {
            client,
            realm: "master".into(),
        };
        s.init().await?;
        Ok(s)
    }

    pub fn set_realm(&mut self, realm: &str) {
        self.realm = realm.into();
    }

    pub async fn init(&self) -> Result<()> {
        self.client
            .query(
                "
            DEFINE TABLE role SCHEMAFULL;

            DEFINE FIELD name ON TABLE role TYPE string;
            DEFINE FIELD description ON TABLE role TYPE string;
            DEFINE FIELD realm ON TABLE role TYPE string;
            
            DEFINE INDEX name_unique ON TABLE role FIELDS name, realm UNIQUE;
            ",
            )
            .send()
            .await?;
        Ok(())
    }

    pub async fn add_default_roles(&self) {
        let _ = self
            .create(&CreateRoleDto {
                name: "admin".into(),
                description: "Admin role".into(),
            })
            .await;
        let _ = self
            .create(&CreateRoleDto {
                name: "guest".into(),
                description: "Guest role".into(),
            })
            .await;
    }

    pub async fn get_by_name(&self, name: &str) -> Result<Role> {
        self.client
            .query("SELECT * FROM role WHERE name = $name AND realm = $realm;")
            .bind("name", name)
            .bind("realm", &self.realm)
            .send()
            .await?
            .get_result()
    }

    pub async fn create(&self, dto: &CreateRoleDto) -> Result<Role> {
        self.client
            .query("CREATE role SET name = $name, description = $description, realm = $realm;")
            .bind("name", &dto.name)
            .bind("description", &dto.description)
            .bind("realm", &self.realm)
            .send()
            .await?
            .get_result()
    }
    pub async fn delete(&self, id: &str) -> Result<()> {
        RoleBinding::delete_by_role(&self.client, id).await?;
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
    use crate::{db::init_client, role::RoleApi};

    #[tokio::test]
    async fn create_role() {
        dotenvy::dotenv().ok();
        let mut api = RoleApi::new(init_client().await.unwrap()).await.unwrap();
        api.set_realm("test");

        let role = api
            .create(&crate::role::CreateRoleDto {
                name: "test".into(),
                description: "Test role".into(),
            })
            .await
            .unwrap();
        assert_eq!(role.name, "test");
        assert_eq!(role.description, "Test role");

        api.delete(&role.id).await.unwrap();
    }
}
