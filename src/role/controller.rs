use super::{model::*, role_binding::RoleBinding};
use anyhow::Result;
use surrealdb_http_client_rs::{Client, ResponseExt};

#[derive(Clone)]
pub struct RoleController {
    client: Client,
    realm: String,
}

impl RoleController {
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

    pub async fn get(&self, id: &str) -> Result<Role> {
        let user: Role = self
            .client
            .query("SELECT * FROM $id;")
            .bind("id", id)
            .send()
            .await?
            .get_result()?;
        Ok(user)
    }

    pub async fn get_all(&self) -> Result<Vec<Role>> {
        self.client
            .query("SELECT * FROM role;")
            .send()
            .await?
            .get_results()
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
    use crate::{
        db::init_client,
        role::{controller::RoleController, model::CreateRoleDto},
    };

    #[tokio::test]
    async fn create_role() {
        dotenvy::dotenv().ok();
        let mut ctrl = RoleController::new(init_client().await.unwrap())
            .await
            .unwrap();
        ctrl.set_realm("test");

        let role = ctrl
            .create(&CreateRoleDto {
                name: "test".into(),
                description: "Test role".into(),
            })
            .await
            .unwrap();
        assert_eq!(role.name, "test");
        assert_eq!(role.description, "Test role");

        ctrl.delete(&role.id).await.unwrap();
    }
}
