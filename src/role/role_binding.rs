use anyhow::Result;
use serde::{Deserialize, Serialize};
use surrealdb_http_client_rs::{Client, ResponseExt};

#[derive(Serialize, Deserialize, Debug)]
pub struct RoleBinding {
    pub id: String,
    #[serde(rename = "in")]
    pub role_id: String,
    #[serde(rename = "out")]
    pub user_id: String,
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
