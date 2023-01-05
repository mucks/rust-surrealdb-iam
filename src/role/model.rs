use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub realm: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateRoleDto {
    pub name: String,
    pub description: String,
}
