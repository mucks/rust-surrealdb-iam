use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Role {
    pub name: String,
    pub description: String,
}

impl Role {}
