use anyhow::Result;
use surrealdb_http_client_rs::Client;

pub async fn init_client() -> Result<Client> {
    let db = crate::env::database_connection_info();
    let cfg = surrealdb_http_client_rs::ClientConfig {
        host: db.host,
        username: db.username,
        password: db.password,
        namespace: db.namespace,
        database: db.database,
    };
    let client = surrealdb_http_client_rs::Client::new(cfg)?;
    Ok(client)
}
