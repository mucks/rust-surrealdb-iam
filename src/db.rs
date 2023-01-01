use anyhow::Result;
use surrealdb_rs::{net::HttpClient, param::Database, protocol::Https, Surreal};

const NUM: usize = 100_000;

pub async fn init_client() -> Result<Surreal<HttpClient>> {
    let db = crate::env::database_connection_info();
    let client = Surreal::connect::<Https>(db.host)
        .with_capacity(NUM)
        .await?;

    // Signin as a namespace, database, or root user
    client
        .signin(Database {
            username: &db.username,
            password: &db.password,
            namespace: &db.namespace,
            database: &db.database,
        })
        .await?;

    // Select a specific namespace and database
    client.use_ns(&db.namespace).use_db(&db.database).await?;

    Ok(client)
}
