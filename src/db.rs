use anyhow::Result;
use surrealdb_rs::{net::HttpClient, param::Database, protocol::Https, Surreal};

const NUM: usize = 100_000;

pub async fn init_client() -> Result<Surreal<HttpClient>> {
    let client = Surreal::connect::<Https>("surrealdb.mucks.dev")
        .with_capacity(NUM)
        .await?;

    // Signin as a namespace, database, or root user
    client
        .signin(Database {
            username: "iam_root",
            password: "uoMsUSznAivc8RYnv9aB",
            namespace: "dev",
            database: "iam",
        })
        .await?;

    // Select a specific namespace and database
    client.use_ns("dev").use_db("iam").await?;

    Ok(client)
}
