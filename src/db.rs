use anyhow::{anyhow, Result};
use hyper::{Body, Client, Method, Request};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SurrealDbResponse {
    pub time: String,
    pub status: String,
    pub result: Option<Vec<serde_json::Value>>,
}

impl SurrealDbResponse {
    pub fn get_first_result(&self) -> Result<serde_json::Value> {
        if let Some(result) = &self.result {
            if let Some(first_result) = result.first() {
                return Ok(first_result.clone());
            }
        }
        Err(anyhow!("No first result found"))
    }
}

//TODO: make this function more sql injection proof
pub async fn query(sql: &str, params: Vec<&str>) -> Result<Vec<SurrealDbResponse>> {
    let mut sql = sql.to_string();
    for (i, param) in params.iter().enumerate() {
        let escaped_param = &format!("{}{}{}", '"', param, '"');
        sql = sql.replace(&format!("{{{}}}", i), escaped_param);
    }
    match hyper_post_sql(sql.clone()).await {
        Ok(resp) => Ok(resp),
        Err(e) => Err(anyhow!("{}\nsql: '{}'", e, sql)),
    }
}

async fn hyper_post_sql(sql: String) -> Result<Vec<SurrealDbResponse>> {
    let url = "http://127.0.0.1:8000/sql";

    let client = Client::new();

    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("Authorization", "Basic cm9vdDpyb290")
        .header("Accept", "application/json")
        .header("Content-Type", "text/plain")
        .header("NS", "test")
        .header("DB", "test")
        .body(Body::from(sql))?;

    let resp = client.request(req).await?;
    let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
    let out = String::from_utf8(body_bytes.to_vec())?;
    let resp: Vec<SurrealDbResponse> = match serde_json::from_str(&out) {
        Ok(resp) => resp,
        Err(_) => return Err(anyhow!("{}", out)),
    };

    if resp[0].status != "OK" {
        return Err(anyhow!("{}", out));
    }

    Ok(resp)
}
