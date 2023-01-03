use axum::response::IntoResponse;
use hyper::StatusCode;

pub type MyResult<T> = std::result::Result<T, MyError>;

pub struct MyError {
    pub err: String,
}

impl From<anyhow::Error> for MyError {
    fn from(err: anyhow::Error) -> Self {
        Self {
            err: err.to_string(),
        }
    }
}

impl IntoResponse for MyError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, self.err).into_response()
    }
}
