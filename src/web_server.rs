use axum::Router;
use std::net::SocketAddr;

pub async fn start() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let app = Router::new();

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
