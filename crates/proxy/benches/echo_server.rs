use axum::Router;
use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::any;
use clap::Parser;
use http_body_util::BodyExt;
use hyper::StatusCode;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(name = "echo-server", about = "Minimal echo server for load testing")]
struct Args {
    /// Listen address
    #[arg(long, default_value = "127.0.0.1:8090")]
    listen: String,
}

async fn echo_handler(req: Request) -> impl IntoResponse {
    let body = req.into_body().collect().await.unwrap().to_bytes();
    (StatusCode::OK, [("content-type", "application/json")], body)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let app = Router::new()
        .route("/", any(echo_handler))
        .route("/{*path}", any(echo_handler));
    let listener = TcpListener::bind(&args.listen).await.unwrap();
    eprintln!("echo-server listening on {}", args.listen);
    axum::serve(listener, app).await.unwrap();
}
