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
    // Mirror the request's Content-Type back so the response body is
    // labelled as what it actually is (form-encoded, csv, …). The proxy's
    // response-side content-type router reads this header, and a wrong
    // label produces spurious parse failures on non-JSON benches.
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    (StatusCode::OK, [("content-type", content_type)], body)
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
