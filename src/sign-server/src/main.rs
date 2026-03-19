use anyhow::Result;
use axum::{routing::get, routing::post, Router};
use nautilus_enclave::EnclaveKeyPair;
use sign_server::common::{get_attestation, health_check, sign_name};
use sign_server::AppState;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Generate Ed25519 keypair — NSM entropy in enclave, OsRng locally
    let eph_kp = EnclaveKeyPair::generate();

    let state = Arc::new(AppState { eph_kp });

    info!("Starting sign-server...");

    run_api_server(state).await
}

async fn run_api_server(state: Arc<AppState>) -> Result<()> {
    use tower_http::cors::{CorsLayer, Any};

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    let app = Router::new()
        .route("/", get(ping))
        .route("/health", get(health_check))
        .route("/get_attestation", get(get_attestation))
        .route("/sign_name", post(sign_name))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await?;
    info!("sign-server listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

async fn ping() -> &'static str {
    "Nautilus TEE Sign Server Ready!"
}
