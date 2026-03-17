use anyhow::Result;
use axum::{routing::get, routing::post, Router};
use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair};
use sign_server::common::{get_attestation, health_check, sign_name};
use sign_server::AppState;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Generate Ed25519 keypair — NSM entropy in enclave, thread_rng locally
    let eph_kp = if std::env::var("ENCLAVE_MODE").is_ok() {
        #[cfg(feature = "aws")]
        {
            use aws_nitro_enclaves_nsm_api::driver;
            use aws_nitro_enclaves_nsm_api::api::{Request, Response};

            let fd = driver::nsm_init();
            let request = Request::GetRandom;
            match driver::nsm_process_request(fd, request) {
                Response::GetRandom { random } => {
                    driver::nsm_exit(fd);
                    let seed: [u8; 32] = random[..32].try_into().expect("Invalid entropy length");
                    use rand::SeedableRng;
                    let mut rng = rand::rngs::StdRng::from_seed(seed);
                    Ed25519KeyPair::generate(&mut rng)
                }
                _ => {
                    driver::nsm_exit(fd);
                    Ed25519KeyPair::generate(&mut rand::thread_rng())
                }
            }
        }
        #[cfg(not(feature = "aws"))]
        {
            Ed25519KeyPair::generate(&mut rand::thread_rng())
        }
    } else {
        Ed25519KeyPair::generate(&mut rand::thread_rng())
    };

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
