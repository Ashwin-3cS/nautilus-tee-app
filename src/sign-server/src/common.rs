use crate::AppState;
use crate::EnclaveError;
use axum::{extract::State, Json};
use fastcrypto::traits::Signer;
use fastcrypto::{encoding::Encoding, traits::ToFromBytes};
use fastcrypto::{encoding::Hex, traits::KeyPair as FcKeyPair};
use fastcrypto::ed25519::Ed25519KeyPair;
#[cfg(feature = "aws")]
use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
#[cfg(feature = "aws")]
use aws_nitro_enclaves_nsm_api::driver;
#[cfg(feature = "aws")]
use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::sync::Arc;
use tracing::info;

// ── Intent message types (matches Nautilus/Sui pattern) ───────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct IntentMessage<T: Serialize> {
    pub intent: IntentScope,
    pub timestamp_ms: u64,
    pub data: T,
}

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum IntentScope {
    Generic = 0,
    SignName = 1,
}

impl<T: Serialize + std::fmt::Debug> IntentMessage<T> {
    pub fn new(data: T, timestamp_ms: u64, intent: IntentScope) -> Self {
        Self { data, timestamp_ms, intent }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProcessedDataResponse<T> {
    pub response: T,
    pub signature: String,
}

/// Sign the BCS bytes of the payload with the enclave keypair.
pub fn to_signed_response<T: Serialize + Clone>(
    kp: &Ed25519KeyPair,
    payload: T,
    timestamp_ms: u64,
    intent: IntentScope,
) -> ProcessedDataResponse<IntentMessage<T>> {
    let intent_msg = IntentMessage {
        intent,
        timestamp_ms,
        data: payload.clone(),
    };

    let signing_payload = bcs::to_bytes(&intent_msg).expect("should not fail");
    let sig = kp.sign(&signing_payload);
    ProcessedDataResponse {
        response: intent_msg,
        signature: Hex::encode(sig),
    }
}

// ── GET /get_attestation ──────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAttestationResponse {
    pub attestation: String,
}

#[cfg(feature = "aws")]
pub async fn get_attestation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GetAttestationResponse>, EnclaveError> {
    info!("get_attestation called");

    let pk = state.eph_kp.public();
    let fd = driver::nsm_init();

    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: None,
        public_key: Some(ByteBuf::from(pk.as_bytes().to_vec())),
    };

    let response = driver::nsm_process_request(fd, request);
    match response {
        NsmResponse::Attestation { document } => {
            driver::nsm_exit(fd);
            Ok(Json(GetAttestationResponse {
                attestation: Hex::encode(document),
            }))
        }
        _ => {
            driver::nsm_exit(fd);
            Err(EnclaveError::GenericError("unexpected NSM response".to_string()))
        }
    }
}

#[cfg(not(feature = "aws"))]
pub async fn get_attestation(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<GetAttestationResponse>, EnclaveError> {
    info!("get_attestation called (mock — aws feature not enabled)");
    Ok(Json(GetAttestationResponse {
        attestation: "mock_attestation_document".to_string(),
    }))
}

// ── GET /health ───────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub public_key: String,
    pub status: String,
}

pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthCheckResponse>, EnclaveError> {
    let pk = state.eph_kp.public();
    Ok(Json(HealthCheckResponse {
        public_key: Hex::encode(pk.as_bytes()),
        status: "ok".to_string(),
    }))
}

// ── POST /sign_name ──────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignNameRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedName {
    pub name: String,
    pub message: String,
}

pub async fn sign_name(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignNameRequest>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<SignedName>>>, EnclaveError> {
    info!("sign_name called for: {}", req.name);

    let timestamp_ms = chrono::Utc::now().timestamp_millis() as u64;

    let signed_name = SignedName {
        name: req.name.clone(),
        message: format!("Hello {}! This message was signed inside a Nitro Enclave.", req.name),
    };

    let response = to_signed_response(
        &state.eph_kp,
        signed_name,
        timestamp_ms,
        IntentScope::SignName,
    );

    Ok(Json(response))
}
