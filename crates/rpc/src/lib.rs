//! RPC endpoints for interacting with the Q-EVM node.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{sse::Event, sse::Sse, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use qevm_core::{DemoOutcome, Node, NodeEvent, NodeStatus};
use qevm_types::{GasAnalysis, OpHash, UserOperationHex};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::instrument;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("node error: {0}")]
    Node(String),
    #[error("invalid op hash: {0}")]
    InvalidHash(String),
}

impl IntoResponse for RpcError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            RpcError::Node(message) => (StatusCode::INTERNAL_SERVER_ERROR, message),
            RpcError::InvalidHash(message) => (StatusCode::BAD_REQUEST, message),
        };
        (status, Json(message)).into_response()
    }
}

#[derive(Clone)]
pub struct RpcState {
    node: Arc<Node>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct SubmitResponse {
    accepted: bool,
    op_hash: String,
}

pub fn router(node: Arc<Node>) -> Router {
    let state = RpcState { node };
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/mempool", get(mempool))
        .route("/user-operations", post(submit))
        .route("/receipts/:hash", get(receipt))
        .route("/events", get(events))
        // Measured on-chain gas vs metered native ML-DSA gas, from live receipts
        .route("/gas-analysis", get(gas_analysis))
        .route("/demo", post(demo))
        .with_state(state)
}

pub async fn serve(addr: SocketAddr, node: Arc<Node>) -> anyhow::Result<()> {
    let app = router(node);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// GET /gas-analysis
/// Aggregates every receipt this node produced: EVM-measured Groth16 verifier
/// gas vs metered native ML-DSA gas. `measured` is false until the first op.
async fn gas_analysis(State(state): State<RpcState>) -> Json<GasAnalysis> {
    Json(state.node.gas_analysis().await)
}

#[derive(Debug, Deserialize)]
struct DemoRequest {
    count: Option<usize>,
}

/// POST /demo {"count": n}
/// Generates n fresh ML-DSA keys, signs and submits one op per key through the
/// real bundler/prover pipeline, then bundles them.
#[instrument(skip_all)]
async fn demo(
    State(state): State<RpcState>,
    Json(request): Json<DemoRequest>,
) -> Result<Json<DemoOutcome>, RpcError> {
    let count = request.count.unwrap_or(8).clamp(1, 64);
    let outcome = state
        .node
        .run_demo(count, 1)
        .await
        .map_err(|e| RpcError::Node(e.to_string()))?;
    Ok(Json(outcome))
}

#[instrument(skip_all)]
async fn status(State(state): State<RpcState>) -> Result<Json<NodeStatus>, RpcError> {
    let status = state
        .node
        .status()
        .await
        .map_err(|e| RpcError::Node(e.to_string()))?;
    Ok(Json(status))
}

#[instrument(skip_all)]
async fn mempool(State(state): State<RpcState>) -> Result<Json<Vec<UserOperationHex>>, RpcError> {
    let ops = state
        .node
        .list_mempool(100)
        .await
        .map_err(|e| RpcError::Node(e.to_string()))?;
    let response = ops.iter().map(UserOperationHex::from_user_op).collect();
    Ok(Json(response))
}

#[instrument(skip_all)]
async fn submit(
    State(state): State<RpcState>,
    Json(payload): Json<UserOperationHex>,
) -> Result<Json<SubmitResponse>, RpcError> {
    let op = payload.to_user_op().map_err(|e| RpcError::Node(e.to_string()))?;
    let outcome = state
        .node
        .submit_user_operation(op)
        .await
        .map_err(|e| RpcError::Node(e.to_string()))?;
    Ok(Json(SubmitResponse {
        accepted: outcome.accepted,
        op_hash: outcome.op_hash.to_hex(),
    }))
}

#[instrument(skip_all)]
async fn receipt(
    State(state): State<RpcState>,
    Path(hash): Path<String>,
) -> Result<impl IntoResponse, RpcError> {
    let op_hash = OpHash::from_hex(&hash).map_err(|e| RpcError::InvalidHash(e.to_string()))?;
    let receipt = state
        .node
        .get_receipt(&op_hash)
        .await
        .map_err(|e| RpcError::Node(e.to_string()))?;

    match receipt {
        Some(receipt) => Ok(Json(receipt).into_response()),
        None => Ok((axum::http::StatusCode::NOT_FOUND, Json("receipt not found")).into_response()),
    }
}

async fn events(State(state): State<RpcState>) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.node.subscribe();
    let stream = BroadcastStream::new(receiver).filter_map(|message| {
        match message {
            Ok(event) => {
                let payload = match &event {
                    NodeEvent::UserOperationAccepted { op_hash, onchain_gas, native_gas, prove_time_ms } => {
                        serde_json::json!({
                            "type": "accepted",
                            "op_hash": op_hash.to_hex(),
                            "onchain_gas": onchain_gas,
                            "native_gas": native_gas,
                            "prove_time_ms": prove_time_ms,
                        })
                    }
                    NodeEvent::UserOperationRejected { op_hash, reason } => {
                        serde_json::json!({"type": "rejected", "op_hash": op_hash.to_hex(), "reason": reason})
                    }
                    NodeEvent::BatchCreated { batch_id, size, gas } => {
                        serde_json::json!({"type": "batch", "batch_id": batch_id, "size": size, "gas": gas})
                    }
                };
                Some(Ok(Event::default().data(payload.to_string())))
            }
            Err(BroadcastStreamRecvError::Lagged(_)) => None,
        }
    });
    Sse::new(stream)
}
