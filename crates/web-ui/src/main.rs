use axum::Router;
use qevm_core::Node;
use qevm_rpc::router as rpc_router;
use qevm_telemetry::{init_telemetry, TelemetryConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = TelemetryConfig::default();
    init_telemetry(telemetry)?;

    let node = Arc::new(Node::new(Default::default()));
    let api = rpc_router(node);

    let assets_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    let app = Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new(assets_dir));

    let addr: SocketAddr = "127.0.0.1:8081".parse().expect("valid addr");
    println!("Q-EVM web UI listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
