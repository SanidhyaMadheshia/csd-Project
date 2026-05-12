//! Tracing + metrics setup for Q-EVM services.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use thiserror::Error;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("metrics error: {0}")]
    Metrics(String),
    #[error("tracing error: {0}")]
    Tracing(String),
}

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub service_name: String,
    pub enable_console: bool,
    pub metrics_addr: SocketAddr,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "qevm".to_string(),
            enable_console: true,
            metrics_addr: "127.0.0.1:9100".parse().expect("valid addr"),
        }
    }
}

pub struct TelemetryHandle {
    pub metrics_handle: PrometheusHandle,
}

pub fn init_telemetry(config: TelemetryConfig) -> Result<TelemetryHandle, TelemetryError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_ansi(config.enable_console)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| TelemetryError::Tracing(e.to_string()))?;

    let builder = PrometheusBuilder::new();
    let handle = builder
        .with_http_listener(config.metrics_addr)
        .install_recorder()
        .map_err(|e| TelemetryError::Metrics(e.to_string()))?;

    Ok(TelemetryHandle {
        metrics_handle: handle,
    })
}
