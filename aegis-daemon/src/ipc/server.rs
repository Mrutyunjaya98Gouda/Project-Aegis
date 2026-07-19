use aegis_analysis::AnalysisPipeline;
use aegis_common::logging::AuditLogger;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::RwLock;

use crate::state::AppState;

/// Run the Unix Domain Socket IPC server.
///
/// Listens for incoming connections on the specified socket path,
/// spawning a handler task for each connected client.
pub async fn run_ipc_server(
    socket_path: &str,
    state: Arc<RwLock<AppState>>,
    audit_logger: Arc<RwLock<AuditLogger>>,
    pipeline: Arc<AnalysisPipeline>,
) -> anyhow::Result<()> {
    // Remove stale socket file if it exists.
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(path = socket_path, "IPC server bound and listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tracing::debug!("New IPC client connected");
                let state = state.clone();
                let logger = audit_logger.clone();
                let pipeline = pipeline.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state, logger, pipeline).await {
                        tracing::warn!("Client handler error: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::error!("Failed to accept IPC connection: {e}");
            }
        }
    }
}

/// Handle a single IPC client connection.
///
/// Reads newline-delimited JSON messages, processes each through
/// the command handler, and writes back JSON responses.
async fn handle_client(
    stream: tokio::net::UnixStream,
    state: Arc<RwLock<AppState>>,
    audit_logger: Arc<RwLock<AuditLogger>>,
    pipeline: Arc<AnalysisPipeline>,
) -> anyhow::Result<()> {
    let peer_cred = stream.peer_cred()?;
    let uid = peer_cred.uid();
    
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            tracing::debug!("IPC client disconnected");
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        tracing::debug!(msg = trimmed, "IPC message received");

        // Parse and handle the command.
        let response = match serde_json::from_str::<
            aegis_common::ipc::IpcMessage<aegis_common::ipc::DaemonCommand>,
        >(trimmed)
        {
            Ok(msg) => {
                let resp_payload =
                    super::handler::handle_command(msg.payload, &state, &audit_logger, &pipeline, uid)
                        .await;
                aegis_common::ipc::IpcMessage::with_id(msg.id, resp_payload)
            }
            Err(e) => {
                tracing::warn!(err = %e, "Failed to parse IPC command");
                aegis_common::ipc::IpcMessage::new(aegis_common::ipc::DaemonResponse::Error {
                    code: 400,
                    message: format!("Invalid command: {e}"),
                })
            }
        };

        // Serialize and send response.
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}
