use aegis_analysis::AnalysisPipeline;
use aegis_common::device::DeviceStatus;
use aegis_common::ipc::{DaemonCommand, DaemonResponse};
use aegis_common::logging::AuditLogger;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::state::AppState;

/// Handle a single daemon command, returning the appropriate response.
pub async fn handle_command(
    command: DaemonCommand,
    state: &Arc<RwLock<AppState>>,
    audit_logger: &Arc<RwLock<AuditLogger>>,
    _pipeline: &Arc<AnalysisPipeline>,
) -> DaemonResponse {
    match command {
        // ── Ping / Health Check ──
        DaemonCommand::Ping => {
            let state = state.read().await;
            DaemonResponse::Pong {
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: state.uptime_secs(),
            }
        }

        // ── List Devices ──
        DaemonCommand::ListDevices => {
            let state = state.read().await;
            DaemonResponse::DeviceList {
                devices: state.list_devices(),
            }
        }

        // ── Get Device ──
        DaemonCommand::GetDevice { session_id } => {
            let state = state.read().await;
            match state.get_device(&session_id) {
                Some(device) => DaemonResponse::DeviceInfo {
                    device: device.clone(),
                },
                None => DaemonResponse::Error {
                    code: 404,
                    message: format!("Device {session_id} not found"),
                },
            }
        }

        // ── Authorize Device ──
        DaemonCommand::AuthorizeDevice {
            session_id,
            read_only: _,
        } => {
            let mut state = state.write().await;
            match state.update_device_status(&session_id, DeviceStatus::Authorized) {
                Some(old_status) => {
                    // Log the authorization.
                    let mut logger = audit_logger.write().await;
                    let _ = logger.log(
                        "policy",
                        "device_authorized",
                        2,
                        &format!("Device {session_id} authorized"),
                        serde_json::json!({
                            "session_id": session_id,
                            "old_status": format!("{old_status}"),
                        }),
                    );

                    DaemonResponse::DeviceActionResult {
                        session_id,
                        new_status: DeviceStatus::Authorized,
                        message: "Device authorized for mounting".to_string(),
                    }
                }
                None => DaemonResponse::Error {
                    code: 404,
                    message: format!("Device {session_id} not found"),
                },
            }
        }

        // ── Block Device ──
        DaemonCommand::BlockDevice { session_id, reason } => {
            let mut state = state.write().await;
            match state.update_device_status(&session_id, DeviceStatus::Blocked) {
                Some(old_status) => {
                    let mut logger = audit_logger.write().await;
                    let _ = logger.log(
                        "policy",
                        "device_blocked",
                        5,
                        &format!("Device {session_id} blocked: {reason}"),
                        serde_json::json!({
                            "session_id": session_id,
                            "reason": reason,
                            "old_status": format!("{old_status}"),
                        }),
                    );

                    DaemonResponse::DeviceActionResult {
                        session_id,
                        new_status: DeviceStatus::Blocked,
                        message: format!("Device blocked: {reason}"),
                    }
                }
                None => DaemonResponse::Error {
                    code: 404,
                    message: format!("Device {session_id} not found"),
                },
            }
        }

        // ── Eject Device ──
        DaemonCommand::EjectDevice { session_id } => {
            let mut state = state.write().await;
            match state.remove_device(&session_id) {
                Some(_device) => {
                    let mut logger = audit_logger.write().await;
                    let _ = logger.log(
                        "device",
                        "device_ejected",
                        1,
                        &format!("Device {session_id} safely ejected"),
                        serde_json::json!({"session_id": session_id}),
                    );

                    DaemonResponse::DeviceActionResult {
                        session_id,
                        new_status: DeviceStatus::Ejected,
                        message: "Device safely ejected".to_string(),
                    }
                }
                None => DaemonResponse::Error {
                    code: 404,
                    message: format!("Device {session_id} not found"),
                },
            }
        }

        // ── Rescan Device ──
        DaemonCommand::RescanDevice { session_id } => {
            let mut state = state.write().await;
            match state.update_device_status(&session_id, DeviceStatus::Analyzing) {
                Some(_) => {
                    // TODO: Trigger async re-analysis via pipeline.
                    DaemonResponse::DeviceActionResult {
                        session_id,
                        new_status: DeviceStatus::Analyzing,
                        message: "Re-analysis started".to_string(),
                    }
                }
                None => DaemonResponse::Error {
                    code: 404,
                    message: format!("Device {session_id} not found"),
                },
            }
        }

        // ── Get Config ──
        DaemonCommand::GetConfig => {
            let state = state.read().await;
            match serde_json::to_string_pretty(&state.config) {
                Ok(json) => DaemonResponse::Config { config_json: json },
                Err(e) => DaemonResponse::Error {
                    code: 500,
                    message: format!("Failed to serialize config: {e}"),
                },
            }
        }

        // ── Update Config ──
        DaemonCommand::UpdateConfig { config_json } => match serde_json::from_str(&config_json) {
            Ok(new_config) => {
                let mut state = state.write().await;
                state.config = new_config;

                let mut logger = audit_logger.write().await;
                let _ = logger.log(
                    "system",
                    "config_updated",
                    3,
                    "Daemon configuration updated via IPC",
                    serde_json::json!({}),
                );

                DaemonResponse::Config {
                    config_json: "Configuration updated successfully".to_string(),
                }
            }
            Err(e) => DaemonResponse::Error {
                code: 400,
                message: format!("Invalid config JSON: {e}"),
            },
        },

        // ── Get Audit Log ──
        DaemonCommand::GetAuditLog { limit, offset } => {
            let logger = audit_logger.read().await;
            match logger.read_entries(limit, offset) {
                Ok((entries, total)) => {
                    let json_entries: Vec<serde_json::Value> = entries
                        .into_iter()
                        .filter_map(|e| serde_json::to_value(e).ok())
                        .collect();
                    DaemonResponse::AuditLogEntries {
                        entries: json_entries,
                        total_count: total,
                    }
                }
                Err(e) => DaemonResponse::Error {
                    code: 500,
                    message: format!("Failed to read audit log: {e}"),
                },
            }
        }

        // ── Shutdown ──
        DaemonCommand::Shutdown => {
            tracing::warn!("Shutdown command received via IPC");
            DaemonResponse::ShuttingDown
        }
    }
}
