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
    uid: u32,
) -> DaemonResponse {
    // Basic RBAC mapping: UID 0 is admin, others are user.
    // Real implementation could map specific UIDs or group memberships.
    let role_name = if uid == 0 { "admin" } else { "user" };

    let has_permission = |cmd: &DaemonCommand, perms: &aegis_common::config::RolePermissions| -> bool {
        match cmd {
            DaemonCommand::Ping => true,
            DaemonCommand::ListDevices => true,
            DaemonCommand::GetDevice { .. } => true,
            DaemonCommand::AuthorizeDevice { .. } => perms.can_authorize,
            DaemonCommand::BlockDevice { .. } => perms.can_block,
            DaemonCommand::EjectDevice { .. } => perms.can_eject,
            DaemonCommand::RescanDevice { .. } => perms.can_authorize, // same as authorize
            DaemonCommand::DeviceEvent { .. } => true,                 // System internal message
            DaemonCommand::GetConfig => perms.can_view_logs,           // safe read
            DaemonCommand::UpdateConfig { .. } => perms.can_configure,
            DaemonCommand::GetAuditLog { .. } => perms.can_view_logs,
            DaemonCommand::Shutdown => perms.can_configure,            // admin level
        }
    };

    let has_access = {
        let state_read = state.read().await;
        if let Some(perms) = state_read.config.policy.roles.get(role_name) {
            has_permission(&command, perms)
        } else {
            false // Deny if role not found
        }
    };

    if !has_access {
        return DaemonResponse::Error {
            code: 403,
            message: format!("Role '{role_name}' lacks permission for this command"),
        };
    }

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
            if let Some(device) = state.get_device_mut(&session_id) {
                device.status = DeviceStatus::Authorized;
                let _ = crate::interception::power_monitor::restore_port_power(&device.sysfs_path);
                
                let mut logger = audit_logger.write().await;
                let _ = logger.log(
                    "policy",
                    "device_authorized",
                    2,
                    &format!("Device {session_id} authorized"),
                    serde_json::json!({
                        "session_id": session_id,
                    }),
                );

                DaemonResponse::DeviceActionResult {
                    session_id,
                    new_status: DeviceStatus::Authorized,
                    message: "Device authorized for mounting".to_string(),
                }
            } else {
                DaemonResponse::Error {
                    code: 404,
                    message: format!("Device {session_id} not found"),
                }
            }
        }

        // ── Block Device ──
        DaemonCommand::BlockDevice { session_id, reason } => {
            let mut state = state.write().await;
            let mut logger = audit_logger.write().await;
            if let Some(device) = state.get_device_mut(&session_id) {
                device.status = DeviceStatus::Blocked;
                let _ = crate::interception::power_monitor::kill_port_power(&device.sysfs_path);
                let _ = logger.log(
                    "policy",
                    "device_blocked",
                    8,
                    &format!("Administrator blocked device: {reason}"),
                    serde_json::json!({ "session_id": session_id, "reason": reason }),
                );
                DaemonResponse::DeviceActionResult {
                    session_id,
                    new_status: DeviceStatus::Blocked,
                    message: format!("Device blocked: {reason}"),
                }
            } else {
                DaemonResponse::Error {
                    code: 404,
                    message: format!("Device {session_id} not found"),
                }
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

        // ── Device Event (External Notify Script) ──
        DaemonCommand::DeviceEvent { action, devpath, kernel, vendor_id, model_id, .. } => {
            tracing::info!(
                "Received external udev notification: {} for {} ({}:{}) at {}",
                action, kernel, vendor_id, model_id, devpath
            );
            // We just acknowledge it. The internal netlink monitor handles state changes.
            DaemonResponse::Success { message: "Event acknowledged".to_string() }
        }

        // ── Shutdown ──
        DaemonCommand::Shutdown => {
            tracing::warn!("Shutdown command received via IPC");
            DaemonResponse::ShuttingDown
        }
    }
}
