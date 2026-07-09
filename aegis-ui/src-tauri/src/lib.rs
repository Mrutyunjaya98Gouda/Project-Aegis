fn daemon_socket_path() -> String {
    std::env::var("AEGIS_SOCKET_PATH")
        .or_else(|_| std::env::var("AEGIS_SOCKET"))
        .unwrap_or_else(|_| "/tmp/aegis.sock".to_string())
}
use aegis_common::ipc::{DaemonCommand, DaemonResponse, IpcMessage};
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

async fn send_daemon_cmd(cmd: DaemonCommand) -> Result<DaemonResponse, String> {
    let socket_path = daemon_socket_path();
    let mut stream = timeout(Duration::from_secs(3), UnixStream::connect(&socket_path))
        .await
        .map_err(|_| format!("Timed out connecting to daemon socket ({socket_path})"))?
        .map_err(|e| format!("Failed to connect to daemon socket ({socket_path}): {}", e))?;

    let msg = IpcMessage::new(cmd);
    let msg_str = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

    stream
        .write_all(msg_str.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(b"\n").await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes_read = timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .map_err(|_| "Timed out waiting for daemon response".to_string())?
        .map_err(|e| e.to_string())?;
    if bytes_read == 0 || line.trim().is_empty() {
        return Err("Received empty response from daemon".to_string());
    }

    let resp_msg: IpcMessage<DaemonResponse> =
        serde_json::from_str(&line).map_err(|e| e.to_string())?;

    // Check if the response is an Error
    if let DaemonResponse::Error { code, message } = &resp_msg.payload {
        return Err(format!("Daemon Error [{}]: {}", code, message));
    }

    Ok(resp_msg.payload)
}

#[tauri::command]
async fn ping_daemon() -> Result<serde_json::Value, String> {
    match send_daemon_cmd(DaemonCommand::Ping).await? {
        DaemonResponse::Pong {
            version,
            uptime_secs,
        } => Ok(serde_json::json!({
            "version": version,
            "uptime": uptime_secs
        })),
        _ => Err("Invalid response type from daemon".into()),
    }
}

#[tauri::command]
async fn eject_device(session_id: String) -> Result<String, String> {
    let uuid = uuid::Uuid::parse_str(&session_id).map_err(|e| e.to_string())?;
    match send_daemon_cmd(DaemonCommand::EjectDevice { session_id: uuid }).await? {
        DaemonResponse::DeviceActionResult { message, .. } => Ok(message),
        _ => Err("Invalid response type from daemon".into()),
    }
}

#[tauri::command]
async fn list_devices() -> Result<serde_json::Value, String> {
    match send_daemon_cmd(DaemonCommand::ListDevices).await? {
        DaemonResponse::DeviceList { devices } => {
            Ok(serde_json::to_value(devices).map_err(|e| e.to_string())?)
        }
        _ => Err("Invalid response type from daemon".into()),
    }
}

#[tauri::command]
async fn authorize_device(session_id: String) -> Result<String, String> {
    let uuid = uuid::Uuid::parse_str(&session_id).map_err(|e| e.to_string())?;
    match send_daemon_cmd(DaemonCommand::AuthorizeDevice {
        session_id: uuid,
        read_only: false,
    })
    .await?
    {
        DaemonResponse::DeviceActionResult { message, .. } => Ok(message),
        _ => Err("Invalid response type from daemon".into()),
    }
}

#[tauri::command]
async fn block_device(session_id: String, reason: String) -> Result<String, String> {
    let uuid = uuid::Uuid::parse_str(&session_id).map_err(|e| e.to_string())?;
    match send_daemon_cmd(DaemonCommand::BlockDevice {
        session_id: uuid,
        reason,
    })
    .await?
    {
        DaemonResponse::DeviceActionResult { message, .. } => Ok(message),
        _ => Err("Invalid response type from daemon".into()),
    }
}

#[tauri::command]
async fn get_audit_log(limit: usize) -> Result<serde_json::Value, String> {
    match send_daemon_cmd(DaemonCommand::GetAuditLog { limit, offset: 0 }).await? {
        DaemonResponse::AuditLogEntries { entries, .. } => {
            Ok(serde_json::to_value(entries).map_err(|e| e.to_string())?)
        }
        _ => Err("Invalid response type from daemon".into()),
    }
}

#[tauri::command]
async fn get_config() -> Result<serde_json::Value, String> {
    match send_daemon_cmd(DaemonCommand::GetConfig).await? {
        DaemonResponse::Config { config_json } => serde_json::from_str(&config_json)
            .map_err(|e| format!("Invalid daemon config response: {e}")),
        _ => Err("Invalid response type from daemon".into()),
    }
}

#[tauri::command]
async fn update_config(config_json: String) -> Result<String, String> {
    match send_daemon_cmd(DaemonCommand::UpdateConfig { config_json }).await? {
        DaemonResponse::Config { .. } => Ok("Config updated".into()),
        DaemonResponse::Error { message, .. } => Err(message),
        _ => Err("Invalid response type from daemon".into()),
    }
}

#[tauri::command]
async fn rescan_device(session_id: String) -> Result<String, String> {
    let uuid = uuid::Uuid::parse_str(&session_id).map_err(|e| e.to_string())?;
    match send_daemon_cmd(DaemonCommand::RescanDevice { session_id: uuid }).await? {
        DaemonResponse::DeviceActionResult { message, .. } => Ok(message),
        _ => Err("Invalid response type from daemon".into()),
    }
}

/// Background task: poll the daemon every 1.5s and emit events to the frontend.
async fn start_event_bridge(app: AppHandle) {
    loop {
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Fetch device list
        if let Ok(DaemonResponse::DeviceList { devices }) =
            send_daemon_cmd(DaemonCommand::ListDevices).await
        {
            let val = serde_json::to_value(&devices).unwrap_or_default();
            let _ = app.emit("aegis://device-update", val);
        }

        // Fetch daemon status
        if let Ok(DaemonResponse::Pong { version, uptime_secs }) =
            send_daemon_cmd(DaemonCommand::Ping).await
        {
            let _ = app.emit(
                "aegis://daemon-status",
                serde_json::json!({ "online": true, "version": version, "uptime": uptime_secs }),
            );
        } else {
            let _ = app.emit(
                "aegis://daemon-status",
                serde_json::json!({ "online": false }),
            );
        }
    }
}


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            ping_daemon,
            list_devices,
            authorize_device,
            block_device,
            get_audit_log,
            get_config,
            update_config,
            eject_device,
            rescan_device
        ])
        .setup(|app| {
            // Kick off the real-time event bridge in the background.
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(start_event_bridge(app_handle));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
