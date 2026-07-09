mod interception;
mod ipc;
mod policy;
mod state;

use aegis_common::config::AegisConfig;
use aegis_common::logging::AuditLogger;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

/// Sample the first `max_bytes` from a block device for analysis.
/// Returns an empty Vec if the device is inaccessible or has no block path.
fn sample_block_device(block_device: &Option<String>, max_bytes: usize) -> Vec<u8> {
    let Some(dev_path) = block_device.as_deref() else {
        return Vec::new();
    };
    // Enable write-blocking before we open the device.
    if let Some(name) = interception::write_blocker::device_name_from_path(dev_path) {
        if let Err(e) = interception::write_blocker::enable_write_block(name) {
            tracing::warn!("Write-blocker failed for {dev_path}: {e} (running without root?)");
        }
    }
    match std::fs::File::open(dev_path) {
        Ok(mut file) => {
            use std::io::Read;
            let mut buf = vec![0u8; max_bytes];
            match file.read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    tracing::debug!(
                        device = dev_path,
                        bytes_read = n,
                        "Block device sampled for analysis"
                    );
                    buf
                }
                Err(e) => {
                    tracing::warn!("Could not read block device {dev_path}: {e}");
                    Vec::new()
                }
            }
        }
        Err(e) => {
            tracing::warn!("Could not open block device {dev_path}: {e} (may need root)");
            Vec::new()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Initialize logging ──
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .json()
        .init();

    tracing::info!("╔══════════════════════════════════════════╗");
    tracing::info!("║   PROJECT AEGIS — Zero-Trust USB Guard   ║");
    tracing::info!(
        "║         Daemon v{}              ║",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("╚══════════════════════════════════════════╝");

    // ── Load configuration ──
    let config_path =
        std::env::var("AEGIS_CONFIG").unwrap_or_else(|_| "config/aegis.toml".to_string());
    let config = AegisConfig::load(Path::new(&config_path))?;
    tracing::info!(socket = %config.daemon.socket_path, "Configuration loaded");

    // ── Initialize audit logger ──
    let audit_logger = AuditLogger::new(&config.logging.log_file, &config.logging.hmac_key)?;
    let audit_logger = Arc::new(RwLock::new(audit_logger));
    tracing::info!(log_file = %config.logging.log_file.display(), "Audit logger initialized");

    // ── Log startup event ──
    {
        let mut logger = audit_logger.write().await;
        logger.log(
            "system",
            "daemon_start",
            1,
            "Aegis daemon started",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "config_path": config_path,
                "socket_path": config.daemon.socket_path,
            }),
        )?;
    }

    // ── Initialize shared state ──
    let app_state = Arc::new(RwLock::new(state::AppState::new(config.clone())));
    tracing::info!("Application state initialized");

    // ── Initialize analysis pipeline ──
    let pipeline = aegis_analysis::AnalysisPipeline::new(
        config.analysis.entropy_threshold,
        config.analysis.yara_enabled,
        config.analysis.hid_spoof_detection,
    );
    let pipeline = Arc::new(pipeline);
    tracing::info!("Analysis pipeline initialized");

    // ── Start IPC server ──
    let socket_path = config.daemon.socket_path.clone();
    let ipc_state = app_state.clone();
    let ipc_logger = audit_logger.clone();
    let ipc_pipeline = pipeline.clone();

    let ipc_handle = tokio::spawn(async move {
        if let Err(e) =
            ipc::server::run_ipc_server(&socket_path, ipc_state, ipc_logger, ipc_pipeline).await
        {
            tracing::error!("IPC server error: {e}");
        }
    });

    tracing::info!("IPC server started — listening for connections");

    // ── Start Udev Polling Loop ──
    let poll_state = app_state.clone();
    let poll_logger = audit_logger.clone();
    let poll_pipeline = pipeline.clone();
    let poll_config = config.clone();

    let _udev_handle = tokio::spawn(async move {
        tracing::info!("Udev monitor started");
        let mut known_ports = HashSet::new();
        let geofence_engine =
            policy::geofence::GeofenceEngine::new(poll_config.policy.geofence_rules.clone());

        loop {
            if let Ok(current_devices) = interception::udev_monitor::enumerate_usb_devices() {
                let mut current_ports = HashSet::new();

                for dev in current_devices {
                    current_ports.insert(dev.port_path.clone());

                    if !known_ports.contains(&dev.port_path) {
                        tracing::info!("🔌 New device detected at {}", dev.port_path);

                        let session_id = dev.session_id;
                        let vid_pid = dev.vid_pid_string();

                        // 1. Hardware Passport Whitelist Check
                        let passport_hash = policy::device_passport::generate_passport(&dev);
                        if policy::device_passport::is_trusted(
                            &passport_hash,
                            &poll_config.policy.trusted_passports,
                        ) {
                            tracing::info!(
                                "✅ Device passport matched whitelist: {}",
                                passport_hash
                            );
                            let mut state = poll_state.write().await;
                            let mut auth_dev = dev.clone();
                            auth_dev.status = aegis_common::device::DeviceStatus::Authorized;
                            state.add_device(auth_dev);
                            continue;
                        }

                        // 2. Geofence Check
                        let geo_result = geofence_engine.check_device(&dev);
                        if !geo_result.allowed {
                            tracing::warn!("🚫 Geofence violation: {}", geo_result.reason);
                            let mut state = poll_state.write().await;
                            let mut blocked_dev = dev.clone();
                            blocked_dev.status = aegis_common::device::DeviceStatus::Blocked;
                            state.add_device(blocked_dev);
                            continue;
                        }

                        // 3. Add to state
                        {
                            let mut state = poll_state.write().await;
                            state.add_device(dev.clone());
                        }

                        // 4. Log detection
                        {
                            let mut logger = poll_logger.write().await;
                            let _ = logger.log(
                                "device",
                                "device_connected",
                                1,
                                "New USB device detected",
                                serde_json::json!({ "session_id": session_id, "vid_pid": vid_pid }),
                            );
                        }

                        // 5. Kick off analysis in a background task
                        let pipeline = poll_pipeline.clone();
                        let state_ref = poll_state.clone();
                        let block_device_path = dev.block_device.clone();
                        tokio::spawn(async move {
                            // Mark device as Analyzing immediately
                            {
                                let mut s = state_ref.write().await;
                                if let Some(d) = s.get_device_mut(&session_id) {
                                    d.status = aegis_common::device::DeviceStatus::Analyzing;
                                }
                            }

                            // Sample the real block device (first 512 KB) for analysis.
                            // Falls back to an empty buffer for HID-only devices.
                            const SAMPLE_SIZE: usize = 512 * 1024; // 512 KB
                            let raw_sample =
                                sample_block_device(&block_device_path, SAMPLE_SIZE);

                            let buffers: Vec<(&str, &[u8])> = if raw_sample.is_empty() {
                                // No block device — HID-only or inaccessible; analyze device metadata only
                                tracing::info!("No block device data available — running metadata-only analysis");
                                vec![]
                            } else {
                                vec![("device_sample.bin", raw_sample.as_slice())]
                            };

                            if let Ok((score, results)) = pipeline.analyze(&dev, &buffers) {
                                let mut s = state_ref.write().await;
                                if let Some(d) = s.get_device_mut(&session_id) {
                                    d.trust_score = score;
                                    d.analysis_results = results;
                                    if score < 40 {
                                        d.status = aegis_common::device::DeviceStatus::Quarantined;
                                        tracing::warn!(
                                            session = %session_id,
                                            trust_score = score,
                                            "Device quarantined — low trust score"
                                        );
                                    } else {
                                        d.status = aegis_common::device::DeviceStatus::Pending;
                                        tracing::info!(
                                            session = %session_id,
                                            trust_score = score,
                                            "Device analysis complete — awaiting approval"
                                        );
                                    }
                                }
                            }
                        });
                    }
                }

                // Identify disconnected devices
                for known_port in known_ports.iter() {
                    if !current_ports.contains(known_port) {
                        tracing::info!("🔌 Device removed from {}", known_port);

                        // Find the session ID to remove it from state
                        let mut to_remove = None;
                        {
                            let state = poll_state.read().await;
                            for (sid, d) in state.devices.iter() {
                                if d.port_path == *known_port {
                                    to_remove = Some(*sid);
                                    break;
                                }
                            }
                        }

                        if let Some(sid) = to_remove {
                            let mut state = poll_state.write().await;
                            state.remove_device(&sid);

                            let mut logger = poll_logger.write().await;
                            let _ = logger.log(
                                "device",
                                "device_disconnected",
                                1,
                                "USB device removed",
                                serde_json::json!({ "session_id": sid, "port": known_port }),
                            );
                        }
                    }
                }

                known_ports = current_ports;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    // ── Wait for shutdown signal ──
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutdown signal received — cleaning up...");

    // Log shutdown event.
    {
        let mut logger = audit_logger.write().await;
        let _ = logger.log(
            "system",
            "daemon_stop",
            1,
            "Aegis daemon shutting down gracefully",
            serde_json::json!({}),
        );
    }

    // Clean up socket file.
    let _ = std::fs::remove_file(&config.daemon.socket_path);
    ipc_handle.abort();

    tracing::info!("Aegis daemon stopped. Goodbye.");
    Ok(())
}
