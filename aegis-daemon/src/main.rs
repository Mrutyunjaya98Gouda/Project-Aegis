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
    let yara_rules_path = std::path::PathBuf::from(&config.analysis.yara_rules_path);
    let pipeline = aegis_analysis::AnalysisPipeline::new(
        config.analysis.entropy_threshold,
        config.analysis.yara_enabled,
        config.analysis.hid_spoof_detection,
        Some(&yara_rules_path),
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

    let poll_state = app_state.clone();
    let poll_logger = audit_logger.clone();
    let poll_pipeline = pipeline.clone();
    let poll_config = config.clone();

    let (udev_tx, mut udev_rx) = tokio::sync::mpsc::unbounded_channel();

    std::thread::spawn(move || {
        let socket = match udev::MonitorBuilder::new()
            .and_then(|b| b.match_subsystem_devtype("usb", "usb_device"))
            .and_then(|b| b.listen())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to start udev monitor: {e}");
                return;
            }
        };

        for event in socket.iter() {
            let act = match event.event_type() {
                udev::EventType::Add => "add",
                udev::EventType::Remove => "remove",
                _ => "other",
            };
            if let Some(sysfs_path) = event.syspath().to_str() {
                let _ = udev_tx.send((act.to_string(), sysfs_path.to_string()));
            }
        }
    });

    let _udev_handle = tokio::spawn(async move {
        tracing::info!("Udev monitor started");
        let mut known_ports = HashSet::new();
        let geofence_engine =
            policy::geofence::GeofenceEngine::new(poll_config.policy.geofence_rules.clone());

        // Initial enumeration
        if let Ok(current_devices) = interception::udev_monitor::enumerate_usb_devices() {
            for dev in current_devices {
                known_ports.insert(dev.port_path.clone());
                let mut state = poll_state.write().await;
                state.add_device(dev);
            }
        }

        while let Some((action, sysfs_path)) = udev_rx.recv().await {
            let path = Path::new(&sysfs_path);
            
            if action == "add" {
                // Wait briefly for udev to populate attributes
                tokio::time::sleep(Duration::from_millis(200)).await;
                
                if let Some(dev) = interception::udev_monitor::parse_usb_device(path) {
                    if known_ports.contains(&dev.port_path) {
                        continue;
                    }
                    known_ports.insert(dev.port_path.clone());
                    
                    tracing::info!("🔌 New device detected at {}", dev.port_path);

                    // 0. Enforce zero-trust default deny immediately
                    let _ = interception::power_monitor::kill_port_power(&dev.sysfs_path);

                    let session_id = dev.session_id;
                    let vid_pid = dev.vid_pid_string();

                    // 1. Hardware Passport Whitelist Check
                    let passport_hash = policy::device_passport::generate_passport(&dev);
                    if policy::device_passport::is_trusted(
                        &passport_hash,
                        &poll_config.policy.trusted_passports,
                    ) {
                        tracing::info!("✅ Device passport matched whitelist: {}", passport_hash);
                        let mut state = poll_state.write().await;
                        let mut auth_dev = dev.clone();
                        auth_dev.status = aegis_common::device::DeviceStatus::Authorized;
                        state.add_device(auth_dev);
                        let _ = interception::power_monitor::restore_port_power(&dev.sysfs_path);
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
                        {
                            let mut s = state_ref.write().await;
                            if let Some(d) = s.get_device_mut(&session_id) {
                                d.status = aegis_common::device::DeviceStatus::Analyzing;
                            }
                        }

                        const SAMPLE_SIZE: usize = 512 * 1024; // 512 KB
                        let raw_sample = sample_block_device(&block_device_path, SAMPLE_SIZE);

                        let buffers: Vec<(&str, &[u8])> = if raw_sample.is_empty() {
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
                                    tracing::warn!(session = %session_id, trust_score = score, "Device quarantined — low trust score");
                                } else {
                                    d.status = aegis_common::device::DeviceStatus::Pending;
                                    tracing::info!(session = %session_id, trust_score = score, "Device analysis complete — awaiting approval");
                                }
                            }
                        }
                    });
                }
            } else if action == "remove" {
                // Find the session ID to remove it from state
                let mut to_remove = None;
                let mut removed_port = None;
                {
                    let state = poll_state.read().await;
                    for (sid, d) in state.devices.iter() {
                        if d.sysfs_path == sysfs_path {
                            to_remove = Some(*sid);
                            removed_port = Some(d.port_path.clone());
                            break;
                        }
                    }
                }

                if let Some(sid) = to_remove {
                    if let Some(port) = removed_port {
                        known_ports.remove(&port);
                        tracing::info!("🔌 Device removed from {}", port);
                        
                        let mut state = poll_state.write().await;
                        state.remove_device(&sid);

                        let mut logger = poll_logger.write().await;
                        let _ = logger.log(
                            "device",
                            "device_disconnected",
                            1,
                            "USB device removed",
                            serde_json::json!({ "session_id": sid, "port": port }),
                        );
                    }
                }
            }
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
