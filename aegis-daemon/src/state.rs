use aegis_common::config::AegisConfig;
use aegis_common::device::{DeviceStatus, UsbDevice};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Shared application state for the Aegis daemon.
pub struct AppState {
    /// Current configuration.
    pub config: AegisConfig,
    /// Connected USB devices indexed by session ID.
    pub devices: HashMap<Uuid, UsbDevice>,
    /// Daemon startup time.
    pub started_at: DateTime<Utc>,
}

impl AppState {
    pub fn new(config: AegisConfig) -> Self {
        Self {
            config,
            devices: HashMap::new(),
            started_at: Utc::now(),
        }
    }

    /// Uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        (Utc::now() - self.started_at).num_seconds().max(0) as u64
    }

    /// Register a newly detected device.
    pub fn add_device(&mut self, device: UsbDevice) {
        tracing::info!(
            session = %device.session_id,
            vid_pid = %device.vid_pid_string(),
            port = %device.port_path,
            "Device registered in state"
        );
        self.devices.insert(device.session_id, device);
    }

    /// Get a device by session ID.
    pub fn get_device(&self, session_id: &Uuid) -> Option<&UsbDevice> {
        self.devices.get(session_id)
    }

    /// Get a mutable reference to a device.
    pub fn get_device_mut(&mut self, session_id: &Uuid) -> Option<&mut UsbDevice> {
        self.devices.get_mut(session_id)
    }

    /// Update a device's status.
    pub fn update_device_status(
        &mut self,
        session_id: &Uuid,
        new_status: DeviceStatus,
    ) -> Option<DeviceStatus> {
        if let Some(device) = self.devices.get_mut(session_id) {
            let old = device.status;
            device.status = new_status;
            device.last_updated = Utc::now();
            tracing::info!(
                session = %session_id,
                old = %old,
                new = %new_status,
                "Device status updated"
            );
            Some(old)
        } else {
            None
        }
    }

    /// Remove a device (e.g., on disconnect or eject).
    pub fn remove_device(&mut self, session_id: &Uuid) -> Option<UsbDevice> {
        self.devices.remove(session_id)
    }

    /// List all currently tracked devices.
    pub fn list_devices(&self) -> Vec<UsbDevice> {
        self.devices.values().cloned().collect()
    }

    /// Count devices by status.
    #[allow(dead_code)]
    pub fn device_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for device in self.devices.values() {
            *counts.entry(format!("{}", device.status)).or_insert(0) += 1;
        }
        counts
    }
}
