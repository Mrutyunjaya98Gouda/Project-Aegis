use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::{DeviceStatus, UsbDevice};

// ─────────────────────────────────────────────────────
//  Messages FROM the UI / external clients TO the daemon
// ─────────────────────────────────────────────────────

/// Commands that can be sent to the daemon via IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonCommand {
    /// Request a health check / heartbeat.
    Ping,

    /// List all currently connected devices.
    ListDevices,

    /// Get detailed info for a specific device.
    GetDevice { session_id: Uuid },

    /// Authorize a device for mounting.
    AuthorizeDevice {
        session_id: Uuid,
        /// Optional: mount as read-only even if authorized.
        read_only: bool,
    },

    /// Block / reject a device.
    BlockDevice { session_id: Uuid, reason: String },

    /// Eject / safely remove a device.
    EjectDevice { session_id: Uuid },

    /// Force a re-scan / re-analysis of a device.
    RescanDevice { session_id: Uuid },

    /// Get the current daemon configuration.
    GetConfig,

    /// Update daemon configuration.
    UpdateConfig { config_json: String },

    /// Retrieve audit log entries.
    GetAuditLog {
        /// Maximum number of entries to return.
        limit: usize,
        /// Offset for pagination.
        offset: usize,
    },

    /// Raw udev event notification from external script.
    DeviceEvent {
        action: String,
        kernel: String,
        vendor_id: String,
        model_id: String,
        serial: String,
        devpath: String,
        timestamp: String,
    },

    /// Shutdown the daemon gracefully.
    Shutdown,
}

// ─────────────────────────────────────────────────────
//  Messages FROM the daemon TO the UI / external clients
// ─────────────────────────────────────────────────────

/// Responses sent from the daemon back to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonResponse {
    /// Heartbeat acknowledgment.
    Pong { version: String, uptime_secs: u64 },

    /// List of all connected devices.
    DeviceList { devices: Vec<UsbDevice> },

    /// Detailed info for a single device.
    DeviceInfo { device: UsbDevice },

    /// Confirmation of a device action.
    DeviceActionResult {
        session_id: Uuid,
        new_status: DeviceStatus,
        message: String,
    },

    /// Current daemon configuration.
    Config { config_json: String },

    /// Audit log entries.
    AuditLogEntries {
        entries: Vec<serde_json::Value>,
        total_count: usize,
    },

    /// Generic success response for operations that don't return data.
    Success { message: String },

    /// A real-time event pushed to connected clients.
    Event(DeviceEvent),

    /// Generic error response.
    Error { code: u32, message: String },

    /// Shutdown acknowledgment.
    ShuttingDown,
}

// ─────────────────────────────────────────────────────
//  Real-time events pushed by the daemon
// ─────────────────────────────────────────────────────

/// Events emitted by the daemon for real-time updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DeviceEvent {
    /// A new USB device was physically inserted.
    DeviceConnected { device: Box<UsbDevice> },

    /// A USB device was physically removed.
    DeviceDisconnected { session_id: Uuid, port_path: String },

    /// Analysis started on a device.
    AnalysisStarted { session_id: Uuid },

    /// Analysis completed.
    AnalysisCompleted {
        session_id: Uuid,
        trust_score: u8,
        flagged: bool,
        summary: String,
    },

    /// Device status changed (authorized, blocked, etc.).
    StatusChanged {
        session_id: Uuid,
        old_status: DeviceStatus,
        new_status: DeviceStatus,
    },

    /// A security alert was triggered.
    SecurityAlert {
        session_id: Uuid,
        severity: u8,
        alert_type: String,
        message: String,
    },
}

/// Wrapper for IPC messages with a correlation ID for request/response matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcMessage<T> {
    /// Unique message identifier for request/response correlation.
    pub id: Uuid,
    /// The actual payload.
    pub payload: T,
}

impl<T> IpcMessage<T> {
    pub fn new(payload: T) -> Self {
        Self {
            id: Uuid::new_v4(),
            payload,
        }
    }

    pub fn with_id(id: Uuid, payload: T) -> Self {
        Self { id, payload }
    }
}
