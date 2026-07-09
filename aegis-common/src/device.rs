use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents a physical USB device detected by the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    /// Unique session identifier for this device connection.
    pub session_id: Uuid,
    /// USB Vendor ID (e.g., 0x0781 for SanDisk).
    pub vendor_id: u16,
    /// USB Product ID.
    pub product_id: u16,
    /// Device serial number (if available).
    pub serial_number: Option<String>,
    /// Device revision/version string.
    pub revision: Option<String>,
    /// Human-readable manufacturer name.
    pub manufacturer: Option<String>,
    /// Human-readable product name.
    pub product_name: Option<String>,
    /// USB device class code.
    pub device_class: u8,
    /// USB device subclass code.
    pub device_subclass: u8,
    /// Physical port topology path (e.g., "1-2.3").
    pub port_path: String,
    /// Bus number.
    pub bus_number: u8,
    /// Device number on the bus.
    pub device_number: u8,
    /// Block device path (e.g., "/dev/sdb") if mass storage.
    pub block_device: Option<String>,
    /// Sysfs path to the device.
    pub sysfs_path: String,
    /// Current trust/authorization status.
    pub status: DeviceStatus,
    /// Computed trust score (0-100).
    pub trust_score: u8,
    /// Hardware passport hash (SHA-256 of VID+PID+Serial+Rev).
    pub passport_hash: Option<String>,
    /// Whether HID interfaces were detected (potential spoof).
    pub has_hid_interface: bool,
    /// Timestamp when the device was first seen.
    pub first_seen: DateTime<Utc>,
    /// Timestamp of last status change.
    pub last_updated: DateTime<Utc>,
    /// Analysis results attached to this device.
    pub analysis_results: Vec<AnalysisResult>,
}

/// Current authorization status of a USB device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Device detected, pending analysis.
    Pending,
    /// Currently being analyzed by the engine.
    Analyzing,
    /// Blocked — failed analysis or policy check.
    Blocked,
    /// Authorized — passed all checks, mount allowed.
    Authorized,
    /// Quarantined — suspicious but admin may override.
    Quarantined,
    /// Ejected — device was safely removed.
    Ejected,
}

/// Represents the physical port location category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortLocation {
    FrontPanel,
    RearIO,
    InternalHeader,
    Hub,
    Unknown,
}

/// Result of a single analysis pass on a device or its files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Type of analysis that was performed.
    pub analysis_type: AnalysisType,
    /// Whether this analysis flagged the device as suspicious.
    pub flagged: bool,
    /// Severity level (0 = clean, 1-3 = low, 4-6 = medium, 7-9 = high, 10 = critical).
    pub severity: u8,
    /// Human-readable summary of findings.
    pub summary: String,
    /// Detailed findings data (analysis-specific).
    pub details: serde_json::Value,
    /// When this analysis was completed.
    pub timestamp: DateTime<Utc>,
}

/// Types of analysis that can be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisType {
    /// Shannon entropy scan for encrypted/packed content.
    Entropy,
    /// YARA signature matching.
    YaraSignature,
    /// HID interface spoof detection.
    HidSpoof,
    /// Hardware passport verification.
    DevicePassport,
    /// ML-based keystroke anomaly detection.
    KeystrokeAnomaly,
    /// MicroVM dynamic detonation.
    Sandbox,
    /// Slack space / hidden sector scan.
    SlackSpace,
}

impl UsbDevice {
    /// Creates a new device entry with default pending status.
    pub fn new(
        vendor_id: u16,
        product_id: u16,
        port_path: String,
        bus_number: u8,
        device_number: u8,
        sysfs_path: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            session_id: Uuid::new_v4(),
            vendor_id,
            product_id,
            serial_number: None,
            revision: None,
            manufacturer: None,
            product_name: None,
            device_class: 0,
            device_subclass: 0,
            port_path,
            bus_number,
            device_number,
            block_device: None,
            sysfs_path,
            status: DeviceStatus::Pending,
            trust_score: 0,
            passport_hash: None,
            has_hid_interface: false,
            first_seen: now,
            last_updated: now,
            analysis_results: Vec::new(),
        }
    }

    /// Formatted VID:PID string (e.g., "0781:5583").
    pub fn vid_pid_string(&self) -> String {
        format!("{:04x}:{:04x}", self.vendor_id, self.product_id)
    }
}

impl std::fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceStatus::Pending => write!(f, "⏳ Pending"),
            DeviceStatus::Analyzing => write!(f, "🔍 Analyzing"),
            DeviceStatus::Blocked => write!(f, "🚫 Blocked"),
            DeviceStatus::Authorized => write!(f, "✅ Authorized"),
            DeviceStatus::Quarantined => write!(f, "⚠️ Quarantined"),
            DeviceStatus::Ejected => write!(f, "⏏️ Ejected"),
        }
    }
}
