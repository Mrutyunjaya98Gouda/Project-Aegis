use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::device::PortLocation;

/// Root configuration for the Aegis daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    /// General daemon settings.
    pub daemon: DaemonConfig,
    /// Analysis engine thresholds and toggles.
    pub analysis: AnalysisConfig,
    /// Policy and access control settings.
    pub policy: PolicyConfig,
    /// Logging configuration.
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to the Unix domain socket.
    pub socket_path: String,
    /// Maximum connected clients.
    pub max_clients: usize,
    /// Device authorization timeout in seconds (auto-block if not approved).
    pub auth_timeout_secs: u64,
    /// Enable kiosk/valet mode (block all devices when screen locked).
    pub kiosk_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Shannon entropy threshold (files above this are flagged).
    pub entropy_threshold: f64,
    /// Enable YARA signature scanning.
    pub yara_enabled: bool,
    /// Path to YARA rules directory.
    pub yara_rules_path: PathBuf,
    /// Enable HID spoof detection.
    pub hid_spoof_detection: bool,
    /// Enable ML keystroke anomaly detection.
    pub ml_anomaly_detection: bool,
    /// Enable dynamic sandbox (MicroVM) detonation.
    pub sandbox_enabled: bool,
    /// Enable honey-token implantation on approved devices.
    pub honey_tokens_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Default action for unknown devices: "block" or "quarantine".
    pub default_action: String,
    /// Trusted device passport hashes (pre-approved devices).
    pub trusted_passports: Vec<String>,
    /// Port geo-fencing rules: port location → allowed or denied.
    pub geofence_rules: HashMap<String, GeofenceRule>,
    /// RBAC role definitions.
    pub roles: HashMap<String, RolePermissions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeofenceRule {
    /// Physical port location this rule applies to.
    pub location: PortLocation,
    /// Whether devices on this port are allowed.
    pub allowed: bool,
    /// Optional: restrict to specific device classes only.
    pub allowed_classes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermissions {
    /// Can authorize devices.
    pub can_authorize: bool,
    /// Can block devices.
    pub can_block: bool,
    /// Can view audit logs.
    pub can_view_logs: bool,
    /// Can modify configuration.
    pub can_configure: bool,
    /// Can eject devices.
    pub can_eject: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Path to the audit log file.
    pub log_file: PathBuf,
    /// HMAC key for tamper-proof log chaining (hex-encoded).
    pub hmac_key: String,
    /// Maximum log file size in MB before rotation.
    pub max_size_mb: u64,
    /// Log level filter (trace, debug, info, warn, error).
    pub level: String,
}

impl Default for AegisConfig {
    fn default() -> Self {
        let mut geofence_rules = HashMap::new();
        geofence_rules.insert(
            "front_panel".to_string(),
            GeofenceRule {
                location: PortLocation::FrontPanel,
                allowed: true,
                allowed_classes: None,
            },
        );
        geofence_rules.insert(
            "rear_io".to_string(),
            GeofenceRule {
                location: PortLocation::RearIO,
                allowed: true,
                allowed_classes: None,
            },
        );

        let mut roles = HashMap::new();
        roles.insert(
            "admin".to_string(),
            RolePermissions {
                can_authorize: true,
                can_block: true,
                can_view_logs: true,
                can_configure: true,
                can_eject: true,
            },
        );
        roles.insert(
            "user".to_string(),
            RolePermissions {
                can_authorize: false,
                can_block: false,
                can_view_logs: true,
                can_configure: false,
                can_eject: true,
            },
        );
        roles.insert(
            "kiosk".to_string(),
            RolePermissions {
                can_authorize: false,
                can_block: false,
                can_view_logs: false,
                can_configure: false,
                can_eject: false,
            },
        );

        Self {
            daemon: DaemonConfig {
                socket_path: "/tmp/aegis.sock".to_string(),
                max_clients: 10,
                auth_timeout_secs: 300,
                kiosk_mode: false,
            },
            analysis: AnalysisConfig {
                entropy_threshold: 7.5,
                yara_enabled: true,
                yara_rules_path: PathBuf::from("rules/yara"),
                hid_spoof_detection: true,
                ml_anomaly_detection: false,
                sandbox_enabled: false,
                honey_tokens_enabled: false,
            },
            policy: PolicyConfig {
                default_action: "quarantine".to_string(),
                trusted_passports: Vec::new(),
                geofence_rules,
                roles,
            },
            logging: LoggingConfig {
                log_file: PathBuf::from("/var/log/aegis/audit.jsonl"),
                hmac_key: "change-me-in-production".to_string(),
                max_size_mb: 100,
                level: "info".to_string(),
            },
        }
    }
}

impl AegisConfig {
    /// Load configuration from a TOML file, falling back to defaults.
    pub fn load(path: &std::path::Path) -> Result<Self, crate::error::AegisError> {
        if path.exists() {
            let content = std::fs::read_to_string(path).map_err(|e| {
                crate::error::AegisError::Config(format!("Failed to read config: {e}"))
            })?;
            toml::from_str(&content).map_err(|e| {
                crate::error::AegisError::Config(format!("Failed to parse config: {e}"))
            })
        } else {
            tracing::warn!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            Ok(Self::default())
        }
    }
}
