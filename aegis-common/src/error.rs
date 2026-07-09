use thiserror::Error;

/// Unified error type for all Aegis components.
#[derive(Debug, Error)]
pub enum AegisError {
    // ── I/O & System ──
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    // ── Device ──
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Device access denied: {0}")]
    AccessDenied(String),

    #[error("Device already in state: {0}")]
    InvalidStateTransition(String),

    // ── Analysis ──
    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("YARA engine error: {0}")]
    YaraEngine(String),

    #[error("Entropy scan error: {0}")]
    EntropyScan(String),

    // ── IPC ──
    #[error("IPC connection error: {0}")]
    IpcConnection(String),

    #[error("IPC protocol error: {0}")]
    IpcProtocol(String),

    #[error("IPC timeout")]
    IpcTimeout,

    // ── Policy ──
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("RBAC unauthorized: role '{role}' cannot perform '{action}'")]
    Unauthorized { role: String, action: String },

    // ── Interception ──
    #[error("udev error: {0}")]
    Udev(String),

    #[error("Write blocker error: {0}")]
    WriteBlocker(String),

    // ── Generic ──
    #[error("{0}")]
    Internal(String),
}

/// Convenient Result alias.
pub type AegisResult<T> = Result<T, AegisError>;
