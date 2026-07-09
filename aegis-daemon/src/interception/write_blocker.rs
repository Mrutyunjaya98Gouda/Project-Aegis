#![allow(dead_code)]
use aegis_common::error::{AegisError, AegisResult};
use std::path::Path;

/// Software-Emulated Hardware Write Blocker
///
/// Enforces read-only mode on USB block devices by manipulating the
/// Linux kernel's per-device read-only flag in sysfs.
///
/// Path: /sys/block/{device}/ro
///   - Write "1" to enforce read-only
///   - Write "0" to allow read-write
///
/// This prevents any outbound write commands (SCSI WRITE) from
/// reaching the USB device, blocking data exfiltration to the drive.
///

/// Enable write-blocking (read-only) on a block device.
///
/// Example: `enable_write_block("sdb")` sets /sys/block/sdb/ro to 1.
pub fn enable_write_block(device_name: &str) -> AegisResult<()> {
    let ro_path = format!("/sys/block/{device_name}/ro");
    let path = Path::new(&ro_path);

    if !path.exists() {
        return Err(AegisError::WriteBlocker(format!(
            "Block device sysfs path not found: {ro_path}"
        )));
    }

    std::fs::write(path, "1").map_err(|e| {
        AegisError::WriteBlocker(format!(
            "Failed to set read-only on {device_name}: {e} (requires root)"
        ))
    })?;

    tracing::info!(
        device = device_name,
        "Write blocker ENABLED — device is read-only"
    );
    Ok(())
}

/// Disable write-blocking (allow read-write) on a block device.
pub fn disable_write_block(device_name: &str) -> AegisResult<()> {
    let ro_path = format!("/sys/block/{device_name}/ro");
    let path = Path::new(&ro_path);

    if !path.exists() {
        return Err(AegisError::WriteBlocker(format!(
            "Block device sysfs path not found: {ro_path}"
        )));
    }

    std::fs::write(path, "0").map_err(|e| {
        AegisError::WriteBlocker(format!(
            "Failed to remove read-only on {device_name}: {e} (requires root)"
        ))
    })?;

    tracing::warn!(
        device = device_name,
        "Write blocker DISABLED — device is read-write"
    );
    Ok(())
}

/// Check if a block device is currently in read-only mode.
pub fn is_write_blocked(device_name: &str) -> AegisResult<bool> {
    let ro_path = format!("/sys/block/{device_name}/ro");
    let path = Path::new(&ro_path);

    if !path.exists() {
        return Err(AegisError::WriteBlocker(format!(
            "Block device sysfs path not found: {ro_path}"
        )));
    }

    let content = std::fs::read_to_string(path).map_err(|e| {
        AegisError::WriteBlocker(format!("Failed to read ro flag for {device_name}: {e}"))
    })?;

    Ok(content.trim() == "1")
}

/// Extract the device name from a full /dev/ path.
/// "/dev/sdb" → "sdb", "/dev/sdc1" → "sdc1"
pub fn device_name_from_path(dev_path: &str) -> Option<&str> {
    dev_path.strip_prefix("/dev/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_name_extraction() {
        assert_eq!(device_name_from_path("/dev/sdb"), Some("sdb"));
        assert_eq!(device_name_from_path("/dev/sdc1"), Some("sdc1"));
        assert_eq!(device_name_from_path("sdb"), None);
    }
}
