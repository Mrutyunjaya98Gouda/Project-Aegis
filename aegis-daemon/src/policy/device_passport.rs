use aegis_common::device::UsbDevice;
use sha2::{Digest, Sha256};

/// Device Digital Passport Module
///
/// Generates a unique cryptographic fingerprint for a USB device
/// by hashing its hardware identifiers. This passport is used to:
/// - Track devices across reconnections
/// - Maintain a whitelist of trusted devices
/// - Detect device identity spoofing
///

/// Generate a SHA-256 passport hash from device hardware identifiers.
pub fn generate_passport(device: &UsbDevice) -> String {
    let mut hasher = Sha256::new();

    // Mix fixed hardware identifiers.
    hasher.update(device.vendor_id.to_le_bytes());
    hasher.update(device.product_id.to_le_bytes());

    if let Some(ref serial) = device.serial_number {
        hasher.update(serial.as_bytes());
    } else {
        hasher.update(b"NO_SERIAL");
    }

    if let Some(ref revision) = device.revision {
        hasher.update(revision.as_bytes());
    } else {
        hasher.update(b"NO_REVISION");
    }

    hex::encode(hasher.finalize())
}

/// Check if a device's passport is in the trusted list.
pub fn is_trusted(passport: &str, trusted_list: &[String]) -> bool {
    trusted_list.iter().any(|t| t == passport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passport_deterministic() {
        let mut dev = UsbDevice::new(0x0781, 0x5583, "1-2".into(), 1, 3, "/sys/test".into());
        dev.serial_number = Some("SN123456".into());
        dev.revision = Some("2.00".into());

        let hash1 = generate_passport(&dev);
        let hash2 = generate_passport(&dev);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_passport_unique_per_device() {
        let mut dev1 = UsbDevice::new(0x0781, 0x5583, "1-2".into(), 1, 3, "/sys/test".into());
        dev1.serial_number = Some("AAA".into());

        let mut dev2 = UsbDevice::new(0x0781, 0x5583, "1-2".into(), 1, 3, "/sys/test".into());
        dev2.serial_number = Some("BBB".into());

        assert_ne!(generate_passport(&dev1), generate_passport(&dev2));
    }

    #[test]
    fn test_trusted_check() {
        let trusted = vec!["abc123".to_string(), "def456".to_string()];
        assert!(is_trusted("abc123", &trusted));
        assert!(!is_trusted("xyz789", &trusted));
    }
}
