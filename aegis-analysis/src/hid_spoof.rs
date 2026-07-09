use aegis_common::device::{AnalysisResult, AnalysisType, UsbDevice};
use chrono::Utc;

/// HID Spoof Detection Module
///
/// Detects USB devices that claim to be mass-storage but also expose
/// HID (Human Interface Device) interfaces. This is the hallmark of
/// BadUSB / Rubber Ducky attacks where a flash drive secretly acts as
/// a keyboard to inject keystrokes.
///
/// Detection logic:
/// 1. Check if the device class is mass-storage (0x08) but also claims HID (0x03)
/// 2. Check the sysfs path for multiple interface descriptors
/// 3. Flag devices with mismatched personality (storage + keyboard)
///
/// USB Class codes relevant to detection.
const USB_CLASS_HID: u8 = 0x03;
const USB_CLASS_MASS_STORAGE: u8 = 0x08;

/// Check a device for HID interface spoofing.
pub fn check_hid_spoof(device: &UsbDevice) -> AnalysisResult {
    let mut suspicious_indicators: Vec<String> = Vec::new();
    let mut severity = 0u8;

    // Check 1: Device claims mass-storage class but has HID interface flag.
    if device.has_hid_interface && device.device_class == USB_CLASS_MASS_STORAGE {
        suspicious_indicators.push(
            "Mass-storage device exposes HID (keyboard) interface — possible BadUSB".to_string(),
        );
        severity = 9;
    }

    // Check 2: Device class is HID but block device is present (shouldn't happen).
    if device.device_class == USB_CLASS_HID && device.block_device.is_some() {
        suspicious_indicators
            .push("HID device has block device path — abnormal configuration".to_string());
        severity = severity.max(8);
    }

    // Check 3: Device class is 0x00 (defined at interface level) — needs deeper check.
    if device.device_class == 0x00 && device.has_hid_interface && device.block_device.is_some() {
        suspicious_indicators.push(
            "Composite device with both HID and mass-storage interfaces — suspicious".to_string(),
        );
        severity = severity.max(7);
    }

    let flagged = !suspicious_indicators.is_empty();
    let summary = if flagged {
        format!(
            "🚨 HID spoof detected on device {} — {} indicator(s)",
            device.vid_pid_string(),
            suspicious_indicators.len()
        )
    } else {
        format!(
            "✅ No HID spoof indicators on device {}",
            device.vid_pid_string()
        )
    };

    AnalysisResult {
        analysis_type: AnalysisType::HidSpoof,
        flagged,
        severity,
        summary,
        details: serde_json::json!({
            "vid_pid": device.vid_pid_string(),
            "device_class": device.device_class,
            "has_hid_interface": device.has_hid_interface,
            "has_block_device": device.block_device.is_some(),
            "indicators": suspicious_indicators,
        }),
        timestamp: Utc::now(),
    }
}

/// Read USB interface descriptors from sysfs to detect hidden HID claims.
/// This reads /sys/bus/usb/devices/{busnum}-{devnum}:*/bInterfaceClass
pub fn detect_hid_from_sysfs(sysfs_path: &str) -> Vec<u8> {
    let mut interface_classes = Vec::new();

    // List all interface directories under the device sysfs path.
    if let Ok(entries) = std::fs::read_dir(sysfs_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            let interface_class_path = path.join("bInterfaceClass");
            if interface_class_path.exists()
                && let Ok(content) = std::fs::read_to_string(&interface_class_path)
                && let Ok(class) = u8::from_str_radix(content.trim(), 16)
            {
                interface_classes.push(class);
            }
        }
    }

    interface_classes
}

/// Check if a set of interface classes indicates a spoofed device.
pub fn is_spoof_combination(interface_classes: &[u8]) -> bool {
    let has_hid = interface_classes.contains(&USB_CLASS_HID);
    let has_storage = interface_classes.contains(&USB_CLASS_MASS_STORAGE);
    has_hid && has_storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_storage_device() {
        let mut device = UsbDevice::new(0x0781, 0x5583, "1-2".into(), 1, 3, "/sys/test".into());
        device.device_class = USB_CLASS_MASS_STORAGE;
        device.has_hid_interface = false;
        device.block_device = Some("/dev/sdb".into());

        let result = check_hid_spoof(&device);
        assert!(!result.flagged);
    }

    #[test]
    fn test_badusb_detected() {
        let mut device = UsbDevice::new(0x0483, 0x5740, "1-3".into(), 1, 4, "/sys/test".into());
        device.device_class = USB_CLASS_MASS_STORAGE;
        device.has_hid_interface = true; // BadUSB: storage + keyboard!
        device.block_device = Some("/dev/sdc".into());

        let result = check_hid_spoof(&device);
        assert!(result.flagged);
        assert!(result.severity >= 9);
    }

    #[test]
    fn test_legitimate_keyboard() {
        let mut device = UsbDevice::new(0x046D, 0xC534, "1-1".into(), 1, 2, "/sys/test".into());
        device.device_class = USB_CLASS_HID;
        device.has_hid_interface = true;
        device.block_device = None; // No block device — normal keyboard

        let result = check_hid_spoof(&device);
        assert!(!result.flagged);
    }

    #[test]
    fn test_spoof_combination_detection() {
        assert!(is_spoof_combination(&[
            USB_CLASS_MASS_STORAGE,
            USB_CLASS_HID
        ]));
        assert!(!is_spoof_combination(&[USB_CLASS_MASS_STORAGE]));
        assert!(!is_spoof_combination(&[USB_CLASS_HID]));
    }
}
