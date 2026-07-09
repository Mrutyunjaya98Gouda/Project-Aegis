use aegis_common::device::UsbDevice;
use aegis_common::error::AegisResult;
use std::path::Path;

/// USB device enumeration via sysfs.
///
/// On Linux, USB devices are exposed in /sys/bus/usb/devices/.
/// This module reads device attributes from sysfs to construct
/// UsbDevice structs without requiring the `udev` crate as a
/// hard dependency. For real-time monitoring, the daemon would
/// integrate with inotify/netlink or the `udev` crate.
/// Enumerate currently connected USB devices by reading sysfs.
pub fn enumerate_usb_devices() -> AegisResult<Vec<UsbDevice>> {
    let sysfs_usb = Path::new("/sys/bus/usb/devices");
    let mut devices = Vec::new();

    if !sysfs_usb.exists() {
        tracing::warn!("sysfs USB path not found — are we on Linux?");
        return Ok(devices);
    }

    let entries = std::fs::read_dir(sysfs_usb)?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip entries that aren't actual USB devices (e.g., "usb1", "usb2" are root hubs).
        if name.starts_with("usb") {
            continue;
        }

        // Must have idVendor and idProduct to be a real device.
        let vid_path = path.join("idVendor");
        let pid_path = path.join("idProduct");

        if !vid_path.exists() || !pid_path.exists() {
            continue;
        }

        let vid = read_hex_attr(&vid_path).unwrap_or(0);
        let pid = read_hex_attr(&pid_path).unwrap_or(0);
        if vid == 0 && pid == 0 {
            continue;
        }

        // Filter out internal built-in devices (e.g., webcam, fingerprint)
        if let Some(removable_status) = read_string_attr(&path.join("removable"))
            && removable_status == "fixed"
        {
            continue;
        }

        let bus_num = read_decimal_attr(&path.join("busnum")).unwrap_or(0) as u8;
        let dev_num = read_decimal_attr(&path.join("devnum")).unwrap_or(0) as u8;

        let mut device = UsbDevice::new(
            vid,
            pid,
            name.clone(),
            bus_num,
            dev_num,
            path.to_string_lossy().to_string(),
        );

        // Read optional attributes.
        device.serial_number = read_string_attr(&path.join("serial"));
        device.manufacturer = read_string_attr(&path.join("manufacturer"));
        device.product_name = read_string_attr(&path.join("product"));
        device.revision = read_string_attr(&path.join("version"));
        device.device_class = read_hex_attr(&path.join("bDeviceClass")).unwrap_or(0) as u8;
        device.device_subclass = read_hex_attr(&path.join("bDeviceSubClass")).unwrap_or(0) as u8;

        // Check for HID interfaces.
        device.has_hid_interface = check_for_hid_interface(&path);

        // Find associated block device.
        device.block_device = find_block_device(&path);

        tracing::debug!(
            vid_pid = %device.vid_pid_string(),
            port = %device.port_path,
            product = ?device.product_name,
            "Enumerated USB device"
        );

        devices.push(device);
    }

    tracing::info!(count = devices.len(), "USB device enumeration complete");
    Ok(devices)
}

/// Read a hex-formatted sysfs attribute (e.g., idVendor "0781").
fn read_hex_attr(path: &Path) -> Option<u16> {
    let content = std::fs::read_to_string(path).ok()?;
    u16::from_str_radix(content.trim(), 16).ok()
}

/// Read a decimal sysfs attribute.
fn read_decimal_attr(path: &Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse().ok()
}

/// Read a string sysfs attribute.
fn read_string_attr(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Check if any interface under this device claims HID class (0x03).
fn check_for_hid_interface(device_path: &Path) -> bool {
    if let Ok(entries) = std::fs::read_dir(device_path) {
        for entry in entries.flatten() {
            let iface_class = entry.path().join("bInterfaceClass");
            if iface_class.exists()
                && let Some(class) = read_hex_attr(&iface_class)
                && class == 0x03
            {
                return true;
            }
        }
    }
    false
}

/// Find the block device name (e.g., "sdb") associated with a USB device.
fn find_block_device(device_path: &Path) -> Option<String> {
    // Traverse: device → host → target → block
    fn search_recursive(path: &Path, depth: u8) -> Option<String> {
        if depth > 6 {
            return None;
        }
        let block_dir = path.join("block");
        if block_dir.exists()
            && let Ok(entries) = std::fs::read_dir(&block_dir)
            && let Some(entry) = entries.flatten().next()
        {
            let name = entry.file_name().to_string_lossy().to_string();
            return Some(format!("/dev/{name}"));
        }
        // Recurse into subdirectories.
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.path().is_dir()
                    && let Some(dev) = search_recursive(&entry.path(), depth + 1)
                {
                    return Some(dev);
                }
            }
        }
        None
    }
    search_recursive(device_path, 0)
}
