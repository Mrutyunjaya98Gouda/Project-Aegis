use aegis_common::device::UsbDevice;
use aegis_common::error::AegisResult;
use std::path::Path;

/// USB device enumeration via sysfs.
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

        if name.starts_with("usb") {
            continue;
        }

        if let Some(device) = parse_usb_device(&path) {
            devices.push(device);
        }
    }

    tracing::info!(count = devices.len(), "USB device enumeration complete");
    Ok(devices)
}

pub fn parse_usb_device(path: &Path) -> Option<UsbDevice> {
    let vid_path = path.join("idVendor");
    let pid_path = path.join("idProduct");

    if !vid_path.exists() || !pid_path.exists() {
        return None;
    }

    let vid = read_hex_attr(&vid_path).unwrap_or(0);
    let pid = read_hex_attr(&pid_path).unwrap_or(0);
    if vid == 0 && pid == 0 {
        return None;
    }

    if let Some(removable_status) = read_string_attr(&path.join("removable")) {
        if removable_status == "fixed" {
            return None;
        }
    }

    let bus_num = read_decimal_attr(&path.join("busnum")).unwrap_or(0) as u8;
    let dev_num = read_decimal_attr(&path.join("devnum")).unwrap_or(0) as u8;
    let name = path.file_name()?.to_string_lossy().to_string();

    let mut device = UsbDevice::new(
        vid,
        pid,
        name.clone(),
        bus_num,
        dev_num,
        path.to_string_lossy().to_string(),
    );

    device.serial_number = read_string_attr(&path.join("serial"));
    device.manufacturer = read_string_attr(&path.join("manufacturer"));
    device.product_name = read_string_attr(&path.join("product"));
    device.revision = read_string_attr(&path.join("version"));
    device.device_class = read_hex_attr(&path.join("bDeviceClass")).unwrap_or(0) as u8;
    device.device_subclass = read_hex_attr(&path.join("bDeviceSubClass")).unwrap_or(0) as u8;
    device.has_hid_interface = check_for_hid_interface(&path);
    device.block_device = find_block_device(&path);

    Some(device)
}

fn read_hex_attr(path: &Path) -> Option<u16> {
    let content = std::fs::read_to_string(path).ok()?;
    u16::from_str_radix(content.trim(), 16).ok()
}

fn read_decimal_attr(path: &Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse().ok()
}

fn read_string_attr(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

fn check_for_hid_interface(device_path: &Path) -> bool {
    if let Ok(entries) = std::fs::read_dir(device_path) {
        for entry in entries.flatten() {
            let iface_class = entry.path().join("bInterfaceClass");
            if iface_class.exists() {
                if let Some(class) = read_hex_attr(&iface_class) {
                    if class == 0x03 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn find_block_device(device_path: &Path) -> Option<String> {
    fn search_recursive(path: &Path, depth: u8) -> Option<String> {
        if depth > 6 { return None; }
        let block_dir = path.join("block");
        if block_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&block_dir) {
                if let Some(entry) = entries.flatten().next() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    return Some(format!("/dev/{name}"));
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(dev) = search_recursive(&entry.path(), depth + 1) {
                        return Some(dev);
                    }
                }
            }
        }
        None
    }
    search_recursive(device_path, 0)
}
