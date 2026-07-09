use aegis_common::config::GeofenceRule;
use aegis_common::device::{PortLocation, UsbDevice};
use std::collections::HashMap;

/// Physical topology geo-fencing engine.
///
/// Enforces USB mount policies based on the physical port location
/// where a device is connected. For example:
/// - Allow flash drives only on rear I/O ports (admin workstation)
/// - Block all front-panel USB in kiosk mode
/// - Restrict hub-connected devices to specific classes
pub struct GeofenceEngine {
    rules: HashMap<String, GeofenceRule>,
}

impl GeofenceEngine {
    pub fn new(rules: HashMap<String, GeofenceRule>) -> Self {
        Self { rules }
    }

    /// Determine the port location from a USB port path string.
    ///
    /// Heuristic mapping (Linux-specific):
    /// - Ports starting with "1-" or "2-" with depth 1 → Rear I/O
    /// - Ports with "-1." pattern (hub) → Hub
    /// - Port paths with higher bus numbers → typically front panel
    pub fn classify_port(port_path: &str) -> PortLocation {
        if port_path.is_empty() {
            return PortLocation::Unknown;
        }

        // Hub detection: if there's a dot, it's through a hub.
        if port_path.contains('.') {
            return PortLocation::Hub;
        }

        // Simple heuristic based on bus-port pattern.
        // Most motherboards expose rear USB on bus 1-2, ports 1-4
        // Front panel headers are typically bus 1-2, ports 5+
        let parts: Vec<&str> = port_path.split('-').collect();
        if parts.len() == 2
            && let Ok(port_num) = parts[1].parse::<u32>()
        {
            if port_num <= 4 {
                return PortLocation::RearIO;
            } else {
                return PortLocation::FrontPanel;
            }
        }

        PortLocation::Unknown
    }

    /// Check if a device is allowed based on its physical port location.
    pub fn check_device(&self, device: &UsbDevice) -> GeofenceResult {
        let location = Self::classify_port(&device.port_path);

        // Find a matching rule for this location.
        for rule in self.rules.values() {
            if rule.location == location {
                if !rule.allowed {
                    return GeofenceResult {
                        allowed: false,
                        location,
                        reason: format!(
                            "Port {} ({:?}) is blocked by geo-fence policy",
                            device.port_path, location
                        ),
                    };
                }

                // Check class restrictions if defined.
                if let Some(ref allowed_classes) = rule.allowed_classes
                    && !allowed_classes.contains(&device.device_class)
                {
                    return GeofenceResult {
                        allowed: false,
                        location,
                        reason: format!(
                            "Device class 0x{:02X} not permitted on {:?} ports",
                            device.device_class, location
                        ),
                    };
                }

                return GeofenceResult {
                    allowed: true,
                    location,
                    reason: "Permitted by geo-fence policy".to_string(),
                };
            }
        }

        // Default: allow if no specific rule exists.
        GeofenceResult {
            allowed: true,
            location,
            reason: "No geo-fence rule for this port location — default allow".to_string(),
        }
    }
}

/// Result of a geo-fence check.
#[derive(Debug, Clone)]
pub struct GeofenceResult {
    pub allowed: bool,
    #[allow(dead_code)]
    pub location: PortLocation,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::config::GeofenceRule;

    #[test]
    fn test_port_classification() {
        assert_eq!(GeofenceEngine::classify_port("1-2"), PortLocation::RearIO);
        assert_eq!(GeofenceEngine::classify_port("1-3"), PortLocation::RearIO);
        assert_eq!(
            GeofenceEngine::classify_port("1-6"),
            PortLocation::FrontPanel
        );
        assert_eq!(GeofenceEngine::classify_port("1-2.3"), PortLocation::Hub);
        assert_eq!(GeofenceEngine::classify_port(""), PortLocation::Unknown);
    }

    #[test]
    fn test_block_front_panel() {
        let mut rules = HashMap::new();
        rules.insert(
            "front".to_string(),
            GeofenceRule {
                location: PortLocation::FrontPanel,
                allowed: false,
                allowed_classes: None,
            },
        );

        let engine = GeofenceEngine::new(rules);
        let device = UsbDevice::new(0x0781, 0x5583, "1-6".into(), 1, 6, "/sys/test".into());

        let result = engine.check_device(&device);
        assert!(!result.allowed);
        assert_eq!(result.location, PortLocation::FrontPanel);
    }

    #[test]
    fn test_allow_rear_io() {
        let mut rules = HashMap::new();
        rules.insert(
            "rear".to_string(),
            GeofenceRule {
                location: PortLocation::RearIO,
                allowed: true,
                allowed_classes: None,
            },
        );

        let engine = GeofenceEngine::new(rules);
        let device = UsbDevice::new(0x0781, 0x5583, "1-2".into(), 1, 2, "/sys/test".into());

        let result = engine.check_device(&device);
        assert!(result.allowed);
    }
}
