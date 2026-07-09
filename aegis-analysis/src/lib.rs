pub mod entropy;
pub mod hid_spoof;
pub mod honey_token;
pub mod ml_anomaly;
pub mod threat_intel;
pub mod yara_engine;

use aegis_common::device::{AnalysisResult, UsbDevice};
use aegis_common::error::AegisResult;

/// The unified analysis pipeline that runs all enabled checks on a device.
pub struct AnalysisPipeline {
    pub entropy_enabled: bool,
    pub entropy_threshold: f64,
    pub yara_enabled: bool,
    pub hid_spoof_enabled: bool,
}

impl AnalysisPipeline {
    pub fn new(entropy_threshold: f64, yara_enabled: bool, hid_spoof_enabled: bool) -> Self {
        Self {
            entropy_enabled: true,
            entropy_threshold,
            yara_enabled,
            hid_spoof_enabled,
        }
    }

    /// Run all enabled analysis passes on a device. Returns a trust score (0-100).
    pub fn analyze(
        &self,
        device: &UsbDevice,
        file_buffers: &[(&str, &[u8])],
    ) -> AegisResult<(u8, Vec<AnalysisResult>)> {
        let mut results = Vec::new();
        let mut penalty: i32 = 0;

        // 1. HID Spoof Detection
        if self.hid_spoof_enabled {
            let result = hid_spoof::check_hid_spoof(device);
            if result.flagged {
                penalty += 50; // Severe — potential BadUSB
            }
            results.push(result);
        }

        // 2. Entropy Analysis on file buffers
        if self.entropy_enabled {
            for (filename, buffer) in file_buffers {
                let result = entropy::analyze_buffer(filename, buffer, self.entropy_threshold);
                if result.flagged {
                    penalty += 15;
                }
                results.push(result);
            }
        }

        // 3. YARA Signature Scan (placeholder — real engine in yara_engine module)
        if self.yara_enabled {
            for (filename, buffer) in file_buffers {
                let result = yara_engine::scan_buffer(filename, buffer);
                if result.flagged {
                    penalty += 30;
                }
                results.push(result);
            }
        }

        // Compute trust score: start at 100, subtract penalties, floor at 0.
        let trust_score = (100i32 - penalty).max(0) as u8;

        Ok((trust_score, results))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::device::UsbDevice;

    #[test]
    fn test_pipeline_clean_device() {
        let device = UsbDevice::new(
            0x0781,
            0x5583,
            "1-2".to_string(),
            1,
            3,
            "/sys/bus/usb/001/003".to_string(),
        );
        let pipeline = AnalysisPipeline::new(7.5, false, true);

        let clean_data = b"Hello, this is a normal text file with low entropy content.";
        let buffers: Vec<(&str, &[u8])> = vec![("readme.txt", clean_data)];

        let (score, results) = pipeline.analyze(&device, &buffers).unwrap();
        assert!(
            score >= 85,
            "Clean device should have high trust score, got {score}"
        );
        assert!(!results.is_empty());
    }
}
