/// ML-Based Keystroke Anomaly Detection Module (Stub)
///
/// NOTE: This module is currently a heuristic stub. It is NOT integrated 
/// into the main analysis pipeline (`lib.rs`). A real implementation would 
/// use an ONNX runtime to run a pre-trained model that analyzes HID input event
/// timing patterns.
///
/// BadUSB detection heuristics:
/// - Superhuman typing speed (< 20ms between keystrokes)
/// - Perfectly uniform inter-key intervals (no human variation)
/// - Burst patterns: rapid typing with no pauses
/// - Suspicious key sequences (rapid Alt+Tab, Win+R, etc.)
use aegis_common::device::AnalysisResult;
use aegis_common::device::AnalysisType;
use chrono::Utc;

/// Represents a single HID input event from a device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeystrokeEvent {
    /// Timestamp in microseconds (monotonic).
    pub timestamp_us: u64,
    /// HID usage code (key identifier).
    pub usage_code: u16,
    /// Whether this is a key press (true) or release (false).
    pub pressed: bool,
}

/// Configuration for the anomaly detector.
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Minimum inter-key interval in microseconds considered human.
    pub min_human_interval_us: u64,
    /// Maximum coefficient of variation for "too uniform" detection.
    pub max_uniformity_score: f64,
    /// Minimum number of events needed for analysis.
    pub min_events: usize,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            min_human_interval_us: 20_000, // 20ms
            max_uniformity_score: 0.05,    // 5% variation
            min_events: 10,
        }
    }
}

/// Analyze a sequence of keystroke events for anomalies.
///
/// Returns an analysis result indicating whether the input pattern
/// appears synthetic (BadUSB) or human.
///
/// **Note**: This is a heuristic stub. Production implementation would
/// load an ONNX model for more sophisticated classification.
pub fn analyze_keystrokes(events: &[KeystrokeEvent], config: &AnomalyConfig) -> AnalysisResult {
    if events.len() < config.min_events {
        return AnalysisResult {
            analysis_type: AnalysisType::KeystrokeAnomaly,
            flagged: false,
            severity: 0,
            summary: "⏳ Insufficient keystroke data for analysis".to_string(),
            details: serde_json::json!({"event_count": events.len(), "min_required": config.min_events}),
            timestamp: Utc::now(),
        };
    }

    // Calculate inter-key intervals.
    let press_events: Vec<&KeystrokeEvent> = events.iter().filter(|e| e.pressed).collect();
    if press_events.len() < 2 {
        return AnalysisResult {
            analysis_type: AnalysisType::KeystrokeAnomaly,
            flagged: false,
            severity: 0,
            summary: "⏳ Not enough press events for timing analysis".to_string(),
            details: serde_json::json!({"press_count": press_events.len()}),
            timestamp: Utc::now(),
        };
    }

    let intervals: Vec<u64> = press_events
        .windows(2)
        .map(|w| w[1].timestamp_us.saturating_sub(w[0].timestamp_us))
        .collect();

    let mean_interval = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;

    // Check 1: Superhuman speed.
    let superhuman_count = intervals
        .iter()
        .filter(|&&i| i < config.min_human_interval_us)
        .count();
    let superhuman_ratio = superhuman_count as f64 / intervals.len() as f64;

    // Check 2: Uniformity (coefficient of variation).
    let variance = intervals
        .iter()
        .map(|&i| {
            let diff = i as f64 - mean_interval;
            diff * diff
        })
        .sum::<f64>()
        / intervals.len() as f64;
    let std_dev = variance.sqrt();
    let cv = if mean_interval > 0.0 {
        std_dev / mean_interval
    } else {
        0.0
    };

    let too_fast = superhuman_ratio > 0.5;
    let too_uniform = cv < config.max_uniformity_score;
    let flagged = too_fast || too_uniform;

    let severity = if too_fast && too_uniform {
        9
    } else if too_fast {
        7
    } else if too_uniform {
        6
    } else {
        0
    };

    let summary = if flagged {
        format!(
            "🚨 Synthetic input detected — speed: {:.0}µs avg, uniformity CV: {:.4}, superhuman: {:.0}%",
            mean_interval,
            cv,
            superhuman_ratio * 100.0
        )
    } else {
        format!(
            "✅ Human-like input pattern — speed: {:.0}µs avg, CV: {:.4}",
            mean_interval, cv
        )
    };

    AnalysisResult {
        analysis_type: AnalysisType::KeystrokeAnomaly,
        flagged,
        severity,
        summary,
        details: serde_json::json!({
            "mean_interval_us": mean_interval,
            "coefficient_of_variation": cv,
            "superhuman_ratio": superhuman_ratio,
            "total_intervals": intervals.len(),
            "too_fast": too_fast,
            "too_uniform": too_uniform,
        }),
        timestamp: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_fast_input() {
        // BadUSB: 5ms between keystrokes, perfectly uniform.
        let events: Vec<KeystrokeEvent> = (0..20)
            .map(|i| KeystrokeEvent {
                timestamp_us: i * 5_000,
                usage_code: 0x04 + (i as u16 % 26),
                pressed: true,
            })
            .collect();

        let result = analyze_keystrokes(&events, &AnomalyConfig::default());
        assert!(result.flagged, "Should detect superhuman speed");
        assert!(result.severity >= 7);
    }

    #[test]
    fn test_human_like_input() {
        // Simulate human typing: ~80ms avg with ±30ms jitter.
        let base_intervals = [
            75000, 110000, 60000, 95000, 80000, 120000, 70000, 90000, 85000, 100000, 65000,
        ];
        let mut timestamp = 0u64;
        let events: Vec<KeystrokeEvent> = base_intervals
            .iter()
            .enumerate()
            .map(|(i, &interval)| {
                timestamp += interval;
                KeystrokeEvent {
                    timestamp_us: timestamp,
                    usage_code: 0x04 + (i as u16 % 26),
                    pressed: true,
                }
            })
            .collect();

        let result = analyze_keystrokes(&events, &AnomalyConfig::default());
        assert!(!result.flagged, "Human-like typing should not be flagged");
    }

    #[test]
    fn test_insufficient_data() {
        let events = vec![KeystrokeEvent {
            timestamp_us: 0,
            usage_code: 0x04,
            pressed: true,
        }];
        let result = analyze_keystrokes(&events, &AnomalyConfig::default());
        assert!(!result.flagged);
    }
}
