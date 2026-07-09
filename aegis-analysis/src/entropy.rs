use aegis_common::device::{AnalysisResult, AnalysisType};
use chrono::Utc;

/// Calculate Shannon entropy of a byte buffer.
///
/// Shannon entropy measures the randomness/information density of data.
/// - Normal text: ~3.5-5.0 bits/byte
/// - Compressed data: ~7.0-7.5 bits/byte
/// - Encrypted/random: ~7.9-8.0 bits/byte
///
/// Files with entropy above the threshold (default 7.5) are flagged as
/// potentially encrypted payloads (ransomware, packed malware).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Analyze a file buffer and return an AnalysisResult.
pub fn analyze_buffer(filename: &str, data: &[u8], threshold: f64) -> AnalysisResult {
    let entropy = calculate_entropy(data);
    let flagged = entropy > threshold;

    let severity = if entropy > 7.9 {
        9 // Almost certainly encrypted/random
    } else if entropy > 7.5 {
        6 // Likely compressed or packed
    } else if entropy > 7.0 {
        3 // Moderately high — could be binary
    } else {
        0 // Normal
    };

    let summary = if flagged {
        format!(
            "⚠️ High entropy detected in '{filename}': {entropy:.3} bits/byte (threshold: {threshold:.1})"
        )
    } else {
        format!("✅ Entropy normal for '{filename}': {entropy:.3} bits/byte")
    };

    AnalysisResult {
        analysis_type: AnalysisType::Entropy,
        flagged,
        severity,
        summary,
        details: serde_json::json!({
            "filename": filename,
            "entropy": entropy,
            "threshold": threshold,
            "size_bytes": data.len(),
        }),
        timestamp: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_single_byte() {
        // All same bytes = zero entropy.
        let data = vec![0xAA; 1024];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_low_text() {
        let data = b"Hello World! This is a simple English text with normal entropy.";
        let entropy = calculate_entropy(data);
        assert!(
            entropy > 3.0 && entropy < 5.5,
            "Text entropy should be 3-5.5, got {entropy}"
        );
    }

    #[test]
    fn test_entropy_high_random() {
        // Pseudo-random: all 256 byte values equally distributed.
        let mut data = Vec::new();
        for _ in 0..100 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        let entropy = calculate_entropy(&data);
        assert!(
            entropy > 7.9,
            "Random data should have entropy > 7.9, got {entropy}"
        );
    }

    #[test]
    fn test_analyze_flags_high_entropy() {
        let mut data = Vec::new();
        for _ in 0..100 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        let result = analyze_buffer("suspicious.bin", &data, 7.5);
        assert!(result.flagged);
        assert!(result.severity >= 6);
    }

    #[test]
    fn test_analyze_passes_low_entropy() {
        let data = b"This is a perfectly normal README file with simple content.";
        let result = analyze_buffer("readme.txt", data, 7.5);
        assert!(!result.flagged);
        assert_eq!(result.severity, 0);
    }
}
