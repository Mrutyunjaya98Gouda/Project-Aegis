use aegis_common::device::{AnalysisResult, AnalysisType};
use chrono::Utc;

/// YARA-X signature scanning engine.
///
/// This module provides structural pattern matching against file buffers
/// using YARA rules. In this initial implementation, we use a built-in
/// set of basic signatures. Full YARA-X integration requires the `yara-x`
/// crate, which will be added when external rule files are loaded.
///
/// Built-in signatures detect:
/// - PE (Windows executable) headers
/// - ELF (Linux executable) headers  
/// - Known ransomware strings
/// - Suspicious script patterns
/// - Packed/UPX compressed binaries
///
/// A simple pattern-based signature for built-in detection.
struct BuiltinSignature {
    name: &'static str,
    description: &'static str,
    patterns: &'static [&'static [u8]],
    severity: u8,
}

const BUILTIN_SIGNATURES: &[BuiltinSignature] = &[
    BuiltinSignature {
        name: "pe_executable",
        description: "Windows PE executable detected",
        patterns: &[b"MZ"],
        severity: 5,
    },
    BuiltinSignature {
        name: "elf_executable",
        description: "Linux ELF executable detected",
        patterns: &[b"\x7fELF"],
        severity: 5,
    },
    BuiltinSignature {
        name: "upx_packed",
        description: "UPX-packed binary detected (common malware packing)",
        patterns: &[b"UPX0", b"UPX1", b"UPX!"],
        severity: 7,
    },
    BuiltinSignature {
        name: "powershell_encoded",
        description: "Base64-encoded PowerShell command detected",
        patterns: &[
            b"-EncodedCommand",
            b"-enc ",
            b"powershell -e ",
            b"FromBase64String",
        ],
        severity: 8,
    },
    BuiltinSignature {
        name: "ransomware_strings",
        description: "Known ransomware indicator strings detected",
        patterns: &[
            b"YOUR FILES HAVE BEEN ENCRYPTED",
            b"All your files are encrypted",
            b"bitcoin wallet",
            b"pay the ransom",
            b"decrypt your files",
        ],
        severity: 10,
    },
    BuiltinSignature {
        name: "suspicious_autorun",
        description: "Autorun.inf detected (potential auto-execution vector)",
        patterns: &[b"[autorun]", b"[AutoRun]"],
        severity: 8,
    },
    BuiltinSignature {
        name: "macro_vba",
        description: "VBA macro code detected",
        patterns: &[b"Sub Auto", b"Sub Workbook_Open", b"Sub Document_Open"],
        severity: 6,
    },
    BuiltinSignature {
        name: "shellcode_nopsled",
        description: "Potential NOP sled detected (shellcode indicator)",
        patterns: &[b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"],
        severity: 9,
    },
];

/// Scan a file buffer against built-in YARA-like signatures.
pub fn scan_buffer(filename: &str, data: &[u8]) -> AnalysisResult {
    let mut matches: Vec<serde_json::Value> = Vec::new();
    let mut max_severity = 0u8;

    for sig in BUILTIN_SIGNATURES {
        for pattern in sig.patterns {
            if contains_pattern(data, pattern) {
                matches.push(serde_json::json!({
                    "rule": sig.name,
                    "description": sig.description,
                    "severity": sig.severity,
                }));
                if sig.severity > max_severity {
                    max_severity = sig.severity;
                }
                break; // One match per signature is enough.
            }
        }
    }

    let flagged = !matches.is_empty();
    let summary = if flagged {
        format!(
            "🚨 {} YARA signature(s) matched in '{filename}' (max severity: {max_severity})",
            matches.len()
        )
    } else {
        format!("✅ No YARA signatures matched in '{filename}'")
    };

    AnalysisResult {
        analysis_type: AnalysisType::YaraSignature,
        flagged,
        severity: max_severity,
        summary,
        details: serde_json::json!({
            "filename": filename,
            "matches": matches,
            "total_rules_checked": BUILTIN_SIGNATURES.len(),
        }),
        timestamp: Utc::now(),
    }
}

/// Simple byte pattern search (Boyer-Moore would be better for production).
fn contains_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_text_file() {
        let data = b"This is a perfectly safe text file with nothing malicious.";
        let result = scan_buffer("readme.txt", data);
        assert!(!result.flagged);
        assert_eq!(result.severity, 0);
    }

    #[test]
    fn test_detect_pe_header() {
        let mut data = Vec::new();
        data.extend_from_slice(b"MZ");
        data.extend_from_slice(&[0x90; 100]);
        let result = scan_buffer("malware.exe", &data);
        assert!(result.flagged);
        assert!(result.severity >= 5);
    }

    #[test]
    fn test_detect_elf_header() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x7fELF");
        data.extend_from_slice(&[0x00; 100]);
        let result = scan_buffer("backdoor", &data);
        assert!(result.flagged);
    }

    #[test]
    fn test_detect_ransomware_string() {
        let data = b"WARNING: YOUR FILES HAVE BEEN ENCRYPTED. Send 1 BTC to recover.";
        let result = scan_buffer("README.txt", data);
        assert!(result.flagged);
        assert_eq!(result.severity, 10);
    }

    #[test]
    fn test_detect_autorun() {
        let data = b"[autorun]\nopen=virus.exe\n";
        let result = scan_buffer("autorun.inf", data);
        assert!(result.flagged);
        assert!(result.severity >= 8);
    }

    #[test]
    fn test_detect_upx_packed() {
        let mut data = Vec::new();
        data.extend_from_slice(b"UPX!");
        data.extend_from_slice(&[0xCC; 200]);
        let result = scan_buffer("packed.bin", &data);
        assert!(result.flagged);
        assert!(result.severity >= 7);
    }
}
