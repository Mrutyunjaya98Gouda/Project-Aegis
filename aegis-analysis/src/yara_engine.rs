use aegis_common::device::{AnalysisResult, AnalysisType};
use chrono::Utc;
use std::path::Path;

/// YARA-X signature scanning engine.
pub struct YaraEngine {
    rules: yara_x::Rules,
}

impl YaraEngine {
    pub fn new(rules_path: &Path) -> anyhow::Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        let mut has_rules = false;

        if rules_path.exists() && rules_path.is_dir() {
            for entry in std::fs::read_dir(rules_path)? {
                let entry = entry?;
                if let Some(ext) = entry.path().extension() {
                    if ext == "yar" || ext == "yara" {
                        match std::fs::read_to_string(entry.path()) {
                            Ok(rule_text) => {
                                if let Err(e) = compiler.add_source(rule_text.as_str()) {
                                    tracing::warn!("Failed to compile rule file {}: {}", entry.path().display(), e);
                                } else {
                                    has_rules = true;
                                }
                            }
                            Err(e) => tracing::warn!("Failed to read rule file {}: {}", entry.path().display(), e),
                        }
                    }
                }
            }
        }

        if !has_rules {
            tracing::warn!("No valid YARA rules found at {}", rules_path.display());
            // Add a dummy rule so build doesn't fail
            compiler.add_source("rule dummy { condition: false }").unwrap();
        }

        let rules = compiler.build();
        Ok(Self { rules })
    }

    pub fn scan_buffer(&self, filename: &str, data: &[u8]) -> AnalysisResult {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let mut matches = Vec::new();
        
        match scanner.scan(data) {
            Ok(results) => {
                for matching_rule in results.matching_rules() {
                    matches.push(serde_json::json!({
                        "rule": matching_rule.identifier(),
                        "namespace": matching_rule.namespace(),
                    }));
                }
            }
            Err(e) => {
                tracing::warn!("YARA scan error on {}: {}", filename, e);
            }
        }

        let flagged = !matches.is_empty();
        let max_severity = if flagged { 8 } else { 0 }; // Baseline severity if matched
        
        let summary = if flagged {
            format!(
                "🚨 {} YARA signature(s) matched in '{filename}'",
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
            }),
            timestamp: Utc::now(),
        }
    }
}
