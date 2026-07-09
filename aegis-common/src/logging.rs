use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::error::{AegisError, AegisResult};

type HmacSha256 = Hmac<Sha256>;

/// A single tamper-proof audit log entry with HMAC chain integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry identifier.
    pub id: Uuid,
    /// Sequence number (monotonically increasing).
    pub seq: u64,
    /// Timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Event category (device, policy, system, analysis).
    pub category: String,
    /// Event action (connected, authorized, blocked, etc.).
    pub action: String,
    /// Severity level (0-10).
    pub severity: u8,
    /// Human-readable description.
    pub message: String,
    /// Structured event data.
    pub data: serde_json::Value,
    /// HMAC of this entry chained with the previous entry's HMAC.
    pub hmac: String,
}

/// Tamper-proof append-only JSON logger with HMAC chaining.
///
/// Each log entry includes an HMAC computed over (previous_hmac + entry_data),
/// creating a hash chain that makes any modification or deletion detectable.
pub struct AuditLogger {
    log_path: PathBuf,
    hmac_key: Vec<u8>,
    current_seq: u64,
    previous_hmac: String,
}

impl AuditLogger {
    /// Initialize the logger, reading the last entry to resume the HMAC chain.
    pub fn new(log_path: &Path, hmac_key: &str) -> AegisResult<Self> {
        // Ensure parent directory exists.
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut current_seq = 0u64;
        let mut previous_hmac = "genesis".to_string();

        // Read the last entry to resume the chain.
        if log_path.exists() {
            let file = File::open(log_path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                    current_seq = entry.seq + 1;
                    previous_hmac = entry.hmac.clone();
                }
            }
        }

        Ok(Self {
            log_path: log_path.to_path_buf(),
            hmac_key: hmac_key.as_bytes().to_vec(),
            current_seq,
            previous_hmac,
        })
    }

    /// Append a new audit entry to the log.
    pub fn log(
        &mut self,
        category: &str,
        action: &str,
        severity: u8,
        message: &str,
        data: serde_json::Value,
    ) -> AegisResult<AuditEntry> {
        let entry_id = Uuid::new_v4();
        let timestamp = Utc::now();

        // Compute HMAC over: previous_hmac | seq | timestamp | category | action | message | data
        let chain_input = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.previous_hmac,
            self.current_seq,
            timestamp.to_rfc3339(),
            category,
            action,
            message,
            data,
        );

        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| AegisError::Internal(format!("HMAC init failed: {e}")))?;
        mac.update(chain_input.as_bytes());
        let hmac_result = hex::encode(mac.finalize().into_bytes());

        let entry = AuditEntry {
            id: entry_id,
            seq: self.current_seq,
            timestamp,
            category: category.to_string(),
            action: action.to_string(),
            severity,
            message: message.to_string(),
            data,
            hmac: hmac_result.clone(),
        };

        // Append to file.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let json_line = serde_json::to_string(&entry)?;
        writeln!(file, "{json_line}")?;

        // Advance chain state.
        self.current_seq += 1;
        self.previous_hmac = hmac_result;

        tracing::debug!(seq = entry.seq, category, action, "Audit entry logged");
        Ok(entry)
    }

    /// Verify the integrity of the entire log file.
    pub fn verify_integrity(&self) -> AegisResult<bool> {
        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);
        let mut prev_hmac = "genesis".to_string();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AegisError::Internal(format!("Line {line_num}: parse error: {e}")))?;

            // Recompute HMAC.
            let chain_input = format!(
                "{}|{}|{}|{}|{}|{}|{}",
                prev_hmac,
                entry.seq,
                entry.timestamp.to_rfc3339(),
                entry.category,
                entry.action,
                entry.message,
                entry.data,
            );

            let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
                .map_err(|e| AegisError::Internal(format!("HMAC init failed: {e}")))?;
            mac.update(chain_input.as_bytes());
            let expected = hex::encode(mac.finalize().into_bytes());

            if entry.hmac != expected {
                tracing::error!(
                    seq = entry.seq,
                    "TAMPER DETECTED at entry {} — HMAC mismatch",
                    entry.seq
                );
                return Ok(false);
            }

            prev_hmac = entry.hmac;
        }

        tracing::info!("Audit log integrity verified — all entries valid");
        Ok(true)
    }

    /// Read log entries with pagination.
    pub fn read_entries(
        &self,
        limit: usize,
        offset: usize,
    ) -> AegisResult<(Vec<AuditEntry>, usize)> {
        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        let mut total = 0usize;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            total += 1;
            if total > offset && entries.len() < limit {
                let entry: AuditEntry = serde_json::from_str(&line)?;
                entries.push(entry);
            }
        }

        Ok((entries, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_audit_log_write_and_verify() {
        let dir = std::env::temp_dir().join("aegis_test_log");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("test_audit.jsonl");

        let mut logger = AuditLogger::new(&log_path, "test-secret-key").unwrap();

        // Write 3 entries.
        logger
            .log(
                "device",
                "connected",
                1,
                "USB device inserted",
                serde_json::json!({"vid": "0781"}),
            )
            .unwrap();
        logger
            .log(
                "analysis",
                "completed",
                3,
                "Entropy scan passed",
                serde_json::json!({"score": 4.2}),
            )
            .unwrap();
        logger
            .log(
                "policy",
                "authorized",
                1,
                "Device approved by admin",
                serde_json::json!({}),
            )
            .unwrap();

        // Verify integrity.
        assert!(logger.verify_integrity().unwrap());

        // Read back.
        let (entries, total) = logger.read_entries(10, 0).unwrap();
        assert_eq!(total, 3);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[2].seq, 2);

        // Clean up.
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tamper_detection() {
        let dir = std::env::temp_dir().join("aegis_test_tamper");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("tamper_audit.jsonl");

        let mut logger = AuditLogger::new(&log_path, "secret").unwrap();
        logger
            .log("device", "connected", 1, "Device A", serde_json::json!({}))
            .unwrap();
        logger
            .log(
                "device",
                "blocked",
                5,
                "Device B blocked",
                serde_json::json!({}),
            )
            .unwrap();

        // Tamper with the log: modify the first line.
        let content = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let tampered = lines[0].replace("Device A", "TAMPERED");
        let new_content = format!("{}\n{}\n", tampered, lines[1]);
        fs::write(&log_path, new_content).unwrap();

        // Verification should fail.
        assert!(!logger.verify_integrity().unwrap());

        let _ = fs::remove_dir_all(&dir);
    }
}
