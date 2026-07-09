use chrono::Utc;
use sha2::{Digest, Sha256};
use std::io::Write;
use uuid::Uuid;

/// Honey-Token File Generation Module
///
/// Plants invisible tracking files on approved USB drives. If the USB
/// is later connected to a compromised machine that copies files,
/// these honey-tokens can be detected when they "phone home" (via
/// embedded tracking identifiers).
///
/// The honey-token is a seemingly innocent file (e.g., "~$desktop.ini",
/// ".thumbs.db", or a hidden dot file) that contains an embedded
/// unique UUID. When queried alongside a monitoring endpoint, this
/// allows attribution of data exfiltration.
///
/// Honey-token metadata stored alongside the generated file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HoneyTokenInfo {
    /// Unique tracking identifier embedded in the token.
    pub token_id: Uuid,
    /// Device session ID this token was planted on.
    pub device_session_id: Uuid,
    /// Device passport hash at time of planting.
    pub device_passport: String,
    /// Filename used for the honey file.
    pub filename: String,
    /// SHA-256 of the generated file content.
    pub content_hash: String,
    /// When the token was planted.
    pub planted_at: chrono::DateTime<Utc>,
}

/// Available honey-token file disguises.
const HONEY_FILENAMES: &[&str] = &[
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".directory",
    "~$Document.tmp",
    ".metadata_never_index",
];

/// Generate a honey-token file and its metadata.
///
/// Returns (filename, file_content, metadata).
pub fn generate_honey_token(
    device_session_id: Uuid,
    device_passport: &str,
) -> (String, Vec<u8>, HoneyTokenInfo) {
    let token_id = Uuid::new_v4();
    let now = Utc::now();

    // Select a filename based on the token UUID (deterministic per token).
    let filename_idx = (token_id.as_bytes()[0] as usize) % HONEY_FILENAMES.len();
    let filename = HONEY_FILENAMES[filename_idx].to_string();

    // Generate file content that looks innocuous but embeds the tracking ID.
    let content = generate_token_content(&token_id, &filename);

    // Hash the content for integrity verification.
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let content_hash = hex::encode(hasher.finalize());

    let info = HoneyTokenInfo {
        token_id,
        device_session_id,
        device_passport: device_passport.to_string(),
        filename: filename.clone(),
        content_hash,
        planted_at: now,
    };

    (filename, content, info)
}

/// Generate plausible file content that embeds the tracking UUID.
fn generate_token_content(token_id: &Uuid, filename: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    match filename {
        "desktop.ini" => {
            // Windows-like desktop.ini with UUID hidden in a comment.
            writeln!(buf, "[.ShellClassInfo]").unwrap();
            writeln!(buf, "IconResource=C:\\Windows\\System32\\SHELL32.dll,4").unwrap();
            writeln!(buf, "[ViewState]").unwrap();
            writeln!(buf, "Mode=").unwrap();
            writeln!(buf, "Vid=").unwrap();
            writeln!(buf, "; AEGIS-TK:{token_id}").unwrap();
        }
        ".directory" => {
            // KDE directory metadata.
            writeln!(buf, "[Desktop Entry]").unwrap();
            writeln!(buf, "Icon=folder").unwrap();
            writeln!(buf, "Comment=AEGIS-TK:{token_id}").unwrap();
        }
        _ => {
            // Binary-looking token with magic bytes + hidden UUID.
            buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // fake magic
            buf.extend_from_slice(&[0x20; 32]); // padding
            buf.extend_from_slice(token_id.as_bytes()); // embedded UUID
            buf.extend_from_slice(&[0x00; 48]); // trailing padding
        }
    }

    buf
}

/// Verify if a file content contains a known honey-token.
pub fn extract_token_id(content: &[u8]) -> Option<Uuid> {
    // Try to find text-based token.
    if let Ok(text) = std::str::from_utf8(content)
        && let Some(pos) = text.find("AEGIS-TK:")
    {
        let uuid_start = pos + "AEGIS-TK:".len();
        let uuid_str = &text[uuid_start..].trim();
        if uuid_str.len() >= 36
            && let Ok(id) = Uuid::parse_str(&uuid_str[..36])
        {
            return Some(id);
        }
    }

    // Try to find binary-embedded UUID (after 36-byte header).
    if content.len() >= 52 {
        let uuid_bytes = &content[36..52];
        if let Ok(id) = Uuid::from_slice(uuid_bytes)
            && !id.is_nil()
        {
            return Some(id);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_token() {
        let session_id = Uuid::new_v4();
        let passport = "abc123def456";

        let (filename, content, info) = generate_honey_token(session_id, passport);

        assert!(!filename.is_empty());
        assert!(!content.is_empty());
        assert_eq!(info.device_session_id, session_id);
        assert_eq!(info.device_passport, passport);

        // Verify the embedded token can be extracted.
        let extracted = extract_token_id(&content);
        assert!(
            extracted.is_some(),
            "Should be able to extract token from content"
        );
        assert_eq!(extracted.unwrap(), info.token_id);
    }

    #[test]
    fn test_no_false_positive() {
        let normal_content = b"This is a totally normal file with no tokens.";
        assert!(extract_token_id(normal_content).is_none());
    }

    #[test]
    fn test_different_devices_different_tokens() {
        let (_, _, info1) = generate_honey_token(Uuid::new_v4(), "pass1");
        let (_, _, info2) = generate_honey_token(Uuid::new_v4(), "pass2");
        assert_ne!(info1.token_id, info2.token_id);
    }
}
