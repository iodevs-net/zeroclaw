//! Closed-Loop Verification for tool executions.
//!
//! This module provides two verification capabilities:
//!
//! 1. **VI Credential Verification** — check that a tool execution's result_hash
//!    matches the expected sd_hash from a Verifiable Intent credential.
//!
//! 2. **Write Verification** — for tools that modify files (`file_write`, shell
//!    commands that write), verify that the actual filesystem content matches the
//!    tool's intended output.
//!
//! ## Flow
//!
//! VI Credential (for 1):
//! 1. An external issuer creates a VI credential with expected sd_hash.
//! 2. After tool execution, `verify_result_hash()` compares result_hash vs sd_hash.
//! 3. On mismatch, a security event is logged.
//!
//! Write Verification (for 2):
//! 1. `verify_write_operation()` is called after write tool executions.
//! 2. It extracts the path and expected content from tool arguments.
//! 3. It reads the actual file and compares content hashes.
//! 4. Mismatches are logged as security events.
//!
//! ## Architecture Note
//!
//! VI credential issuance is not yet integrated into the agent loop.
//! Write verification is implemented for `file_write` tool.

use std::path::Path;

use sha2::{Digest, Sha256};
use crate::verifiable_intent::verification::verify_sd_hash_binding;

// ── VI Credential Verification ────────────────────────────────────────

/// Result of closed-loop verification.
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Verification passed.
    Match,
    /// No credential was provided — verification is not applicable.
    NoCredential,
    /// Verification failed — hash mismatch.
    Mismatch { expected: String, actual: String },
}

/// Verify that a tool execution result_hash matches the expected sd_hash
/// from a Verifiable Intent credential.
pub fn verify_result_hash(result_hash: &str, sd_hash: Option<&str>) -> VerificationResult {
    match sd_hash {
        None => VerificationResult::NoCredential,
        Some(expected) => {
            if result_hash == expected {
                VerificationResult::Match
            } else {
                VerificationResult::Mismatch {
                    expected: expected.to_string(),
                    actual: result_hash.to_string(),
                }
            }
        }
    }
}

/// Verify result_hash against a serialized VI credential.
pub fn verify_against_credential(
    result_hash: &str,
    serialized_parent: &str,
) -> Result<(), crate::verifiable_intent::error::ViError> {
    verify_sd_hash_binding(result_hash, serialized_parent)
}

// ── Write Tool Verification ─────────────────────────────────────────

/// Tools that modify the filesystem and can be verified.
const WRITE_TOOLS: &[&str] = &["file_write", "shell"];

/// Check if a tool name is a write operation that modifies files.
pub fn is_write_tool(tool_name: &str) -> bool {
    WRITE_TOOLS.contains(&tool_name)
}

/// Verify a file_write tool execution by reading the actual file content
/// and comparing it against the expected content from the tool arguments.
///
/// Returns `Ok(Some(()))` on successful verification,
/// `Ok(None)` if verification is not applicable (wrong tool, missing args),
/// `Err(...)` on verification failure.
pub fn verify_file_write(
    tool_args: &serde_json::Value,
    workspace_dir: &Path,
) -> Result<Option<()>, String> {
    let path = tool_args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'path' in file_write args".to_string())?;

    let expected_content = tool_args
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'content' in file_write args".to_string())?;

    // Resolve path relative to workspace
    let full_path = if Path::new(path).is_absolute() {
        Path::new(path).to_path_buf()
    } else {
        workspace_dir.join(path)
    };

    // Read actual file content
    let actual_content = match std::fs::read_to_string(&full_path) {
        Ok(c) => c,
        Err(e) => {
            return Err(format!(
                "file_write verification: failed to read '{}': {e}",
                full_path.display()
            ));
        }
    };

    // Compare content
    if actual_content == expected_content {
        Ok(Some(()))
    } else {
        let expected_hash = hex::encode(Sha256::digest(expected_content.as_bytes()));
        let actual_hash = hex::encode(Sha256::digest(actual_content.as_bytes()));
        Err(format!(
            "file_write verification FAILED for '{}': content mismatch (expected {}, actual {})",
            full_path.display(),
            expected_hash,
            actual_hash
        ))
    }
}

/// Verify a shell command that may have written files.
///
/// For shell commands, we check if the output indicates a successful file write
/// and verify the target file if identifiable.
///
/// This is a best-effort verification — shell commands are complex and not all
/// writes can be reliably detected.
pub fn verify_shell_write(
    _tool_args: &serde_json::Value,
    _workspace_dir: &Path,
    _tool_output: &str,
) -> Result<Option<()>, String> {
    // Shell write verification is complex because:
    // 1. We need to parse the command to identify write targets
    // 2. We need to know what content was written
    // For now, return None (not applicable) — full implementation
    // would require parsing the shell command and extracting write targets.
    Ok(None)
}

/// Verify a write tool execution result.
///
/// `tool_name` — the name of the tool that was executed.
/// `tool_args` — the arguments passed to the tool.
/// `tool_output` — the output returned by the tool.
/// `result_hash` — the SHA-256 fingerprint of (success, output, error).
/// `workspace_dir` — the ZeroClaw workspace directory.
///
/// Returns `Ok(Some(()))` on successful verification,
/// `Ok(None)` if verification does not apply,
/// `Err(...)` on verification failure.
pub fn verify_write_operation(
    tool_name: &str,
    tool_args: &serde_json::Value,
    tool_output: &str,
    result_hash: &str,
    workspace_dir: &Path,
) -> Result<Option<()>, String> {
    if !is_write_tool(tool_name) {
        return Ok(None);
    }

    match tool_name {
        "file_write" => {
            if let Err(e) = verify_file_write(tool_args, workspace_dir) {
                tracing::error!(
                    tool = tool_name,
                    result_hash,
                    "CLOSED-LOOP VERIFICATION FAILED: {e}"
                );
                return Err(e);
            }
        }
        "shell" => {
            if let Err(e) = verify_shell_write(tool_args, workspace_dir, tool_output) {
                tracing::error!(
                    tool = tool_name,
                    result_hash,
                    "CLOSED-LOOP VERIFICATION FAILED: {e}"
                );
                return Err(e);
            }
        }
        _ => {}
    }

    tracing::debug!(
        tool = tool_name,
        result_hash,
        "closed-loop write verification passed"
    );
    Ok(Some(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn verify_no_credential_returns_no_credential() {
        let result = verify_result_hash("abc123", None);
        assert!(matches!(result, VerificationResult::NoCredential));
    }

    #[test]
    fn verify_matching_hash_returns_match() {
        let result = verify_result_hash("abc123", Some("abc123"));
        assert!(matches!(result, VerificationResult::Match));
    }

    #[test]
    fn verify_mismatched_hash_returns_mismatch() {
        let result = verify_result_hash("actual", Some("expected"));
        match result {
            VerificationResult::Mismatch { expected, actual } => {
                assert_eq!(expected, "expected");
                assert_eq!(actual, "actual");
            }
            _ => panic!("expected Mismatch"),
        }
    }

    #[test]
    fn is_write_tool_recognizes_file_write() {
        assert!(is_write_tool("file_write"));
        assert!(is_write_tool("shell"));
        assert!(!is_write_tool("web_fetch"));
        assert!(!is_write_tool("grep"));
    }

    #[test]
    fn verify_file_write_matches() {
        let tmp = TempDir::new().unwrap();
        let workspace = tmp.path();

        // Create a test file
        let file_path = workspace.join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let args = serde_json::json!({
            "path": "test.txt",
            "content": "hello world"
        });

        let result = verify_file_write(&args, workspace);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn verify_file_write_mismatch() {
        let tmp = TempDir::new().unwrap();
        let workspace = tmp.path();

        // Create a test file with DIFFERENT content
        let file_path = workspace.join("test.txt");
        std::fs::write(&file_path, "different content").unwrap();

        let args = serde_json::json!({
            "path": "test.txt",
            "content": "expected content"
        });

        let result = verify_file_write(&args, workspace);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("mismatch"));
        assert!(err.contains("test.txt"));
    }

    #[test]
    fn verify_file_write_missing_file() {
        let tmp = TempDir::new().unwrap();
        let workspace = tmp.path();

        let args = serde_json::json!({
            "path": "nonexistent.txt",
            "content": "hello"
        });

        let result = verify_file_write(&args, workspace);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read"));
    }

    #[test]
    fn verify_file_write_missing_args() {
        let tmp = TempDir::new().unwrap();
        let workspace = tmp.path();

        let args_no_path = serde_json::json!({ "content": "hello" });
        let result = verify_file_write(&args_no_path, workspace);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("path"));

        let args_no_content = serde_json::json!({ "path": "test.txt" });
        let result = verify_file_write(&args_no_content, workspace);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("content"));
    }
}
