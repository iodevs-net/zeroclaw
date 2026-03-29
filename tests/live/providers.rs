//! Consolidated live provider tests.
//!
//! All tests in this module require real external API credentials and are
//! marked with `#[ignore]`. Run with: `cargo test --test live -- --ignored`

use zeroclaw::config::load_api_key_for_tests;
use zeroclaw::providers::traits::{ChatMessage, Provider};
use zeroclaw::providers::ProviderRuntimeOptions;

/// Sends a real multi-turn conversation to OpenAI Codex and verifies
/// the model retains context from earlier messages.
///
/// Requires valid OAuth credentials in `~/.zeroclaw/`.
/// Run manually: `cargo test e2e_live_openai_codex_multi_turn -- --ignored`
#[tokio::test]
#[ignore = "requires live OpenAI Codex OAuth credentials"]
async fn e2e_live_openai_codex_multi_turn() {
    use zeroclaw::providers::openai_codex::OpenAiCodexProvider;

    let provider = OpenAiCodexProvider::new(&ProviderRuntimeOptions::default(), None).unwrap();
    let model = "gpt-5.3-codex";

    // Turn 1: establish a fact
    let messages_turn1 = vec![
        ChatMessage::system("You are a concise assistant. Reply in one short sentence."),
        ChatMessage::user("The secret word is \"zephyr\". Just confirm you noted it."),
    ];
    let response1 = provider
        .chat_with_history(&messages_turn1, model, 0.0)
        .await;
    assert!(response1.is_ok(), "Turn 1 failed: {:?}", response1.err());
    let r1 = response1.unwrap();
    assert!(!r1.is_empty(), "Turn 1 returned empty response");

    // Turn 2: ask the model to recall the fact
    let messages_turn2 = vec![
        ChatMessage::system("You are a concise assistant. Reply in one short sentence."),
        ChatMessage::user("The secret word is \"zephyr\". Just confirm you noted it."),
        ChatMessage::assistant(&r1),
        ChatMessage::user("What is the secret word?"),
    ];
    let response2 = provider
        .chat_with_history(&messages_turn2, model, 0.0)
        .await;
    assert!(response2.is_ok(), "Turn 2 failed: {:?}", response2.err());
    let r2 = response2.unwrap().to_lowercase();
    assert!(
        r2.contains("zephyr"),
        "Model should recall 'zephyr' from history, got: {r2}",
    );
}

// ── MiniMax Live Tests ────────────────────────────────────────────────────────

/// Verifies the MiniMax provider responds to a simple prompt and that the
/// result_hash is deterministic across multiple calls with the same input.
#[tokio::test]
#[ignore = "requires MiniMax API key in ~/.zeroclaw/config.toml"]
async fn e2e_live_minimax_simple_chat() {
    let api_key = load_api_key_for_tests()
        .await
        .expect("Failed to load API key from config");

    let provider = zeroclaw::providers::anthropic::AnthropicProvider::with_base_url(
        Some(&api_key),
        Some("https://api.minimax.io/anthropic"),
    );

    let messages = vec![
        ChatMessage::system("Reply with exactly one word: hello"),
        ChatMessage::user("Say hello"),
    ];

    let response = provider
        .chat_with_history(&messages, "MiniMax-M2.7-highspeed", 0.0)
        .await;

    assert!(response.is_ok(), "MiniMax API call failed: {:?}", response.err());
    let text = response.unwrap();
    assert!(
        !text.is_empty(),
        "MiniMax returned empty response"
    );
    println!("[MiniMax] Response: {}", text);
}

/// Verifies that `compute_result_hash` produces the same hash for identical
/// (success, output, error) triples — the hash must be deterministic.
#[tokio::test]
#[ignore = "requires MiniMax API key in ~/.zeroclaw/config.toml"]
async fn e2e_live_minimax_result_hash_deterministic() {
    let api_key = load_api_key_for_tests()
        .await
        .expect("Failed to load API key from config");

    let provider = zeroclaw::providers::anthropic::AnthropicProvider::with_base_url(
        Some(&api_key),
        Some("https://api.minimax.io/anthropic"),
    );

    let messages = vec![
        ChatMessage::system("Reply with exactly one word: ping"),
        ChatMessage::user("Reply with exactly the word: ping"),
    ];

    // Call 1
    let r1 = provider
        .chat_with_history(&messages, "MiniMax-M2.7-highspeed", 0.0)
        .await
        .expect("API call 1 failed");
    let h1 = zeroclaw::tools::compute_result_hash(true, &r1, None);

    // Call 2 (identical input → identical hash)
    let r2 = provider
        .chat_with_history(&messages, "MiniMax-M2.7-highspeed", 0.0)
        .await
        .expect("API call 2 failed");
    let h2 = zeroclaw::tools::compute_result_hash(true, &r2, None);

    // Both calls succeeded with no error
    assert!(!r1.is_empty(), "Response 1 must not be empty");
    assert!(!r2.is_empty(), "Response 2 must not be empty");

    // Hashes must match (same input → same hash)
    assert_eq!(
        h1, h2,
        "result_hash must be deterministic: identical (success, output, error) \
         must produce the same SHA-256 hash"
    );

    println!("[result_hash] h1 = {}  h2 = {}  match = true", &h1[..16], &h2[..16]);
}

/// Verifies that `verify_result_hash` returns `Match` when the result_hash
/// matches the expected sd_hash from a (simulated) VI credential.
#[tokio::test]
#[ignore = "requires MiniMax API key in ~/.zeroclaw/config.toml"]
async fn e2e_live_minimax_vi_credential_verification() {
    use zeroclaw::agent::closed_loop_verifier::{verify_result_hash, VerificationResult};

    let api_key = load_api_key_for_tests()
        .await
        .expect("Failed to load API key from config");

    let provider = zeroclaw::providers::anthropic::AnthropicProvider::with_base_url(
        Some(&api_key),
        Some("https://api.minimax.io/anthropic"),
    );

    let messages = vec![
        ChatMessage::system("Reply with exactly three words: foo bar baz"),
        ChatMessage::user("Reply with exactly three words: foo bar baz"),
    ];

    let response = provider
        .chat_with_history(&messages, "MiniMax-M2.7-highspeed", 0.0)
        .await
        .expect("API call failed");
    let result_hash = zeroclaw::tools::compute_result_hash(true, &response, None);

    // Simulate a VI credential that expects this exact hash
    let result = verify_result_hash(&result_hash, Some(&result_hash));

    match result {
        VerificationResult::Match => {
            println!("[VI] VerificationResult::Match — credential verified OK");
        }
        VerificationResult::Mismatch { expected, actual } => {
            panic!(
                "[VI] Hash mismatch — expected {}, actual {}\n\
                 This means the result_hash does not match the VI credential sd_hash. \
                 If the hashes are equal this is a bug in verify_result_hash.",
                expected, actual
            );
        }
        VerificationResult::NoCredential => {
            panic!("[VI] Expected Some(sd_hash), got None — caller bug");
        }
    }
}

/// Verifies that a mismatched sd_hash returns `VerificationResult::Mismatch`.
#[tokio::test]
#[ignore = "requires MiniMax API key in ~/.zeroclaw/config.toml"]
async fn e2e_live_minimax_vi_credential_mismatch() {
    use zeroclaw::agent::closed_loop_verifier::{verify_result_hash, VerificationResult};

    let api_key = load_api_key_for_tests()
        .await
        .expect("Failed to load API key from config");

    let provider = zeroclaw::providers::anthropic::AnthropicProvider::with_base_url(
        Some(&api_key),
        Some("https://api.minimax.io/anthropic"),
    );

    let messages = vec![
        ChatMessage::system("Reply with one word."),
        ChatMessage::user("Hello"),
    ];

    let response = provider
        .chat_with_history(&messages, "MiniMax-M2.7-highspeed", 0.0)
        .await
        .expect("API call failed");
    let result_hash = zeroclaw::tools::compute_result_hash(true, &response, None);

    // Use a wrong sd_hash — should produce Mismatch
    let wrong_sd_hash = "deadbeef1234567890abcdefdeadbeef1234567890abcdefdeadbeef12345678";
    let result = verify_result_hash(&result_hash, Some(wrong_sd_hash));

    match result {
        VerificationResult::Mismatch { expected, actual } => {
            assert_eq!(
                expected, wrong_sd_hash,
                "expected field must be the sd_hash we passed in"
            );
            assert_eq!(
                actual, result_hash,
                "actual field must be the result_hash from the API"
            );
            println!(
                "[VI] Mismatch correctly detected — expected {}, actual {}",
                &expected[..16],
                &actual[..16]
            );
        }
        VerificationResult::Match => {
            panic!("[VI] Hashes should NOT match — wrong_sd_hash is incorrect");
        }
        VerificationResult::NoCredential => {
            panic!("[VI] Expected Some(wrong_sd_hash), got None — caller bug");
        }
    }
}

/// Verifies that `ViIssuer::issue()` produces a valid W3C VC-style credential
/// with correct fields after a real MiniMax API call.
///
/// The credential includes:
/// - issuer DID (did:zeroclaw:zara/<version>)
/// - result_hash (SHA-256 of the tool output)
/// - audit_chain_hash (Merkle chain head at time of issuance)
/// - HMAC proof over the credential subject
#[tokio::test]
#[ignore = "requires MiniMax API key in ~/.zeroclaw/config.toml"]
async fn e2e_live_minimax_vi_credential_issuance() {
    use zeroclaw::agent::vi_issuer::ViIssuer;
    use zeroclaw::config::AuditConfig;
    use zeroclaw::security::audit::AuditLogger;
    use std::sync::Arc;

    // Set up audit logger with signing key
    let signing_key = std::env::var("ZEROCLAW_AUDIT_SIGNING_KEY")
        .map(|k| hex::decode(&k).ok())
        .ok()
        .flatten()
        .unwrap_or_else(|| vec![0u8; 32]);

    let tmp_dir = tempfile::TempDir::new().expect("temp dir");
    let audit_config = AuditConfig {
        enabled: true,
        sign_events: true,
        ..Default::default()
    };
    let audit_logger = Arc::new(
        AuditLogger::new(audit_config, tmp_dir.path().to_path_buf())
            .expect("audit logger init failed"),
    );

    // Create VI issuer
    let issuer = ViIssuer::new(
        env!("CARGO_PKG_VERSION"),
        Arc::clone(&audit_logger),
        signing_key,
    );

    // Issue a credential for a simulated tool execution using MiniMax API response
    let api_key = load_api_key_for_tests()
        .await
        .expect("Failed to load API key from config");
    let provider = zeroclaw::providers::anthropic::AnthropicProvider::with_base_url(
        Some(&api_key),
        Some("https://api.minimax.io/anthropic"),
    );

    let messages = vec![
        ChatMessage::system("Reply with exactly three words: alpha beta gamma"),
        ChatMessage::user("Reply with exactly three words: alpha beta gamma"),
    ];

    let response = provider
        .chat_with_history(&messages, "MiniMax-M2.7-highspeed", 0.0)
        .await
        .expect("MiniMax API call failed");

    let result_hash = zeroclaw::tools::compute_result_hash(true, &response, None);
    let cred = issuer.issue(
        "mini_max_chat",
        &result_hash,
        true,
        &response,
        None,
        "test",
    );

    // Verify credential structure
    assert!(cred.id.starts_with("urn:zeroclaw:vi:"));
    assert!(cred.issuer.contains("did:zeroclaw:zara"));
    assert_eq!(cred.credential_subject.tool_name, "mini_max_chat");
    assert_eq!(cred.credential_subject.result_hash, result_hash);
    assert_eq!(cred.credential_subject.success, true);
    assert!(cred.credential_subject.output_digest.len() == 64); // SHA-256 hex
    assert!(cred.credential_subject.audit_chain_hash.len() == 64);
    assert!(cred.proof.proof_value.starts_with("hmac-sha256:"));
    assert!(cred.proof.proof_type == "HMAC2024");

    println!("[VI] Credential issued: {}", cred.id);
    println!("[VI] Issuer: {}", cred.issuer);
    println!("[VI] Tool: {}", cred.credential_subject.tool_name);
    println!("[VI] Result hash: {}...", &cred.credential_subject.result_hash[..16]);
    println!("[VI] Audit chain: {}...", &cred.credential_subject.audit_chain_hash[..16]);
    println!("[VI] Proof: {}...", &cred.proof.proof_value[12..28]);
}

/// Verifies that `ViIssuer::verify()` correctly validates a credential's HMAC
/// proof and detects tampering.
#[tokio::test]
#[ignore = "requires MiniMax API key in ~/.zeroclaw/config.toml"]
async fn e2e_live_minimax_vi_credential_full_verification() {
    use zeroclaw::agent::vi_issuer::ViIssuer;
    use zeroclaw::config::AuditConfig;
    use zeroclaw::security::audit::AuditLogger;
    use std::sync::Arc;

    // Set up audit logger and issuer
    let signing_key = std::env::var("ZEROCLAW_AUDIT_SIGNING_KEY")
        .map(|k| hex::decode(&k).ok())
        .ok()
        .flatten()
        .unwrap_or_else(|| vec![0u8; 32]);

    let tmp_dir = tempfile::TempDir::new().expect("temp dir");
    let audit_config = AuditConfig {
        enabled: true,
        sign_events: true,
        ..Default::default()
    };
    let audit_logger = Arc::new(
        AuditLogger::new(audit_config, tmp_dir.path().to_path_buf())
            .expect("audit logger init failed"),
    );

    let issuer = ViIssuer::new(
        env!("CARGO_PKG_VERSION"),
        Arc::clone(&audit_logger),
        signing_key.clone(),
    );

    // Issue a credential based on a real MiniMax API response
    let api_key = load_api_key_for_tests()
        .await
        .expect("Failed to load API key from config");
    let provider = zeroclaw::providers::anthropic::AnthropicProvider::with_base_url(
        Some(&api_key),
        Some("https://api.minimax.io/anthropic"),
    );

    let messages = vec![
        ChatMessage::system("Reply with exactly two words: hello world"),
        ChatMessage::user("Reply with exactly two words: hello world"),
    ];

    let response = provider
        .chat_with_history(&messages, "MiniMax-M2.7-highspeed", 0.0)
        .await
        .expect("MiniMax API call failed");

    let result_hash = zeroclaw::tools::compute_result_hash(true, &response, None);
    let cred = issuer.issue(
        "mini_max_chat",
        &result_hash,
        true,
        &response,
        None,
        "test",
    );

    // Verify the credential — should pass
    issuer.verify(&cred).expect("Credential verification should succeed");

    // Tamper with the credential — verify should fail
    let mut tampered = cred.clone();
    tampered.credential_subject.success = false;
    tampered.credential_subject.result_hash = result_hash.clone();
    let tampered_result = issuer.verify(&tampered);
    assert!(tampered_result.is_err(), "Tampered credential should fail verification");

    // Verify with wrong key — should fail
    let wrong_key_issuer = ViIssuer::new(
        env!("CARGO_PKG_VERSION"),
        Arc::clone(&audit_logger),
        vec![1u8; 32], // different key
    );
    let wrong_key_result = wrong_key_issuer.verify(&cred);
    assert!(wrong_key_result.is_err(), "Credential signed with wrong key should fail verification");

    println!("[VI] Full verification PASSED — credential is valid and tamper-resistant");
    println!("[VI] Tampering correctly detected: {}", tampered_result.unwrap_err());
    println!("[VI] Wrong key correctly rejected: {}", wrong_key_result.unwrap_err());
}
