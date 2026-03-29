//! Decrypt and print the API key from the ZeroClaw config.
//!
//! Run with:
//!   cargo run --bin decrypt-key
//!   ZEROCLAW_CONFIG_DIR=~/.zeroclaw cargo run --bin decrypt-key
//!
//! Exits with code 0 and prints the decrypted API key to stdout.
//! Exits with code 1 and prints an error message to stderr if the key cannot be obtained.

use zeroclaw::Config;

#[tokio::main]
async fn main() {
    let config = match Config::load_or_init().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    match &config.api_key {
        Some(key) => {
            println!("{}", key);
        }
        None => {
            eprintln!("No api_key found in config");
            std::process::exit(1);
        }
    }
}
