//! Hardware sentinel for proactive peripheral monitoring.
//!
//! This module implements a background worker that monitors the health
//! and firmware versions of connected hardware peripherals (ESP32, STM32, etc.).

use crate::config::Config;
use crate::peripherals::list_configured_boards;
use anyhow::Result;
use std::time::Duration;
use tokio::time::interval;

/// Run the hardware sentinel loop.
pub async fn run(config: Config) -> Result<()> {
    if !config.peripherals.enabled {
        tracing::info!("Hardware sentinel disabled (peripherals not enabled)");
        return Ok(());
    }

    let mut tick_interval = interval(Duration::from_secs(300)); // Check every 5 minutes

    loop {
        tick_interval.tick().await;
        tracing::info!("Running hardware sentinel check...");

        let boards = list_configured_boards(&config.peripherals);
        for board in boards {
            match check_board_health(board).await {
                Ok(status) => {
                    tracing::info!("Peripheral health [{}]: {}", board.board, status);
                    crate::health::mark_component_ok(&format!("peripheral:{}", board.board));
                }
                Err(e) => {
                    tracing::warn!("Peripheral failure [{}]: {}", board.board, e);
                    crate::health::mark_component_error(
                        &format!("peripheral:{}", board.board),
                        e.to_string(),
                    );
                }
            }
        }
    }
}

async fn check_board_health(board: &crate::config::PeripheralBoardConfig) -> Result<String> {
    // This is a simplified health check. In a real scenario, we would
    // attempt a light connection or ping.
    
    if board.transport == "serial" {
        if let Some(ref path) = board.path {
            if std::path::Path::new(path).exists() {
                // Try to open the port briefly
                // match serialport::new(path, board.baud).timeout(Duration::from_millis(500)).open() {
                //     Ok(_) => Ok("Online (Serial)".into()),
                //     Err(e) => anyhow::bail!("Serial port error: {}", e),
                // }
                // For now, just check path existence to avoid locking the port from other tools
                Ok(format!("Online (Path {} exists)", path))
            } else {
                anyhow::bail!("Serial path does not exist: {}", path)
            }
        } else {
            anyhow::bail!("Serial board missing path")
        }
    } else if board.transport == "native" {
        Ok("Online (Native/System)".into())
    } else {
        Ok(format!("Status Unknown (Transport: {})", board.transport))
    }
}
