#[allow(clippy::module_inception)]
pub mod agent;
pub mod classifier;
pub mod closed_loop_verifier;
pub mod context_analyzer;
pub mod context_compressor;
pub mod cost;
pub mod dispatcher;
pub mod eval;
pub mod history;
pub mod history_pruner;
pub mod loop_;
pub mod loop_detector;
pub mod memory_loader;
pub mod personality;
pub mod prompt;
pub mod reflection;
pub mod thinking;
pub mod tool_execution;
pub mod tool_search;
pub mod did;
pub mod vi_issuer;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use agent::{Agent, AgentBuilder, TurnEvent};
#[allow(unused_imports)]
pub use loop_::{process_message, run};
