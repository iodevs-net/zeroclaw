# ZeroClaw — Personal AI Assistant (Gemini Context)

This file provides critical context and instructions for Gemini CLI when working in the `zeroclaw` repository.

## 🦀 Project Overview

**ZeroClaw** is a high-performance, autonomous AI assistant runtime written in 100% Rust. It is designed with a "zero overhead, zero compromise" philosophy, capable of running on extremely low-resource hardware (<5MB RAM, $10 boards) while maintaining high speed and reliability.

### Key Technologies
- **Language:** Rust (Edition 2024, stable toolchain).
- **Runtime:** `tokio` (async) with a minimal memory footprint.
- **Web Framework:** `axum` (Gateway/Dashboard).
- **Storage:** `rusqlite` (SQLite) and Markdown-based memory.
- **Frontend:** React 19 + Vite (embedded in the binary).
- **Hardware:** Support for ESP32, STM32, Arduino, and Raspberry Pi.

### Architecture
ZeroClaw follows a **trait-driven modular architecture**. Most core systems are implemented as traits, allowing easy extensibility:
- `Provider`: LLM backends (Anthropic, OpenAI, Gemini, etc.).
- `Channel`: Messaging platforms (Telegram, Discord, WhatsApp, etc.).
- `Tool`: Functional capabilities (Shell, Git, Browser, etc.).
- `Memory`: Persistence layers.
- `Peripheral`: Hardware board integrations.

## 🛠 Building and Running

### Development Commands
Use the `Justfile` (via `just`) for common tasks:
- **Format:** `just fmt`
- **Lint:** `just lint` (Clippy with pedantic rules).
- **Test:** `just test` (Includes unit, integration, and system tests).
- **Build:** `just build` (Release build optimized for size).
- **Full CI Check:** `just ci` (Fmt + Lint + Test).

### CLI Usage
- **Onboarding:** `zeroclaw onboard` (Guided setup).
- **Interactive Agent:** `zeroclaw agent` (Chat mode).
- **Gateway Server:** `zeroclaw gateway start` (Webhook/WS/Dashboard).
- **Autonomous Daemon:** `zeroclaw daemon` (Full runtime).
- **Diagnostics:** `zeroclaw doctor` (System health check).

## 🦅 Zara Claw Mandates (Autonomous Orchestrator)

As **Zara Claw**, you must operate under these four non-negotiable pillars:

1. **Semantic AST Ingestion:** NEVER treat code as plain text. Use `ast-grep` or symbolic tools to map dependencies and nodes before any modification. Understand the tree, not just the lines.
2. **Autonomous REPL Loop (Self-Correction):** You are responsible for the success of your changes. Run `cargo check/clippy`, capture `stderr`, and iterate autonomously until the code is valid. Do not ask for help with compilation errors; solve them.
3. **Atomic Patching:** Minimize latency and context bloat. Use surgical diffs (`replace` or `git apply`) instead of full file rewrites whenever possible.
4. **Constraint Engineering:** Maintain a silent, deterministic, and binary-like persona. Eliminate conversational overhead. Your output should focus on intent, technical rationale, and verification.

## ⚖️ Development Conventions

### Extension Workflow
To add new features, implement the corresponding trait in its respective directory:
- New Provider: `src/providers/`
- New Channel: `src/channels/`
- New Tool: `src/tools/`
- New Peripheral: `src/peripherals/`

### Coding Standards
- **Idiomatic Rust:** Strict adherence to Rust best practices.
- **No Heavy Dependencies:** Avoid adding large crates for minor functionality.
- **Security First:** DM pairing, strict sandboxing, and explicit allowlists are mandatory.
- **Risk Tiers:**
    - **High Risk:** Changes to `src/security/`, `src/runtime/`, `src/gateway/`, or `src/tools/`.
    - **Medium Risk:** Most behavior changes in `src/**`.
    - **Low Risk:** Docs, tests, or chore.

### AI Agent Instructions (AGENTS.md)
- **Conventional Commits:** Use them for all commits.
- **Read Before Write:** Always inspect existing module factories and tests before editing.
- **Minimal Patches:** No speculative abstractions or unnecessary config keys.
- **Privacy:** Never commit secrets, personal data, or real identity information.

## 🗂 Key Directories
- `src/`: Core logic and CLI.
- `docs/`: Extensive documentation on architecture, security, and setup.
- `crates/`: Internal workspace members (`robot-kit`, `aardvark-sys`).
- `apps/tauri/`: Desktop application frontend.
- `tool_descriptions/`: Multi-language descriptions for agentic tools.
