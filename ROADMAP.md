# 🦀 Roadmap de Potenciación — Zara Claw (Senior Full Stack Orchestrator)

## 🎯 Objetivo General
Transformar a Zara Claw en un orquestador de IA de alto rendimiento, autónomo, reflexivo y verificable, optimizado para hardware de bajos recursos y soberanía de datos.

---

## ✅ Fase I: Cimiento Cognitivo (Completada — Marzo 2026)
*Implementación de la infraestructura de razonamiento y aprendizaje.*

- [x] **Búsqueda Semántica de Herramientas:** Implementado `SemanticToolSearch` en `src/agent/tool_search.rs`. Zara ahora selecciona dinámicamente las ~20 herramientas más relevantes para reducir el ruido en el contexto.
- [x] **Reflexión Post-Tarea:** Implementado `ReflectionEngine` en `src/agent/reflection.rs`. Zara realiza un post-mortem autónomo tras cada tarea y guarda lecciones aprendidas.
- [x] **Refactorización de Memoria:** Todo el sistema de proveedores migrado a `Arc<dyn Provider>` para permitir concurrencia segura entre razonamiento y reflexión.
- [x] **Identidad Persistente:** Verificación y estabilización de la carga de `SOUL.md` e `IDENTITY.md`.

## ✅ Fase II: Operaciones Globales y Hardware (Completada — Marzo 2026)
*Extensión de capacidades funcionales y monitoreo físico.*

- [x] **DocSyncTool:** Creada herramienta en `src/tools/doc_sync.rs` para sincronizar automáticamente el README a los 30+ idiomas soportados usando LLMs.
- [x] **Hardware Sentinel:** Implementado proceso de fondo en `src/daemon/sentinel.rs` que monitorea el latido (heartbeat) de periféricos ESP32/STM32.
- [x] **Estabilización de Firmas:** Corregidas todas las firmas de `all_tools` y el motor del agente en el Gateway, CLI y Canales para asegurar estabilidad absoluta.

## 🚧 Fase III: Inteligencia de Navegación y Auditoría (En Progreso)
*Mejora de la visión interna y seguridad de ejecución.*

- [x] **Auditoría Merkle Chain:** Implementado `src/security/audit.rs` con hash chain SHA-256 para trail inmutable. Genesis block, eventos de auditoría, encadenamiento criptográfico.
- [x] **Integración AuditLogger en CommandLoggerHook:** Cada ejecución de tool ahora escribe al audit log con `result_hash`, channel, tool name, success y duration. Gateway y Channels registran el hook automáticamente.
- [x] **Result Hash en ToolExecutionOutcome:** `SHA-256(output ‖ error ‖ success)` calculado en cada tool execution. Disponible para auditoría y verificación.
- [x] **Closed-Loop Verifier Module:** `src/agent/closed_loop_verifier.rs` — infraestructura de verificación VI credential y write verification. `verify_result_hash()`, `verify_file_write()` implementados con tests.
- [x] **Closed-Loop Verification para Writes:** `verify_write_operation()` integrado en `run_tool_call_loop`. Verificación automática post-ejecución de `file_write` y `shell`. advisory-only (warnings).
- [x] **Tests de Integración con API Real:** `load_api_key_for_tests()` y binary `decrypt-key` permiten tests con API MiniMax real (no mocks). 4 tests live pasan.
- [x] **Integración VI Issuance:** `src/agent/vi_issuer.rs` implementa issuance W3C VC 1.1 con HMAC-SHA256 proof. `ViCredentialHook` integrado en canal para issuance automático post-tool execution. `AuditLogger::get_last_entry_hash()` expuesto para anchoring.
- [x] **VI Credential Store SQLite:** `ViCredentialStore` con conexión `rusqlite` envuelta en `Mutex`. Tabla `vi_credentials` con índices. Persistencia en `~/.zeroclaw/vi_credentials.db`. Thread-safe.
- [x] **Endpoints REST VI:** `GET /api/vi/verify/:id` y `GET /api/vi/credentials` con auth bearer. Verificación HMAC-SHA256 de proof. Filtros por tool, channel y limit.
- [x] **Tests Live VI Credential:** Sistema funcionando en daemon real. 2 credenciales emitidas para `web_search_tool` y `web_fetch` tras interacción real via Telegram. Verificación `verified: true`.
- [x] **DID Document y Resolutor:** `src/agent/did.rs` con `DIDResolver` y `DIDDocument`. Soporta `did:zeroclaw:zara/<version>`. Endpoint `GET /api/did/:id` para resolución off-chain.
- [ ] **Activación Code Context (Embedded):** Indexación semántica del codebase usando syn + BM25 embedded (alternativa a Milvus, alignment con philosophy low-memory).

## 📅 Fase IV: Optimización Multi-Modelo y UI (Pendiente)
- [ ] **Chain of Thought Routing:** Implementar en `classifier.rs` el enrutamiento para que modelos ligeros (Haiku) validen planes y modelos "Senior" (Sonnet/GPT4) ejecuten lógica compleja.
- [ ] **Dashboard i18n:** Actualizar el Dashboard en React 19 para visualizar el estado del Hardware Sentinel y el progreso de DocSync.

## 🔮 Fase V: Reflexión Autónoma (Borrador)
- [ ] **Auto-Mejora Continua:** Zara analiza sus propios patrones de error y propone mejoras al código base.
- [ ] **Learning Loop:** El `ReflectionEngine` retroalimenta al `SemanticToolSearch` para mejorar selección de herramientas basada en éxito/fracaso histórico.

---
*Ultima actualización: Marzo 2026*
