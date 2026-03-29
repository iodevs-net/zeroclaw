# 🦀 Roadmap de Potenciación — Zara Claw (Senior Full Stack Orchestrator)

## 🎯 Objetivo General
Transformar a Zara Claw en un orquestador de IA de alto rendimiento, autónomo, reflexivo y verificable, optimizado para hardware de bajos recursos y soberanía de datos.

---

## ✅ Fase I: Cimiento Cognitivo (Completada)
*Implementación de la infraestructura de razonamiento y aprendizaje.*

- [x] **Búsqueda Semántica de Herramientas:** Implementado `SemanticToolSearch` en `src/agent/tool_search.rs`. Zara ahora selecciona dinámicamente las ~20 herramientas más relevantes para reducir el ruido en el contexto.
- [x] **Reflexión Post-Tarea:** Implementado `ReflectionEngine` en `src/agent/reflection.rs`. Zara realiza un post-mortem autónomo tras cada tarea y guarda lecciones aprendidas.
- [x] **Refactorización de Memoria:** Todo el sistema de proveedores migrado a `Arc<dyn Provider>` para permitir concurrencia segura entre razonamiento y reflexión.
- [x] **Identidad Persistente:** Verificación y estabilización de la carga de `SOUL.md` e `IDENTITY.md`.

## ✅ Fase II: Operaciones Globales y Hardware (Completada)
*Extensión de capacidades funcionales y monitoreo físico.*

- [x] **DocSyncTool:** Creada herramienta en `src/tools/doc_sync.rs` para sincronizar automáticamente el README a los 30+ idiomas soportados usando LLMs.
- [x] **Hardware Sentinel:** Implementado proceso de fondo en `src/daemon/sentinel.rs` que monitorea el latido (heartbeat) de periféricos ESP32/STM32.
- [x] **Estabilización de Firmas:** Corregidas todas las firmas de `all_tools` y el motor del agente en el Gateway, CLI y Canales para asegurar estabilidad absoluta.

## 🚧 Fase III: Inteligencia de Navegación y Auditoría (Siguiente)
*Mejora de la visión interna y seguridad de ejecución.*

- [ ] **Activación de Code Context (Milvus):** (Settings actualizados en `~/.gemini/settings.json`). Siguiente paso: Indexar el codebase local para navegación semántica de símbolos Rust.
- [ ] **Auditoría de Bucle Cerrado (Closed-Loop Auditing):**
    - [ ] Vincular el hachís del `ToolResult` con la intención firmada en `verifiable_intent`.
    - [ ] Crear un rastro de auditoría inmutable en `src/security/audit.rs`.
- [ ] **Closed-Loop Verification:** Asegurar que los cambios realizados por herramientas de escritura sean verificados criptográficamente antes de darlos por concluidos.

## 📅 Fase IV: Optimización Multi-Modelo y UI
- [ ] **Chain of Thought Routing:** Implementar en `classifier.rs` el enrutamiento para que modelos ligeros (Haiku) validen planes y modelos "Senior" (Sonnet/GPT4) ejecuten lógica compleja.
- [ ] **Dashboard i18n:** Actualizar el Dashboard en React 19 para visualizar el estado del Hardware Sentinel y el progreso de DocSync.

---
*Ultima actualización: Marzo 2026*
