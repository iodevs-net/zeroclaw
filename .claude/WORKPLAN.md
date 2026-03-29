# Work Plan: DID Document + Code Context

## Estado: Marzo 2026 — Post-VI Credential

### ✅ Completado
- **T7**: Arquitectura VI Credentials — W3C VC 1.1 con HMAC-SHA256
- **T8**: `vi_issuer.rs` — issuance y firma
- **T9**: Integración en `run_tool_call_loop` post-ejecución
- **T10**: Tests live con MiniMax API real (4/4 pasan)
- **T14**: `ViCredentialStore` SQLite con `Mutex<Connection>`
- **T16**: Endpoints REST `/api/vi/verify/:id` y `/api/vi/credentials`
- **T17**: `ViCredentialHook` usando store persistente
- **T18**: Sistema verificado end-to-end en daemon real (Telegram → hook → SQLite → API)

### 🎯 Siguiente: T15 — DID Document y Resolutor

#### Arquitectura
```
did:zeroclaw:zara/0.6.5
├── DID Document (JSON-LD)
│   ├── @context: ["https://www.w3.org/ns/did/v1", "https://zeroclaw.dev/did/v1"]
│   ├── id: did:zeroclaw:zara/0.6.5
│   ├── verificationMethod: did:zeroclaw:zara/0.6.5#audit-chain
│   │   └── type: HMACVerificationKey2024
│   │   └── publicKeyHex: (audit chain public key derivation)
│   └── authentication: did:zeroclaw:zara/0.6.5#agent
├── Resolutor
│   ├── resolve(did) → DIDDocument
│   └── verify(credential) → VerificationResult
```

#### Tareas
- [ ] **T15a**: Definir esquema DID Document en `src/agent/did.rs`
- [ ] **T15b**: Implementar `DIDResolver` con soporte `did:zeroclaw:`
- [ ] **T15c**: Integrar resolutor en `handle_api_vi_verify` para verificación off-chain
- [ ] **T15d**: Exponer `GET /api/did/:id` para resolver DID documents

---

## 📚 Code Context (T11-T13)

### Arquitectura
Stack embedded de bajo consumo:
```
syn → Rust AST parsing
in-memory HashMap → symbol index (name, path, item_type, docs)
bm25 ranking → búsqueda sin embeddings
CodeNavigateTool → registrada en registry
```

### Tareas
- [ ] **T11**: Diseñar arquitectura Code Context (syn + bm25 embedded)
- [ ] **T12**: Implementar `src/tools/code_indexer.rs` — parser + index
- [ ] **T13**: Crear `CodeNavigateTool` y registrar en registry

### Archivos a crear/modificar
- `src/agent/did.rs` (nuevo) — DID document + resolver
- `src/tools/code_indexer.rs` (nuevo)
- `src/tools/mod.rs` — exportar code_indexer
- `src/tools/registry.rs` — registrar CodeNavigateTool
- `src/agent/tool_search.rs` — integrar con SemanticToolSearch

---

## Dependencias

```
T15 (DID) ──→ T16 (ya completado) ──→ Sistema VI completo
T11 ──→ T12 ──→ T13
T15 y T11-T13 son independientes (paralelo)
```

---

## Decisiones Arquitectónicas

1. ✅ **DID Method**: `did:zeroclaw:` — identity basada en agent version
2. ✅ **Storage**: credentials en SQLite separado del audit log
3. ⚠️ **Code**: BM25 simple vs tantivy — evaluar según complejidad de búsqueda
4. ⚠️ **Code**: indexación lazy-load por modulo vs full startup — evaluar latency

---

*Ultima actualización: Marzo 2026*
