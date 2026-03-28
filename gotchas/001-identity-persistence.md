# Gotcha #001: Persistencia de Identidad en Docker

## Síntoma
El agente responde como un asistente genérico a pesar de tener configurado el `system_prompt` en `config.toml`.

## Causa Raíz (Atomic Root Cause)
1. **Límite de Caracteres**: `max_system_prompt_chars` estaba en 0, lo que truncaba toda la identidad personalizada.
2. **Desajuste de Rutas**: ZeroClaw (Docker) busca su identidad (SOUL.md, IDENTITY.md) en `/zeroclaw-data/workspace`, mientras que los archivos se estaban creando en el root del host o en rutas no sincronizadas.
3. **Clave de Configuración**: La clave `system_prompt` en `[agent]` no es reconocida por el binario; ZeroClaw prefiere el sistema "file-driven" mediante archivos Markdown en el workspace.

## Solución
1. Ajustar `max_system_prompt_chars = 4096` en `config.toml`.
2. Crear `SOUL.md`, `IDENTITY.md` y `USER.md` dentro de la carpeta de workspace interna del contenedor (`/zeroclaw-data/workspace`).
3. Sincronizar permisos con el UID `65534` (nobody).

## Estado Final
Resuelto. Zara Claw ahora es plenamente consciente de su identidad y rol.
