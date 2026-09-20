# Рекомендации и контекст для агентов (AGENTS.md)

Код — документация: механика проверки описана в пакете `proxy_probe` (константы, классификатор, схемы конфигов движков, кэш).

---

## Внешние источники информации и движки

1. **Репозиторий Throne**: `https://github.com/throneproj/Throne` (C++/Qt, движки sing-box и Xray).
   - Каталог данных: `%LOCALAPPDATA%\Throne` или `%APPDATA%\Throne`.
   - `config\throne.db` — SQLite: активные группы, URL подписок, схемы `outbound_json`. Скрипт использует безопасный снимок БД с WAL в `%TEMP%\proxy-probe\snapshot\`.
   - `ThroneCore.exe` — определяет версии движков при запуске.
2. **Официальные релизы движков (GitHub Releases)**:
   - Актуальные версии определяются динамически из `ThroneCore.exe` (sing-box `https://github.com/SagerNet/sing-box/releases` и Xray `https://github.com/XTLS/Xray-core/releases`).
   - Бинарники кэшируются в папке `bin/` в корне проекта (или переопределяются через `PROXY_PROBE_BIN_DIR`) и валидируются по SHA-256 из релизов upstream (`.dgst` / `.sha256`).
3. **Целевой API и гео**:
   - `https://generativelanguage.googleapis.com/v1beta/...` — Gemini API (маркер гео-блока: `User location is not supported`).
   - `https://ipwho.is/` — гео-определение egress-IP для отчёта.

