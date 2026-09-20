# Рекомендации и контекст для агентов (AGENTS.md)

Код — документация: механика проверки описана в пакете `proxy_probe` (константы, классификатор, схемы конфигов движков, кэш).

---

## Источники информации и движки

1. **Репозиторий Throne**: `https://github.com/throneproj/Throne` (C++/Qt, движки sing-box и Xray).
   - Каталог данных: `%LOCALAPPDATA%\Throne` или `%APPDATA%\Throne`.
   - `config\throne.db` — SQLite: активные группы, URL подписок, схемы `outbound_json`. Скрипт использует безопасный снимок БД с WAL в `%TEMP%\proxy-probe\snapshot\`.
   - `ThroneCore.exe` — определяет версии движков при запуске.
2. **Официальные релизы движков (GitHub Releases)**:
   - `https://github.com/SagerNet/sing-box/releases` — v1.13.16 (windows-amd64).
   - `https://github.com/XTLS/Xray-core/releases` — v26.7.28 (`Xray-windows-64.zip`).
   - Бинарники кэшируются в папке `bin/` в корне проекта (или переопределяются через `PROXY_PROBE_BIN_DIR`).
3. **Целевой API и гео**:
   - `https://generativelanguage.googleapis.com/v1beta/...` — Gemini API (маркер гео-блока: `User location is not supported`).
   - `https://ipwho.is/` — гео-определение egress-IP для отчёта.

