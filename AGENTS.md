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
4. **Защита от исчерпания квот agy / Gemini**:
   - Автоматический выбор легковесной Flash-модели через `detect_best_agy_model` (приоритет: `flash.*low` -> `flash.*medium` -> `flash`; переопределение через `--agy-model` / `AGY_MODEL`).
   - Семафор ограничения параллелизма к `agy` (`--agy-concurrency`, по умолчанию 2 процесса).
   - Автомат аварийного отключения `QuotaCircuitBreaker`: при ошибке `individual quota reached` вызовы `agy` мгновенно отключаются для последующих серверов, сохраняя только сетевой preflight/geo; статус `UNKNOWN` исключён из кэширования в `results.json`.
   - Предстартовая проверка `check_agy_health` предупреждает об исчерпании квоты до запуска тестирования пула.
5. **Дедупликация и кэширование по конфигурации (SSOT)**:
   - Канонический ключ `Server.config_identity` нормализует параметры между диалектами Xray и sing-box (`protocol:host:port:cred:sni:reality_pk:fingerprint:flow:alpn:path`).
   - Идентичность устраняет зависимость от диалекта и исключает артефакты БД (например `packet_encoding: xudp`), позволяя свежим записям из онлайна (`fresh`) вытеснять устаревшие копии из локальной БД Throne (`db`).
   - Профили с различными uTLS фингерпринтами (`chrome`, `firefox`, ...) сохраняют независимость в кэше и пуле проверки.
6. **L4 TCP предфильтр (Stage 0)**:
   - Быстрый отсев недоступных хостов по сокетному 3-way handshake (`socket.create_connection`) перед запуском локальных движков `sing-box` / `Xray`.
   - SSOT дедупликация эндпоинтов `(server, server_port)`: уникальный хост проверяется строго один раз параллельно (`batch_probe_tcp`), результат проецируется на все профили этого эндпоинта.
   - Изоляция UDP-протоколов: `hysteria2`, `tuic`, `wireguard` прозрачно минуют предфильтр (`Server.is_tcp_protocol`).
   - CLI-флаги управления: `--no-tcp-prefilter`, `--tcp-timeout` (по умолчанию 1.5с), `--tcp-concurrency` (по умолчанию 100 воркеров).
7. **Оптимизация производительности проверки движками (Stage 1)**:
   - In-Memory запуск: передача конфигурации в `sing-box` (`-c stdin`) и `Xray` (`-c stdin:`) через `stdin`, сбор вывода через in-memory пайп. Файлы и каталоги на диске во время проверки не создаются.
   - Фильтрация по представителям эндпоинтов (Host-Representative First): первоочередная проверка по 1 представителю от каждого уникального сокета `(server, server_port)`. Падение туннеля представителя по сетевому таймауту мгновенно отсекает зависимые профили этого хоста (флаг отключения: `--no-rep-filter`).
   - Настройка сетевого конвейера: `--preflight-timeout` (по умолчанию 2.5с вместо 4.0с), адаптивный дефолт параллелизма `--jobs` (`min(32, max(8, cpu*2))`).
