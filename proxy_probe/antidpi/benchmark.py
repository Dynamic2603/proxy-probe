from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..engines import project_root
from ..models import RESULT_BLOCK, RESULT_OK, Server
from .models import AntidpiBenchmarkResult

logger = logging.getLogger(__name__)

DEFAULT_RATINGS_FILENAME = "antidpi_ratings.json"


def default_ratings_path() -> Path:
    """Возвращает путь к локальному рейтингу стратегий (SSOT)."""
    return project_root() / "data" / DEFAULT_RATINGS_FILENAME


def load_ratings(path: Path | None = None) -> AntidpiBenchmarkResult | None:
    """Загружает сохраненный локальный рейтинг стратегий."""
    p = path or default_ratings_path()
    if not p.is_file():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return AntidpiBenchmarkResult.from_dict(raw)
    except Exception as exc:
        logger.warning("Сбой чтения рейтинга стратегий %s: %s", p, exc)
        return None


def save_ratings(result: AntidpiBenchmarkResult, path: Path | None = None) -> None:
    """Атомарно сохраняет результаты бенчмарка в JSON-файл (SSOT)."""
    p = path or default_ratings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def select_dead_servers(servers: list[Server], limit: int = 15) -> list[Server]:
    """Отбирает уникальные по хосту серверы, упавшие по сетевым причинам (L4/TLS).

    Строго исключает геоблоки Google (RESULT_BLOCK), так как Zapret бессилен против санкций сервиса.
    """
    seen_hosts: set[str] = set()
    selected: list[Server] = []

    for s in servers:
        if s.result == RESULT_BLOCK or s.result == RESULT_OK:
            continue
        # Отбираем только узлы с признаками сетевого таймаута / drop
        if not s.server or s.server in seen_hosts:
            continue
        if not s.import_obj or not isinstance(s.import_obj, dict):
            continue

        seen_hosts.add(s.server)
        selected.append(s)
        if len(selected) >= limit:
            break

    return selected


def calculate_strategy_score(rescued: int, total: int, avg_latency: int) -> int:
    """Вычисляет скор надежности стратегии (0..100) на выборке упавших узлов (SSOT)."""
    if total <= 0 or rescued <= 0:
        return 0
    rate = rescued / total
    base = int(rate * 80)
    lat_penalty = max(0, (avg_latency - 100) // 10) if avg_latency > 0 else 0
    lat_bonus = max(0, 20 - lat_penalty)
    return max(1, min(100, base + lat_bonus))


def build_relay_detour(
    is_xray: bool,
    relay_port: int,
    relay_host: str = "127.0.0.1",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Создает модификацию конфига outbound и объект relay-прокси для sing-box или Xray (SSOT)."""
    if is_xray:
        detour_patch = {"proxySettings": {"tag": "zapret-relay"}}
        relay_outbound = {
            "protocol": "socks",
            "tag": "zapret-relay",
            "settings": {"servers": [{"address": relay_host, "port": relay_port}]},
        }
    else:
        detour_patch = {"detour": "zapret-relay"}
        relay_outbound = {
            "type": "socks",
            "tag": "zapret-relay",
            "server": relay_host,
            "server_port": relay_port,
        }
    return detour_patch, relay_outbound


def format_benchmark_table(result: AntidpiBenchmarkResult) -> str:
    """Форматирует сводную таблицу результатов бенчмарка в читаемый Markdown/консольный вид."""
    lines: list[str] = [
        f"### Рейтинг Anti-DPI стратегий (Дата: {result.tested_at[:19]}, Провайдер: {result.isp or 'Default'})",
        "",
        "| № | Стратегия | Семейство | Спасено | Успех | Задержка | Скор |",
        "|---|---|---|---|---|---|---|",
    ]

    for r in result.ratings:
        is_best = r.strategy_number == result.best_strategy_number
        mark = "⭐ " if is_best else ""
        pct = f"{int(r.success_rate * 100)}%"
        lat = f"{r.avg_latency_ms} мс" if r.avg_latency_ms > 0 else "—"
        name = r.strategy_name[:40] + ("..." if len(r.strategy_name) > 40 else "")
        lines.append(
            f"| {mark}S{r.strategy_number:02d} | {name} | {r.family_name} | "
            f"{r.rescued_count}/{r.total_tested} | {pct} | {lat} | {r.score} |"
        )

    return "\n".join(lines)
