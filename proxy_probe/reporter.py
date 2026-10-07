from __future__ import annotations

import datetime as _dt
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from .models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, RESULT_UNKNOWN, Server

RESULT_TABLE_ORDER = {RESULT_OK: 0, RESULT_BLOCK: 1, RESULT_UNKNOWN: 2, RESULT_DEAD: 3}

if TYPE_CHECKING:
    from .cache import ResultCache


def write_report(
    servers: list[Server],
    report_path: Path,
    ver_sb: str,
    ver_xr: str,
    warnings: list[str],
    time_s: float,
    cached_counts: dict[str, int] | None = None,
    cache_note: str = "",
) -> None:
    counts = Counter(s.result for s in servers if s.result)
    tested_count = sum(1 for s in servers if s.result)
    server_stat = f"{tested_count} из {len(servers)} (прервано)" if tested_count < len(servers) else f"{len(servers)}"
    lines: list[str] = [
        "# Отчёт о проверке серверов подписок (работа с agy / Gemini)\n",
        f"- Дата: {_dt.datetime.now(_dt.UTC).astimezone().isoformat(timespec='seconds')}",
        f"- Проверено серверов: {server_stat}",
    ]
    if cached_counts:
        hit_txt = ", ".join(f"{k} = {v}" for k, v in cached_counts.items() if v)
        if hit_txt:
            lines.append(f"- Пропущено по кэшу (не проверялись): {hit_txt}")
    lines.append(f"- Движки: sing-box v{ver_sb}, Xray v{ver_xr} (точные версии Throne)")
    lines.append(f"- Время проверки: {time_s:.0f} с")
    if counts:
        lines.append("- Итог: " + ", ".join(f"{k} = {v}" for k, v in counts.most_common()))
    if warnings:
        lines.append("\n## Предупреждения\n")
        for w in warnings:
            lines.append(f"- {w}")
    lines.append("\n## Методика предупреждений\n")
    lines.append(
        "- Тестовый трафик идёт через живой туннель Throne (двойной хоп через активный сервер) — возможны\n"
        "  ложные DEAD, если активный сервер лежит.\n"
        "- IPv6-only серверы могут ложно падать (нет IPv6 в песочнице).\n"
        "- БД Throne не изменялась; подписки были освежены скриптом (fetch по URL).\n"
    )
    if cache_note:
        lines.append(f"- {cache_note}\n")
    lines.append("\n## Результаты\n")
    lines.append("| № | Результат | Группа | Движок | Сервер | Страна | Egress IP | мс | Имя | Ответ / Примечание |")
    lines.append("|---|-----------|--------|--------|--------|--------|-----------|-----|-----|-------------------|")
    sorted_servers = sorted(
        servers,
        key=lambda s: (RESULT_TABLE_ORDER.get(s.result, 99), s.index),
    )
    for s in sorted_servers:
        name = (s.name or "").replace("|", "\\|")[:60]
        note = (s.note or "").replace("|", "\\|").replace("\n", " ").strip()
        lines.append(
            f"| {s.index} | {s.result or '—'} | {s.group_name} | {s.engine} | {s.server}:{s.server_port} | "
            f"{s.country} | {s.ip_out} | {s.latency_ms} | {name} | {note} |"
        )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_import_file(
    cache: ResultCache | None,
    path: Path,
    fallback_servers: list[Server] | None = None,
) -> tuple[int, int]:
    sb: list[dict] = []
    xr: list[dict] = []

    if cache is not None:
        sorted_entries = sorted(cache.entries.items(), key=lambda kv: kv[0])
        for host_port, entry in sorted_entries:
            if entry.get("result") != RESULT_OK:
                continue
            if not cache.is_valid(host_port):
                continue
            obj = entry.get("import_obj")
            if not isinstance(obj, dict):
                continue
            eng = entry.get("engine")
            if eng == "xray" or (not eng and obj.get("protocol")):
                xr.append(obj)
            else:
                sb.append(obj)
    elif fallback_servers:
        ok = sorted([s for s in fallback_servers if s.result == RESULT_OK], key=lambda s: s.host_port)
        sb = [s.import_obj for s in ok if s.engine == "sing-box"]
        xr = [s.import_obj for s in ok if s.engine == "xray"]

    if path.exists() and path.stat().st_size > 0:
        try:
            bak_path = path.with_suffix(".txt.bak")
            shutil.copy2(path, bak_path)
        except OSError:
            pass

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
        if sb:
            f.write(json.dumps(sb, ensure_ascii=False) + "\n")
        if xr:
            f.write(json.dumps(xr, ensure_ascii=False) + "\n")
    tmp_path.replace(path)
    return len(sb), len(xr)
