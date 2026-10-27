from __future__ import annotations

import datetime as _dt
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from .models import RESULT_OK, STATE_ACTIVE, STATE_DEGRADED, Server

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
    cached_unique_hosts: dict[str, set[str]] | None = None,
) -> None:
    counts = Counter(s.result for s in servers if s.result)
    tested_count = sum(1 for s in servers if s.result)
    server_stat = f"{tested_count} из {len(servers)} (прервано)" if tested_count < len(servers) else f"{len(servers)}"
    lines: list[str] = [
        "# Отчёт о проверке серверов подписок (работа с agy / Gemini)\n",
        f"- Дата: {_dt.datetime.now(_dt.UTC).astimezone().isoformat(timespec='seconds')}",
        f"- Проверено серверов: {server_stat}",
    ]
    fresh_cnt = sum(1 for s in servers if s.source == "fresh")
    db_cnt = sum(1 for s in servers if s.source == "db")
    if fresh_cnt or db_cnt:
        lines.append(f"- Состав пула: {len(servers)} серверов (онлайн: {fresh_cnt}, из БД Throne: {db_cnt})")
    if cached_counts:
        hit_parts = []
        for k, v in cached_counts.items():
            if not v:
                continue
            u_cnt = len(cached_unique_hosts.get(k, set())) if cached_unique_hosts else 0
            if u_cnt > 0 and u_cnt < v:
                hit_parts.append(f"{k} = {v} ({u_cnt} уникальных узлов)")
            else:
                hit_parts.append(f"{k} = {v}")
        if hit_parts:
            lines.append(f"- Пропущено по кэшу (не проверялись): {', '.join(hit_parts)}")
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
    lines.append(
        "| № | Результат | Статус | Скор | Группа | Движок | Сервер | Страна | Egress IP | мс | Имя |"
        " Ответ / Примечание |"
    )
    lines.append(
        "|---|-----------|--------|------|--------|--------|--------|--------|-----------|-----|-----|"
        "-------------------|"
    )
    for s in servers:
        name = (s.formatted_tag or s.name or "").replace("|", "\\|")[:80]
        note = (s.note or "").replace("|", "\\|").replace("\n", " ").strip()
        state_str = s.state or "—"
        if s.state == STATE_DEGRADED:
            state_str = f"DEGRADED ({s.consecutive_fails}/3)"
        score_str = f"⭐{s.score}" if s.score >= 90 else (str(s.score) if s.score > 0 else "—")
        lines.append(
            f"| {s.index} | {s.result or '—'} | {state_str} | {score_str} | {s.group_name} | {s.engine} | "
            f"{s.server}:{s.server_port} | {s.country} | {s.ip_out} | {s.latency_ms} | {name} | {note} |"
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

    def _prepare_obj(srv: Server) -> dict:
        obj = dict(srv.import_obj)
        obj["tag"] = srv.formatted_tag
        return obj

    seen_keys: set[str] = set()
    ok_servers: list[Server] = []

    # 1. Серверы активного пула в UI-порядке (s.index)
    if fallback_servers:
        for s in fallback_servers:
            is_ok = (s.result == RESULT_OK or s.state == STATE_DEGRADED)
            if is_ok and s.import_obj:
                ok_servers.append(s)
                seen_keys.add(s.config_identity)
                seen_keys.add(s.cache_key)
                seen_keys.add(s.host_port)

    # 2. Дополнительные валидные серверы из кэша, если они не были в активном пуле
    if cache is not None:
        for entry_key, entry in cache.entries.items():
            state = entry.get("state")
            res = entry.get("result")
            if res != RESULT_OK and state != STATE_DEGRADED:
                continue
            if not cache.is_valid(entry_key):
                continue
            raw_obj = entry.get("import_obj")
            if not isinstance(raw_obj, dict):
                continue

            host = str(raw_obj.get("server") or "")
            port = int(raw_obj.get("server_port") or 0)
            if not host:
                sett = raw_obj.get("settings")
                if isinstance(sett, dict):
                    host = str(sett.get("address") or "")
                    port = int(sett.get("port") or 0)

            eng = str(entry.get("engine") or "")
            if not eng:
                eng = "xray" if raw_obj.get("protocol") else "sing-box"

            s = Server(
                group_id=0,
                group_name="",
                name=str(raw_obj.get("tag", "")),
                engine=eng,
                server=host,
                server_port=port,
                import_obj=raw_obj,
                source="cache",
                country=str(entry.get("country", "")),
                ip_out=str(entry.get("ip_out", "")),
                country_code=str(entry.get("country_code", "")),
                city=str(entry.get("city", "")),
                org=str(entry.get("org", "")),
                score=int(entry.get("score", 70 if res == RESULT_OK else 0)),
                state=str(entry.get("state", STATE_ACTIVE if res == RESULT_OK else STATE_DEGRADED)),
                consecutive_fails=int(entry.get("consecutive_fails", 0)),
            )
            if s.config_identity in seen_keys or s.cache_key in seen_keys or s.host_port in seen_keys:
                continue
            seen_keys.add(s.config_identity)
            seen_keys.add(s.cache_key)
            seen_keys.add(s.host_port)
            ok_servers.append(s)

    ok_servers.sort(
        key=lambda s: (
            0 if s.state == STATE_ACTIVE else 1,
            -s.score,
            s.latency_ms if s.latency_ms > 0 else 99999,
        )
    )

    for s in ok_servers:
        prepared = _prepare_obj(s)
        if s.engine == "xray" or (not s.engine and s.import_obj.get("protocol")):
            xr.append(prepared)
        else:
            sb.append(prepared)

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
