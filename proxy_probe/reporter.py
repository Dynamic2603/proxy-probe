from __future__ import annotations

import copy
import datetime as _dt
import json
import shutil
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from .antidpi.benchmark import apply_relay_detour, build_relay_outbound
from .antidpi.relay import DEFAULT_RELAY_PORT
from .cache import ResultCache, server_from_cache_entry
from .engines import singbox_to_xray_outbound
from .models import (
    STATE_DEGRADED,
    Server,
    format_score_display,
    is_exportable,
)
from .stats import SummaryStats, compute_summary_stats


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
    stats: SummaryStats | None = None,
) -> None:
    if stats is None:
        stats = compute_summary_stats(servers)
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

    ok_orgs = [o for o in stats.org_stats if o.ok_count > 0]
    if ok_orgs:
        lines.append("\n## Рейтинг хостинг-провайдеров (Дата-центры / ISP)\n")
        lines.append(
            "| № | Провайдер | Рабочих узлов | Всего узлов | Ср. задержка | Ср. скор | Страны |"
        )
        lines.append(
            "|---|-----------|:-------------:|:-----------:|:------------:|:--------:|--------|"
        )
        for idx, org in enumerate(ok_orgs, 1):
            c_str = ", ".join(org.countries) if org.countries else "-"
            score_str = format_score_display(org.avg_score)
            lat_str = f"{org.avg_latency_ms} мс" if org.avg_latency_ms > 0 else "-"
            name_clean = org.org_name.replace("|", "\\|")
            lines.append(
                f"| {idx} | {name_clean} | {org.ok_count} | {org.total_count} | {lat_str} | {score_str} | {c_str} |"
            )

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
        score_str = format_score_display(s.score, s.state)
        lines.append(
            f"| {s.index} | {s.result or '—'} | {state_str} | {score_str} | {s.group_name} | {s.engine} | "
            f"{s.server}:{s.server_port} | {s.country} | {s.ip_out} | {s.latency_ms} | {name} | {note} |"
        )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def deduplicate_by_endpoint(servers: Iterable[Server]) -> list[Server]:
    """Отбирает ровно один лучший рабочий профиль для каждого уникального эндпоинта (SRP).

    Для конфигураций, идентичных по протоколу, хосту, порту, ключам и SNI, но различающихся
    только отпечатком uTLS (fingerprint), сохраняется только сильнейший профиль по Server.export_rank.
    """
    best_by_endpoint: dict[str, Server] = {}
    for s in servers:
        if not s.is_exportable or not s.import_obj:
            continue
        key = s.endpoint_identity
        current = best_by_endpoint.get(key)
        if current is None or s.export_rank > current.export_rank:
            best_by_endpoint[key] = s
    return list(best_by_endpoint.values())


def write_import_file(
    cache: ResultCache | None,
    path: Path,
    fallback_servers: list[Server] | None = None,
    relay_port: int = DEFAULT_RELAY_PORT,
) -> tuple[int, int]:
    sb: list[dict] = []
    xr: list[dict] = []

    def _prepare_obj(srv: Server) -> dict:
        obj = copy.deepcopy(srv.import_obj)
        obj["tag"] = srv.formatted_tag
        return obj

    candidates: list[Server] = []

    # 1. Серверы активного пула в UI-порядке (s.index)
    if fallback_servers:
        for s in fallback_servers:
            if s.is_exportable and s.import_obj:
                candidates.append(s)

    # 2. Дополнительные валидные серверы из кэша
    if cache is not None:
        for entry_key, entry in cache.entries.items():
            state = str(entry.get("state", ""))
            res = str(entry.get("result", ""))
            if not is_exportable(res, state) or not cache.is_valid(entry_key):
                continue
            cached_srv = server_from_cache_entry(entry)
            if cached_srv is not None:
                candidates.append(cached_srv)

    # Дедупликация по сервисному эндпоинту: 1 лучший профиль на узел
    ok_servers = deduplicate_by_endpoint(candidates)
    ok_servers.sort(key=lambda s: s.export_rank, reverse=True)

    has_zapret_sb = False
    has_zapret_xr = False

    for s in ok_servers:
        prepared = _prepare_obj(s)
        is_xray = bool(s.engine == "xray" or (not s.engine and s.import_obj.get("protocol")))
        is_zapret = bool(s.antidpi_strategy and s.antidpi_strategy > 0 and s.is_tcp_protocol)

        if is_zapret:
            # Для узлов sing-box, требующих Zapret, конвертируем в Xray:
            # Throne блокирует detour в sing-box подписках, но полностью поддерживает dialerProxy в Xray
            if not is_xray:
                converted = singbox_to_xray_outbound(prepared)
                if "protocol" in converted:
                    prepared = converted
                    is_xray = True

            prepared = apply_relay_detour(prepared, is_xray=is_xray)
            if is_xray:
                has_zapret_xr = True
            else:
                has_zapret_sb = True
        else:
            # Прямые серверы никогда не должны содержать detour / dialerProxy
            prepared.pop("detour", None)
            if (
                isinstance(ss := prepared.get("streamSettings"), dict)
                and isinstance(sockopt := ss.get("sockopt"), dict)
            ):
                sockopt.pop("dialerProxy", None)

        if is_xray:
            xr.append(prepared)
        else:
            sb.append(prepared)

    if has_zapret_sb:
        sb.append(build_relay_outbound(is_xray=False, relay_port=relay_port))
    if has_zapret_xr:
        xr.append(build_relay_outbound(is_xray=True, relay_port=relay_port))

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
