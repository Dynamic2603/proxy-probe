from __future__ import annotations

import dataclasses
import statistics
from collections import Counter
from typing import Any

from .models import (
    BLOCK_MARKERS,
    RESULT_BLOCK,
    RESULT_DEAD,
    RESULT_OK,
    STATE_DEGRADED,
    Server,
    normalize_org_name,
)


@dataclasses.dataclass(frozen=True)
class GeoStat:
    code: str
    name: str
    count: int
    avg_latency_ms: int


@dataclasses.dataclass(frozen=True)
class GroupStat:
    group_id: int
    group_name: str
    ok_count: int
    total_count: int
    success_rate: float
    fresh_ok_count: int = 0


@dataclasses.dataclass(frozen=True)
class OrgStat:
    org_name: str
    ok_count: int
    total_count: int
    avg_latency_ms: int
    avg_score: int
    countries: list[str]


@dataclasses.dataclass(frozen=True)
class SummaryStats:
    total: int
    tested: int
    counts: dict[str, int]
    geo_stats: list[GeoStat]
    latency_min: int
    latency_median: int
    latency_avg: int
    group_stats: list[GroupStat]
    failure_reasons: list[tuple[str, int]]
    org_stats: list[OrgStat] = dataclasses.field(default_factory=list)


def _classify_failure(server: Server) -> str:
    """Определяет человекочитаемую категорию сбоя узла (SSOT)."""
    note = (server.note or "").lower()
    res = server.result

    if res == RESULT_BLOCK or any(m.lower() in note for m in BLOCK_MARKERS):
        return "Геоблок Gemini (AGY-BLOCK)"
    if note.startswith("tcp:"):
        return "L4 TCP недоступен (порт закрыт/таймаут)"
    if "отсев по узлу" in note:
        return "Отсев по хосту (узел недоступен)"
    if "таймаут" in note or "timeout" in note or "deadline" in note:
        return "Таймаут туннеля / handshake"
    if "движок не поднял порт" in note or "exit code" in note:
        return "Ошибка запуска движка (sing-box/Xray)"
    if "лимит квоты" in note or "quota" in note:
        return "Исчерпана квота agy"
    if "tls" in note or "certificate" in note:
        return "Ошибка TLS / сертификата"
    if "connection refused" in note or "connection reset" in note or "eof" in note:
        return "Сброс соединения / отказ узла"
    return "Прочие сетевые ошибки"


def compute_summary_stats(servers: list[Server]) -> SummaryStats:
    """Вычисляет аналитическую сводку по пулу проверенных серверов (SSOT / чистая функция)."""
    total = len(servers)
    tested = sum(1 for s in servers if s.result)
    counts = dict(Counter(s.result for s in servers if s.result))

    # 1. Рабочие серверы (AGY-OK и удерживаемые DEGRADED)
    working_servers = [s for s in servers if s.result == RESULT_OK or s.state == STATE_DEGRADED]

    # 2. Задержка для рабочих серверов
    latencies = [s.latency_ms for s in working_servers if s.latency_ms > 0]
    lat_min = min(latencies) if latencies else 0
    lat_med = int(statistics.median(latencies)) if latencies else 0
    lat_avg = int(sum(latencies) / len(latencies)) if latencies else 0

    # 3. География рабочих серверов (без emoji-флагов, текстовые коды и названия)
    geo_map: dict[tuple[str, str], list[int]] = {}
    for s in working_servers:
        code = (s.country_code or "").strip().upper()
        name = (s.country or "").strip()
        if not code and not name:
            code = "UNKNOWN"
            name = "Неизвестно"
        elif not code:
            code = name.upper()[:3]
        elif not name:
            name = code
        geo_map.setdefault((code, name), []).append(s.latency_ms)

    geo_stats: list[GeoStat] = []
    for (code, name), lats in geo_map.items():
        valid_lats = [x for x in lats if x > 0]
        avg_l = int(sum(valid_lats) / len(valid_lats)) if valid_lats else 0
        geo_stats.append(
            GeoStat(
                code=code,
                name=name,
                count=len(lats),
                avg_latency_ms=avg_l,
            )
        )
    # Сортировка по убыванию количества, затем по задержке
    geo_stats.sort(key=lambda g: (-g.count, g.avg_latency_ms))

    # 4. Статистика по подпискам/группам (сохраняя UI-порядок первого появления)
    groups_order: list[int] = []
    groups_data: dict[int, dict[str, Any]] = {}
    for s in servers:
        gid = s.group_id
        if gid not in groups_data:
            groups_order.append(gid)
            groups_data[gid] = {
                "name": s.group_name or f"Group {gid}",
                "total": 0,
                "ok": 0,
                "fresh_ok": 0,
            }
        groups_data[gid]["total"] += 1
        if s.result == RESULT_OK or s.state == STATE_DEGRADED:
            groups_data[gid]["ok"] += 1
        if s.result == RESULT_OK and not getattr(s, "from_cache", False):
            groups_data[gid]["fresh_ok"] += 1

    group_stats: list[GroupStat] = []
    for gid in groups_order:
        d = groups_data[gid]
        t_cnt = d["total"]
        o_cnt = d["ok"]
        f_cnt = d["fresh_ok"]
        rate = (o_cnt / t_cnt * 100.0) if t_cnt > 0 else 0.0
        group_stats.append(
            GroupStat(
                group_id=gid,
                group_name=d["name"],
                ok_count=o_cnt,
                total_count=t_cnt,
                success_rate=rate,
                fresh_ok_count=f_cnt,
            )
        )

    # Сортировка подписок: по количеству выявленных AGY-OK в текущей проверке (без кэша),
    # затем по общему числу OK и проценту успеха
    group_stats.sort(
        key=lambda g: (g.fresh_ok_count, g.ok_count, g.success_rate),
        reverse=True,
    )

    # 5. Причины сбоев (для серверов с неуспешным результатом)
    failed_servers = [s for s in servers if s.result in (RESULT_DEAD, RESULT_BLOCK)]
    failure_counter = Counter(_classify_failure(s) for s in failed_servers)
    failure_reasons = failure_counter.most_common(6)

    # 6. Рейтинг хостинг-провайдеров (дата-центров / ISP)
    orgs_map: dict[str, list[Server]] = {}
    for s in servers:
        clean_org = normalize_org_name(s.org)
        if clean_org:
            orgs_map.setdefault(clean_org, []).append(s)

    org_stats: list[OrgStat] = []
    for org_name, org_servers in orgs_map.items():
        ok_servers = [s for s in org_servers if s.result == RESULT_OK or s.state == STATE_DEGRADED]
        ok_cnt = len(ok_servers)
        lats = [s.latency_ms for s in ok_servers if s.latency_ms > 0]
        avg_l = int(sum(lats) / len(lats)) if lats else 0
        scores = [s.score for s in ok_servers if s.score > 0]
        avg_s = int(sum(scores) / len(scores)) if scores else 0
        countries = sorted(list({s.country_code.upper() for s in ok_servers if s.country_code}))
        org_stats.append(
            OrgStat(
                org_name=org_name,
                ok_count=ok_cnt,
                total_count=len(org_servers),
                avg_latency_ms=avg_l,
                avg_score=avg_s,
                countries=countries,
            )
        )
    # Сортировка: больше рабочих узлов -> меньше задержка -> выше скор -> по имени
    org_stats.sort(
        key=lambda o: (-o.ok_count, o.avg_latency_ms if o.ok_count > 0 else 999999, -o.avg_score, o.org_name)
    )

    return SummaryStats(
        total=total,
        tested=tested,
        counts=counts,
        geo_stats=geo_stats,
        latency_min=lat_min,
        latency_median=lat_med,
        latency_avg=lat_avg,
        group_stats=group_stats,
        failure_reasons=failure_reasons,
        org_stats=org_stats,
    )
