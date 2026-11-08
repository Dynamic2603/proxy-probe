from __future__ import annotations

from proxy_probe.models import (
    RESULT_BLOCK,
    RESULT_DEAD,
    RESULT_OK,
    RESULT_UNKNOWN,
    STATE_ACTIVE,
    STATE_DEGRADED,
    Server,
)
from proxy_probe.stats import compute_summary_stats


def _make_server(
    index: int = 1,
    gid: int = 1,
    gname: str = "Group 1",
    result: str = RESULT_OK,
    latency_ms: int = 100,
    country_code: str = "DE",
    country: str = "Германия",
    note: str = "",
    state: str = STATE_ACTIVE,
    org: str = "",
    score: int = 70,
) -> Server:
    return Server(
        group_id=gid,
        group_name=gname,
        name=f"Server {index}",
        engine="sing-box",
        server=f"10.0.{gid}.{index}",
        server_port=443,
        import_obj={},
        source="fresh",
        index=index,
        result=result,
        latency_ms=latency_ms,
        country_code=country_code,
        country=country,
        note=note,
        state=state,
        org=org,
        score=score,
    )


def test_compute_summary_stats_empty() -> None:
    stats = compute_summary_stats([])
    assert stats.total == 0
    assert stats.tested == 0
    assert stats.counts == {}
    assert stats.geo_stats == []
    assert stats.latency_min == 0
    assert stats.latency_median == 0
    assert stats.latency_avg == 0
    assert stats.group_stats == []
    assert stats.failure_reasons == []
    assert stats.org_stats == []


def test_compute_summary_stats_latency_and_geo() -> None:
    s1 = _make_server(1, result=RESULT_OK, latency_ms=50, country_code="DE", country="Германия")
    s2 = _make_server(2, result=RESULT_OK, latency_ms=150, country_code="DE", country="Германия")
    s3 = _make_server(3, result=RESULT_OK, latency_ms=100, country_code="NL", country="Нидерланды")
    s4 = _make_server(4, result=RESULT_DEAD, latency_ms=0, country_code="DE", country="Германия")

    stats = compute_summary_stats([s1, s2, s3, s4])
    assert stats.total == 4
    assert stats.tested == 4
    assert stats.counts[RESULT_OK] == 3
    assert stats.counts[RESULT_DEAD] == 1

    # Latencies: 50, 100, 150
    assert stats.latency_min == 50
    assert stats.latency_median == 100
    assert stats.latency_avg == 100

    # Geo: DE has 2 OK (avg 100 ms), NL has 1 OK (avg 100 ms)
    assert len(stats.geo_stats) == 2
    assert stats.geo_stats[0].code == "DE"
    assert stats.geo_stats[0].name == "Германия"
    assert stats.geo_stats[0].count == 2
    assert stats.geo_stats[0].avg_latency_ms == 100

    assert stats.geo_stats[1].code == "NL"
    assert stats.geo_stats[1].name == "Нидерланды"
    assert stats.geo_stats[1].count == 1
    assert stats.geo_stats[1].avg_latency_ms == 100


def test_compute_summary_stats_group_order_and_rate() -> None:
    # Group B has 1 fresh OK, Group A has 2 fresh OK
    s1 = _make_server(1, gid=20, gname="Group B", result=RESULT_OK)
    s2 = _make_server(2, gid=20, gname="Group B", result=RESULT_DEAD)
    s3 = _make_server(3, gid=10, gname="Group A", result=RESULT_OK)
    s4 = _make_server(4, gid=10, gname="Group A", result=RESULT_OK)

    stats = compute_summary_stats([s1, s2, s3, s4])
    assert len(stats.group_stats) == 2
    # Сортировка по выявленным свежим AGY-OK: Group A (2 OK) впереди Group B (1 OK)
    assert stats.group_stats[0].group_id == 10
    assert stats.group_stats[0].ok_count == 2
    assert stats.group_stats[0].fresh_ok_count == 2
    assert stats.group_stats[0].total_count == 2
    assert stats.group_stats[0].success_rate == 100.0

    assert stats.group_stats[1].group_id == 20
    assert stats.group_stats[1].ok_count == 1
    assert stats.group_stats[1].fresh_ok_count == 1
    assert stats.group_stats[1].total_count == 2
    assert stats.group_stats[1].success_rate == 50.0


def test_compute_summary_stats_group_fresh_vs_cached_sorting() -> None:
    # Group Cached has 10 OK from cache (0 fresh)
    cached_servers = [
        _make_server(i, gid=1, gname="Cached Group", result=RESULT_OK)
        for i in range(10)
    ]
    for s in cached_servers:
        s.from_cache = True

    # Group Fresh has only 1 OK, but it is freshly verified in this run
    fresh_s = _make_server(100, gid=2, gname="Fresh Group", result=RESULT_OK)
    fresh_s.from_cache = False

    stats = compute_summary_stats([*cached_servers, fresh_s])
    assert len(stats.group_stats) == 2
    # Fresh Group (1 fresh OK) must be ranked ahead of Cached Group (0 fresh OK)
    assert stats.group_stats[0].group_id == 2
    assert stats.group_stats[0].fresh_ok_count == 1
    assert stats.group_stats[1].group_id == 1
    assert stats.group_stats[1].fresh_ok_count == 0


def test_compute_summary_stats_failure_classification() -> None:
    s_tcp = _make_server(1, result=RESULT_DEAD, note="tcp: таймаут соединения (хост не отвечает)")
    s_rep = _make_server(2, result=RESULT_DEAD, note="отсев по узлу (хост упал)")
    s_geo = _make_server(3, result=RESULT_BLOCK, note="User location is not supported")
    s_to = _make_server(4, result=RESULT_DEAD, note="таймаут preflight 2.5s")
    s_eng = _make_server(5, result=RESULT_DEAD, note="движок не поднял порт")
    s_quota = _make_server(6, result=RESULT_UNKNOWN, note="лимит квоты agy")

    stats = compute_summary_stats([s_tcp, s_rep, s_geo, s_to, s_eng, s_quota])
    fail_dict = dict(stats.failure_reasons)
    assert fail_dict["L4 TCP недоступен (порт закрыт/таймаут)"] == 1
    assert fail_dict["Отсев по хосту (узел недоступен)"] == 1
    assert fail_dict["Геоблок Gemini (AGY-BLOCK)"] == 1
    assert fail_dict["Таймаут туннеля / handshake"] == 1
    assert fail_dict["Ошибка запуска движка (sing-box/Xray)"] == 1


def test_compute_summary_stats_includes_degraded_nodes() -> None:
    # DEGRADED nodes count as working for summary table and stats
    s_ok = _make_server(1, result=RESULT_OK, latency_ms=80, state=STATE_ACTIVE)
    s_deg = _make_server(2, result=RESULT_DEAD, latency_ms=120, state=STATE_DEGRADED)
    s_dead = _make_server(3, result=RESULT_DEAD, latency_ms=0, state=RESULT_DEAD)

    stats = compute_summary_stats([s_ok, s_deg, s_dead])
    # Latencies should include s_ok and s_deg (80 and 120 -> avg 100)
    assert stats.latency_avg == 100
    assert stats.latency_min == 80


def test_compute_summary_stats_org_ranking() -> None:
    # Org A: 2 OK servers (avg 60ms, score 90, countries DE, FI)
    s1 = _make_server(1, result=RESULT_OK, latency_ms=50, score=90, country_code="DE", org="Hosting Alpha")
    s2 = _make_server(2, result=RESULT_OK, latency_ms=70, score=90, country_code="FI", org="Hosting Alpha")
    s3 = _make_server(3, result=RESULT_DEAD, latency_ms=0, score=0, country_code="DE", org="Hosting Alpha")

    # Org B: 1 OK server (avg 120ms, score 70, country NL)
    s4 = _make_server(4, result=RESULT_OK, latency_ms=120, score=70, country_code="NL", org="Hosting Beta")

    # Empty org: should be ignored or not crash
    s5 = _make_server(5, result=RESULT_OK, latency_ms=80, org="")

    stats = compute_summary_stats([s1, s2, s3, s4, s5])
    assert len(stats.org_stats) == 2
    # Leader is Hosting Alpha (2 OK)
    org_a = stats.org_stats[0]
    assert org_a.org_name == "Hosting Alpha"
    assert org_a.ok_count == 2
    assert org_a.total_count == 3
    assert org_a.avg_latency_ms == 60
    assert org_a.avg_score == 90
    assert org_a.countries == ["DE", "FI"]

    # Second is Hosting Beta (1 OK)
    org_b = stats.org_stats[1]
    assert org_b.org_name == "Hosting Beta"
    assert org_b.ok_count == 1
    assert org_b.total_count == 1
    assert org_b.avg_latency_ms == 120
    assert org_b.avg_score == 70
    assert org_b.countries == ["NL"]
