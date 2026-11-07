from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from proxy_probe.antidpi.benchmark import (
    apply_relay_detour,
    build_relay_detour,
    calculate_strategy_score,
    format_benchmark_table,
    load_ratings,
    prepare_strategies_for_level,
    probe_proxy_tunnel,
    save_ratings,
    select_dead_servers,
)
from proxy_probe.antidpi.models import (
    AntidpiBenchmarkResult,
    StrategyProfile,
    StrategyRating,
)
from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, Server


def make_srv(host: str, result: str, port: int = 443) -> Server:
    return Server(
        group_id=1,
        group_name="G1",
        name=f"s_{host}",
        engine="sing-box",
        server=host,
        server_port=port,
        import_obj={"type": "vless", "server": host, "server_port": port},
        source="fresh",
        result=result,
    )


def test_select_dead_servers() -> None:
    s_ok = make_srv("1.1.1.1", RESULT_OK)
    s_block = make_srv("2.2.2.2", RESULT_BLOCK)
    s_dead1 = make_srv("3.3.3.3", RESULT_DEAD)
    s_dead2 = make_srv("3.3.3.3", RESULT_DEAD)  # Дубликат по хосту
    s_dead3 = make_srv("4.4.4.4", RESULT_DEAD)

    selected = select_dead_servers([s_ok, s_block, s_dead1, s_dead2, s_dead3], limit=10)
    assert len(selected) == 2
    hosts = [s.server for s in selected]
    assert hosts == ["3.3.3.3", "4.4.4.4"]


def test_calculate_strategy_score() -> None:
    assert calculate_strategy_score(0, 10, 0) == 0
    # 10 из 10 спасено, задержка 80мс
    score_fast = calculate_strategy_score(10, 10, 80)
    assert score_fast == 100

    # 5 из 10 спасено, задержка 150мс
    score_mid = calculate_strategy_score(5, 10, 150)
    assert 50 <= score_mid <= 65

    # Штраф за повторные сбои
    score_penalized = calculate_strategy_score(10, 10, 80, failures=2)
    assert score_penalized == 50  # 100 - 2 * 25


def test_build_relay_detour() -> None:
    # sing-box
    sb_detour, sb_out = build_relay_detour(is_xray=False, relay_port=10850)
    assert sb_detour == {"detour": "zapret-relay"}
    assert sb_out["type"] == "socks"
    assert sb_out["server_port"] == 10850

    # Xray (modern Xray 26+ dialerProxy)
    xr_detour, xr_out = build_relay_detour(is_xray=True, relay_port=10850)
    assert xr_detour == {"streamSettings": {"sockopt": {"dialerProxy": "zapret-relay"}}}
    assert xr_out["protocol"] == "socks"
    assert xr_out["settings"]["servers"][0]["port"] == 10850


def test_apply_relay_detour() -> None:
    # sing-box
    sb_obj = {"type": "vless", "server": "1.2.3.4"}
    patched_sb = apply_relay_detour(sb_obj, is_xray=False)
    assert patched_sb["detour"] == "zapret-relay"

    # Xray with existing streamSettings (preserves existing properties)
    xr_obj = {
        "protocol": "vless",
        "streamSettings": {"security": "reality", "realitySettings": {"serverName": "test.com"}},
    }
    patched_xr = apply_relay_detour(xr_obj, is_xray=True)
    assert patched_xr["streamSettings"]["sockopt"]["dialerProxy"] == "zapret-relay"
    assert patched_xr["streamSettings"]["realitySettings"]["serverName"] == "test.com"


def test_probe_proxy_tunnel_invalid() -> None:
    srv = make_srv("127.0.0.1", RESULT_DEAD)
    srv.import_obj = {}
    ok, lat, reason = probe_proxy_tunnel(srv)
    assert not ok
    assert lat == 0
    assert "import_obj" in reason


def test_save_and_load_ratings(tmp_path: Path) -> None:
    ratings_file = tmp_path / "ratings.json"
    r1 = StrategyRating(
        strategy_number=1,
        strategy_name="Fake + Split",
        family_name="fake + multisplit",
        rescued_count=8,
        total_tested=10,
        success_rate=0.8,
        avg_latency_ms=75,
        score=84,
    )
    bench = AntidpiBenchmarkResult(
        tested_at="2026-11-07T07:00:00",
        isp="MTS",
        best_strategy_number=1,
        ratings=[r1],
    )

    save_ratings(bench, path=ratings_file)
    assert ratings_file.is_file()

    loaded = load_ratings(path=ratings_file)
    assert loaded is not None
    assert loaded.isp == "MTS"
    assert loaded.best_strategy_number == 1
    assert len(loaded.ratings) == 1
    assert loaded.ratings[0].strategy_number == 1
    assert loaded.ratings[0].technical_family == "fake + multisplit"


def test_format_benchmark_table() -> None:
    r1 = StrategyRating(
        strategy_number=1,
        strategy_name="Fake + Split",
        family_name="fake + multisplit",
        rescued_count=8,
        total_tested=10,
        success_rate=0.8,
        avg_latency_ms=75,
        score=84,
        status="TOP",
    )
    bench = AntidpiBenchmarkResult(
        tested_at="2026-11-07T07:00:00",
        isp="MTS",
        best_strategy_number=1,
        ratings=[r1],
    )
    table = format_benchmark_table(bench)
    assert "⭐ S01" in table
    assert "8/10" in table
    assert "80%" in table
    assert "75 мс" in table
    assert "fake + multisplit" in table
    assert "[⭐TOP]" in table


def test_living_ratings_feedback_and_merge() -> None:
    bench = AntidpiBenchmarkResult(
        tested_at="2026-11-07T07:00:00",
        isp="AutoDetected",
        best_strategy_number=10,
        ratings=[
            StrategyRating(
                strategy_number=10,
                strategy_name="Spotify",
                family_name="fake + multisplit",
                rescued_count=2,
                total_tested=10,
                success_rate=0.2,
                avg_latency_ms=120,
                score=40,
                status="ACTIVE",
            )
        ],
    )

    # 1. Живой сбой (0 спасено) -> штраф и перевод в DEGRADED
    bench.record_live_feedback(strategy_number=10, rescued=0, total=10)
    assert bench.ratings[0].consecutive_failures == 1
    assert bench.ratings[0].score == 15  # 40 - 25
    assert bench.ratings[0].status == "DEGRADED"

    # 2. Еще один сбой -> score падает до 0, статус DEAD
    bench.record_live_feedback(strategy_number=10, rescued=0, total=10)
    assert bench.ratings[0].consecutive_failures == 2
    assert bench.ratings[0].score == 0
    assert bench.ratings[0].status == "DEAD"
    assert bench.best_strategy_number is None

    # 3. Успешный бенчмарк оживляет стратегию
    new_r = StrategyRating(
        strategy_number=10,
        strategy_name="Spotify",
        family_name="fake + multisplit",
        rescued_count=5,
        total_tested=10,
        success_rate=0.5,
        avg_latency_ms=110,
        score=65,
    )
    bench.merge_benchmark_results([new_r])
    assert bench.ratings[0].consecutive_failures == 0
    assert bench.ratings[0].score == 65
    assert bench.ratings[0].status == "ACTIVE"
    assert bench.best_strategy_number == 10


def test_prepare_strategies_for_level() -> None:
    strat1 = StrategyProfile(1, 1, "fake + multisplit", 1, "S1", "", ())
    strat2 = StrategyProfile(2, 2, "tcpseg", 1, "S2", "", ())
    catalogue = [strat1, strat2]

    living = AntidpiBenchmarkResult(
        tested_at="",
        isp="",
        best_strategy_number=2,
        ratings=[
            StrategyRating(2, "S2", "tcpseg", 1, 1, 1.0, 50, 90, status="TOP"),
        ],
    )

    # Уровень 2: приоритет проверенным лидерам (S2 идет раньше S1)
    l2 = prepare_strategies_for_level(2, catalogue, living)
    assert len(l2) == 2
    assert l2[0].number == 2
    assert l2[1].number == 1


def test_select_dead_servers_ranking() -> None:
    s_l4_dead = make_srv("1.1.1.1", RESULT_DEAD)
    s_l4_dead.note = "tcp: таймаут соединения (хост не отвечает)"

    s_preflight = make_srv("2.2.2.2", RESULT_DEAD)
    s_preflight.note = "preflight: туннель не пропускает трафик"

    s_degraded = make_srv("3.3.3.3", RESULT_DEAD)
    s_degraded.state = "DEGRADED"

    selected = select_dead_servers([s_l4_dead, s_preflight, s_degraded], limit=2)
    assert len(selected) == 2
    # Preflight и Degraded должны идти раньше мертвого L4 TCP
    assert selected[0].server == "2.2.2.2"
    assert selected[1].server == "3.3.3.3"


def test_collect_dead_candidates_from_cache(tmp_path: Path) -> None:
    from proxy_probe.antidpi.__main__ import collect_dead_candidates
    from proxy_probe.cache import ResultCache

    c_file = tmp_path / "test_cache.json"
    cache = ResultCache(path=c_file)
    cache.entries = {
        "s1": {
            "result": RESULT_DEAD,
            "state": "DEAD",
            "note": "preflight drop",
            "import_obj": {"type": "vless", "server": "8.8.8.8", "server_port": 443},
        }
    }

    # Подменяем чтение Throne, чтобы проверить fallback
    with patch("proxy_probe.throne.read_groups", side_effect=RuntimeError("no throne")):
        cands = collect_dead_candidates(cache)
        assert len(cands) == 1
        assert cands[0].server == "8.8.8.8"
        assert cands[0].note == "preflight drop"
