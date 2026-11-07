from __future__ import annotations

from pathlib import Path

from proxy_probe.antidpi.benchmark import (
    build_relay_detour,
    calculate_strategy_score,
    format_benchmark_table,
    load_ratings,
    save_ratings,
    select_dead_servers,
)
from proxy_probe.antidpi.models import AntidpiBenchmarkResult, StrategyRating
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
    assert 50 <= score_mid <= 60


def test_build_relay_detour() -> None:
    # sing-box
    sb_detour, sb_out = build_relay_detour(is_xray=False, relay_port=10850)
    assert sb_detour == {"detour": "zapret-relay"}
    assert sb_out["type"] == "socks"
    assert sb_out["server_port"] == 10850

    # Xray
    xr_detour, xr_out = build_relay_detour(is_xray=True, relay_port=10850)
    assert xr_detour == {"proxySettings": {"tag": "zapret-relay"}}
    assert xr_out["protocol"] == "socks"
    assert xr_out["settings"]["servers"][0]["port"] == 10850


def test_save_and_load_ratings(tmp_path: Path) -> None:
    ratings_file = tmp_path / "ratings.json"
    r1 = StrategyRating(
        strategy_number=1,
        strategy_name="Fake + Split",
        family_name="Golden 1",
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


def test_format_benchmark_table() -> None:
    r1 = StrategyRating(
        strategy_number=1,
        strategy_name="Fake + Split",
        family_name="Golden 1",
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
    table = format_benchmark_table(bench)
    assert "⭐ S01" in table
    assert "8/10" in table
    assert "80%" in table
    assert "75 мс" in table
    assert "Golden 1" in table
