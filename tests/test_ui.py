from __future__ import annotations

from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, RESULT_UNKNOWN, Server
from proxy_probe.ui import (
    format_cached_counters,
    format_latency,
    format_live_counters,
    format_result,
    print_progress_row,
)


def test_format_result() -> None:
    assert "AGY-OK" in format_result(RESULT_OK)
    assert "AGY-BLOCK" in format_result(RESULT_BLOCK)
    assert "DEAD" in format_result(RESULT_DEAD)
    assert "UNKNOWN" in format_result(RESULT_UNKNOWN)
    assert "—" in format_result("")


def test_format_latency() -> None:
    assert format_latency(0) == "-"
    assert "200 мс" in format_latency(200)
    assert "800 мс" in format_latency(800)
    assert "2000 мс" in format_latency(2000)


def test_format_cached_counters() -> None:
    # Multiple cached values
    cached = {RESULT_OK: 32, RESULT_BLOCK: 5, RESULT_DEAD: 0}
    res = format_cached_counters(cached)
    assert res == "Из кэша: AGY-OK: 32, AGY-BLOCK: 5"

    # Empty cached counts
    assert format_cached_counters({}) == ""
    assert format_cached_counters({RESULT_OK: 0, RESULT_DEAD: 0}) == ""


def test_format_live_counters() -> None:
    counts = {
        RESULT_OK: 32,
        RESULT_BLOCK: 5,
        RESULT_DEAD: 532,
        RESULT_UNKNOWN: 1,
    }
    res = format_live_counters(counts)
    assert res == "AGY-OK: 32 | AGY-BLOCK: 5 | DEAD: 532 | UNKNOWN: 1"

    # Missing keys default to 0
    res_partial = format_live_counters({RESULT_OK: 10})
    assert res_partial == "AGY-OK: 10 | AGY-BLOCK: 0 | DEAD: 0 | UNKNOWN: 0"


def test_print_progress_row_write_fn() -> None:
    server = Server(
        group_id=1,
        group_name="Default",
        name="TestServer",
        engine="sing-box",
        server="127.0.0.1",
        server_port=8080,
        import_obj={},
        source="fresh",
        result=RESULT_OK,
        latency_ms=120,
    )
    written: list[str] = []
    print_progress_row(server, 1, 10, write_fn=written.append)
    assert len(written) == 1
    assert "127.0.0.1:8080" in written[0]
    assert "AGY-OK" in written[0]
