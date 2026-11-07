from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from proxy_probe.models import (
    RESULT_BLOCK,
    RESULT_DEAD,
    RESULT_OK,
    RESULT_UNKNOWN,
    Server,
)
from proxy_probe.ui import (
    console,
    format_cached_counters,
    format_latency,
    format_live_counters,
    format_result,
    print_progress_row,
    print_results_table,
    print_summary_panel,
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


def test_format_cached_counters_with_unique_hosts() -> None:
    cached = {RESULT_OK: 10, RESULT_BLOCK: 2}
    unique = {
        RESULT_OK: {"1.1.1.1:443", "2.2.2.2:443"},
        RESULT_BLOCK: {"3.3.3.3:443", "4.4.4.4:443"},
    }
    res = format_cached_counters(cached, unique)
    assert res == "Из кэша: AGY-OK: 10 (2 уникальных), AGY-BLOCK: 2"


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


def test_print_results_table_mode_none() -> None:
    s = Server(1, "G", "S", "sing-box", "1.1.1.1", 443, {}, "fresh", result=RESULT_OK)
    with patch.object(console, "print") as mock_print:
        print_results_table([s], mode="none")
        mock_print.assert_not_called()


def test_print_results_table_mode_ok_filters_dead() -> None:
    s_ok = Server(1, "G", "S1", "sing-box", "1.1.1.1", 443, {}, "fresh", index=1, result=RESULT_OK)
    s_dead = Server(1, "G", "S2", "sing-box", "2.2.2.2", 443, {}, "fresh", index=2, result=RESULT_DEAD)

    with patch.object(console, "print") as mock_print:
        print_results_table([s_ok, s_dead], mode="ok", limit=20)
        mock_print.assert_called_once()
        table = mock_print.call_args[0][0]
        # Only 1 row in table (s_ok), s_dead filtered out
        assert table.row_count == 1


def test_print_results_table_limit_caption() -> None:
    s1 = Server(1, "G", "S1", "sing-box", "1.1.1.1", 443, {}, "fresh", index=1, result=RESULT_OK)
    s2 = Server(1, "G", "S2", "sing-box", "2.2.2.2", 443, {}, "fresh", index=2, result=RESULT_OK)

    with patch.object(console, "print") as mock_print:
        print_results_table([s1, s2], mode="ok", limit=1)
        table = mock_print.call_args[0][0]
        assert table.row_count == 1
        assert "Показано первых 1 из 2" in str(table.caption)


def test_print_summary_panel_renders_stats() -> None:
    s1 = Server(
        1,
        "G1",
        "S1",
        "sing-box",
        "1.1.1.1",
        443,
        {},
        "fresh",
        index=1,
        result=RESULT_OK,
        latency_ms=90,
        country_code="DE",
        country="Германия",
    )
    s2 = Server(
        1,
        "G1",
        "S2",
        "sing-box",
        "2.2.2.2",
        443,
        {},
        "fresh",
        index=2,
        result=RESULT_DEAD,
        note="tcp: таймаут",
    )

    with patch.object(console, "print") as mock_print:
        print_summary_panel(
            servers=[s1, s2],
            cached_counts={},
            report_path=Path("report.md"),
            import_path=Path("proxy-ok.txt"),
            nb=1,
            nx=0,
            elapsed_s=2.5,
        )
        mock_print.assert_called_once()
        panel = mock_print.call_args[0][0]
        panel_text = str(panel.renderable)
        assert "AGY-OK" in panel_text
        assert "DE (Германия)" in panel_text
        assert "L4 TCP недоступен" in panel_text
        assert "Задержка (AGY-OK)" in panel_text
