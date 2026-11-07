from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from tqdm import tqdm

from proxy_probe.cli import _execute_probe_pool, build_arg_parser
from proxy_probe.models import RESULT_DEAD, RESULT_OK, Server


def test_execute_probe_pool_interrupted() -> None:
    servers = [
        Server(
            group_id=1,
            group_name="Test",
            name=f"s{i}",
            engine="sing-box",
            server="1.1.1.1",
            server_port=443,
            import_obj={},
            source="fresh",
        )
        for i in range(5)
    ]

    class FakeCtx:
        xr_exe = "fake_xr"
        sb_exe = "fake_sb"
        agy_bin = "fake_agy"
        use_tcp_prefilter = False
        initial_circuit_breaker = None

    def mock_as_completed(futures):
        raise KeyboardInterrupt()

    with patch("proxy_probe.cli.concurrent.futures.as_completed", side_effect=mock_as_completed):
        completed, interrupted = _execute_probe_pool(
            to_probe=servers,
            jobs=2,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=FakeCtx(),  # type: ignore[arg-type]
            print_timeout="5s",
        )

    assert interrupted is True
    assert completed == 0


def test_execute_probe_pool_success_with_cached_counts() -> None:
    servers = [
        Server(
            group_id=1,
            group_name="Test",
            name="s1",
            engine="sing-box",
            server="1.1.1.1",
            server_port=443,
            import_obj={},
            source="fresh",
        )
    ]

    class FakeCtx:
        xr_exe = "fake_xr"
        sb_exe = "fake_sb"
        agy_bin = "fake_agy"
        use_tcp_prefilter = False
        initial_circuit_breaker = None

    mock_result = {
        "result": "AGY-OK",
        "country": "US",
        "ip_out": "1.1.1.1",
        "latency_ms": 100,
        "note": "ok",
    }

    with patch("proxy_probe.cli._probe_worker", return_value=mock_result):
        completed, interrupted = _execute_probe_pool(
            to_probe=servers,
            jobs=1,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=FakeCtx(),  # type: ignore[arg-type]
            print_timeout="5s",
            cached_counts={"AGY-OK": 32, "AGY-BLOCK": 5},
        )

    assert interrupted is False
    assert completed == 1
    assert servers[0].result == "AGY-OK"


def test_execute_probe_pool_stage0_dead_filtered() -> None:
    server = Server(
        group_id=1,
        group_name="Test",
        name="dead_host",
        engine="sing-box",
        server="192.0.2.1",
        server_port=443,
        import_obj={"type": "vless"},
        source="fresh",
    )

    class FakeCtx:
        xr_exe = "fake_xr"
        sb_exe = "fake_sb"
        agy_bin = "fake_agy"
        use_tcp_prefilter = True
        tcp_timeout = 1.0
        tcp_concurrency = 10
        initial_circuit_breaker = None

    mock_tcp_results = {
        ("192.0.2.1", 443): (False, 0, "tcp: таймаут соединения (хост не отвечает)"),
    }

    with (
        patch("proxy_probe.cli.batch_probe_tcp", return_value=mock_tcp_results),
        patch("proxy_probe.cli._probe_worker") as mock_worker,
    ):
        completed, interrupted = _execute_probe_pool(
            to_probe=[server],
            jobs=1,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=FakeCtx(),  # type: ignore[arg-type]
            print_timeout="5s",
        )

    assert interrupted is False
    assert completed == 1
    assert server.result == RESULT_DEAD
    assert "tcp: таймаут соединения" in server.note
    # Движок не должен был запускаться вообще
    mock_worker.assert_not_called()


def test_execute_probe_pool_stage0_alive_passed_to_engine() -> None:
    server = Server(
        group_id=1,
        group_name="Test",
        name="alive_host",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"type": "vless"},
        source="fresh",
    )

    class FakeCtx:
        xr_exe = "fake_xr"
        sb_exe = "fake_sb"
        agy_bin = "fake_agy"
        use_tcp_prefilter = True
        tcp_timeout = 1.0
        tcp_concurrency = 10
        initial_circuit_breaker = None

    mock_tcp_results = {
        ("1.1.1.1", 443): (True, 50, ""),
    }
    mock_engine_result = {
        "result": RESULT_OK,
        "country": "US",
        "ip_out": "1.1.1.1",
        "latency_ms": 120,
        "note": "ok",
    }

    with (
        patch("proxy_probe.cli.batch_probe_tcp", return_value=mock_tcp_results),
        patch("proxy_probe.cli._probe_worker", return_value=mock_engine_result) as mock_worker,
    ):
        completed, interrupted = _execute_probe_pool(
            to_probe=[server],
            jobs=1,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=FakeCtx(),  # type: ignore[arg-type]
            print_timeout="5s",
        )

    assert interrupted is False
    assert completed == 1
    assert server.result == RESULT_OK
    mock_worker.assert_called_once()


def test_cli_parser_tcp_flags() -> None:
    parser = build_arg_parser()
    args = parser.parse_args(["--no-tcp-prefilter", "--tcp-timeout", "2.5", "--tcp-concurrency", "50"])
    assert args.no_tcp_prefilter is True
    assert args.tcp_timeout == 2.5
    assert args.tcp_concurrency == 50


def test_cli_parser_table_flags() -> None:
    parser = build_arg_parser()
    # Default values
    default_args = parser.parse_args([])
    assert default_args.table == "ok"
    assert default_args.table_limit == 20

    # Custom values
    args = parser.parse_args(["--table", "none", "--table-limit", "100"])
    assert args.table == "none"
    assert args.table_limit == 100


def test_execute_probe_pool_engine_counters_isolated_from_cache() -> None:
    server = Server(
        group_id=1,
        group_name="Test",
        name="s1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={},
        source="fresh",
    )

    class FakeCtx:
        xr_exe = "fake_xr"
        sb_exe = "fake_sb"
        agy_bin = "fake_agy"
        use_tcp_prefilter = False
        initial_circuit_breaker = None

    mock_result = {
        "result": RESULT_OK,
        "country": "US",
        "ip_out": "1.1.1.1",
        "latency_ms": 100,
        "note": "ok",
    }

    postfix_calls: list[str] = []
    real_set_postfix = tqdm.set_postfix_str

    def fake_set_postfix(self: Any, s: str = "", refresh: bool = True) -> None:
        postfix_calls.append(s)
        real_set_postfix(self, s, refresh=refresh)

    with (
        patch("proxy_probe.cli._probe_worker", return_value=mock_result),
        patch.object(tqdm, "set_postfix_str", side_effect=fake_set_postfix, autospec=True),
    ):
        completed, interrupted = _execute_probe_pool(
            to_probe=[server],
            jobs=1,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=FakeCtx(),  # type: ignore[arg-type]
            print_timeout="5s",
            cached_counts={"AGY-OK": 50, "DEAD": 100},
        )

    assert interrupted is False
    assert completed == 1
    # Начальный постфикс должен стартовать с 0 (AGY-OK: 0), а финальный — ровно AGY-OK: 1 (не 50 и не 51)
    assert any("AGY-OK: 0" in call for call in postfix_calls)
    assert any("AGY-OK: 1" in call for call in postfix_calls)
    assert not any("AGY-OK: 50" in call or "AGY-OK: 51" in call for call in postfix_calls)


def test_execute_probe_pool_stage0_log_semantics() -> None:
    s1 = Server(
        group_id=1,
        group_name="T",
        name="s1",
        engine="sing-box",
        server="10.0.0.1",
        server_port=443,
        import_obj={},
        source="fresh",
    )
    s2 = Server(
        group_id=1,
        group_name="T",
        name="s2",
        engine="sing-box",
        server="10.0.0.1",
        server_port=443,
        import_obj={},
        source="fresh",
    )

    class FakeCtx:
        xr_exe = "fake_xr"
        sb_exe = "fake_sb"
        agy_bin = "fake_agy"
        use_tcp_prefilter = True
        tcp_timeout = 1.0
        tcp_concurrency = 10
        initial_circuit_breaker = None

    mock_tcp_results = {
        ("10.0.0.1", 443): (False, 0, "tcp: таймаут"),
    }

    printed_lines: list[str] = []
    with (
        patch("proxy_probe.cli.batch_probe_tcp", return_value=mock_tcp_results),
        patch("proxy_probe.cli.console.print", side_effect=lambda msg, **_kw: printed_lines.append(str(msg))),
    ):
        completed, _ = _execute_probe_pool(
            to_probe=[s1, s2],
            jobs=1,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=FakeCtx(),  # type: ignore[arg-type]
            print_timeout="5s",
        )

    assert completed == 2
    assert s1.result == RESULT_DEAD
    assert s2.result == RESULT_DEAD
    # Проверяем семантику: 2 сервера, 1 узел
    assert any("отсеяно 2 серверов (1 узлов)" in line for line in printed_lines)


def test_cli_parser_optimization_flags() -> None:
    parser = build_arg_parser()
    args = parser.parse_args(["--preflight-timeout", "2.0", "--no-rep-filter"])
    assert args.preflight_timeout == 2.0
    assert args.no_rep_filter is True


def test_execute_probe_pool_representative_filter_dead() -> None:
    s1 = Server(1, "g", "s1", "sing-box", "1.2.3.4", 443, {}, "fresh")
    s2 = Server(1, "g", "s2", "sing-box", "1.2.3.4", 443, {}, "fresh")
    s3 = Server(1, "g", "s3", "sing-box", "1.2.3.4", 443, {}, "fresh")

    class FakeCtx:
        xr_exe = "fake_xr"
        sb_exe = "fake_sb"
        agy_bin = "fake_agy"
        use_tcp_prefilter = False
        use_rep_filter = True
        initial_circuit_breaker = None

    mock_dead_result = {
        "result": RESULT_DEAD,
        "country": "",
        "ip_out": "",
        "latency_ms": 2500,
        "note": "preflight: туннель не пропускает трафик",
    }

    with patch("proxy_probe.cli._probe_worker", return_value=mock_dead_result) as mock_worker:
        completed, interrupted = _execute_probe_pool(
            to_probe=[s1, s2, s3],
            jobs=1,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=FakeCtx(),  # type: ignore[arg-type]
            print_timeout="5s",
        )

    assert interrupted is False
    assert completed == 3
    # Движок должен запуститься строго 1 раз (для представителя), а остальные 2 отсеяться автоматически
    assert mock_worker.call_count == 1
    assert s1.result == RESULT_DEAD
    assert s2.result == RESULT_DEAD
    assert s3.result == RESULT_DEAD
    assert "отсев по узлу" in s2.note
    assert "отсев по узлу" in s3.note


def test_execute_probe_pool_representative_filter_alive() -> None:
    s1 = Server(1, "g", "s1", "sing-box", "1.2.3.4", 443, {}, "fresh")
    s2 = Server(1, "g", "s2", "sing-box", "1.2.3.4", 443, {}, "fresh")

    class FakeCtx:
        xr_exe = "fake_xr"
        sb_exe = "fake_sb"
        agy_bin = "fake_agy"
        use_tcp_prefilter = False
        use_rep_filter = True
        initial_circuit_breaker = None

    mock_ok_result = {
        "result": RESULT_OK,
        "country": "US",
        "ip_out": "1.2.3.4",
        "latency_ms": 150,
        "note": "ok",
    }

    with patch("proxy_probe.cli._probe_worker", return_value=mock_ok_result) as mock_worker:
        completed, interrupted = _execute_probe_pool(
            to_probe=[s1, s2],
            jobs=1,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=FakeCtx(),  # type: ignore[arg-type]
            print_timeout="5s",
        )

    assert interrupted is False
    assert completed == 2
    # Для живого узла должны провериться оба профиля
    assert mock_worker.call_count == 2
    assert s1.result == RESULT_OK
    assert s2.result == RESULT_OK


def test_main_calls_load_dotenv() -> None:
    with patch("proxy_probe.cli.load_dotenv") as mock_load_dotenv, \
         patch("proxy_probe.cli.build_arg_parser") as mock_parser:
        mock_parser.return_value.parse_args.side_effect = SystemExit(0)
        try:
            from proxy_probe.cli import main
            main()
        except SystemExit:
            pass
        mock_load_dotenv.assert_called_once()


def test_cli_geo_precheck_and_web_flags() -> None:
    parser = build_arg_parser()
    # По умолчанию: precheck включен, timeout 2.5, web отключен
    args = parser.parse_args([])
    assert args.no_geo_precheck is False
    assert args.geo_precheck_timeout == 2.5
    assert args.check_web is False

    # С пользовательскими флагами
    custom_args = parser.parse_args(["--no-geo-precheck", "--geo-precheck-timeout", "4.0", "--check-web"])
    assert custom_args.no_geo_precheck is True
    assert custom_args.geo_precheck_timeout == 4.0
    assert custom_args.check_web is True


def test_setup_environment_geo_precheck_flags() -> None:
    from pathlib import Path

    from proxy_probe.cli import _setup_environment

    parser = build_arg_parser()
    args = parser.parse_args(["--geo-precheck-timeout", "3.0", "--check-web", "--skip-precheck", "--no-cache"])

    with patch("proxy_probe.cli._resolve_agy_bin", return_value="agy"), \
         patch("proxy_probe.cli.detect_throne_versions", return_value=("1.0", "1.0")), \
         patch("proxy_probe.cli.ensure_binaries", return_value=(Path("sb"), Path("xr"))):
        ctx = _setup_environment(args)

    assert ctx.use_geo_precheck is True
    assert ctx.geo_precheck_timeout == 3.0
    assert ctx.check_web is True


def test_cli_antidpi_flags() -> None:
    parser = build_arg_parser()
    # Defaults
    args = parser.parse_args([])
    assert args.antidpi is False
    assert args.antidpi_strategy is None
    assert args.antidpi_port == 10850

    # Custom
    custom_args = parser.parse_args(["--antidpi", "--antidpi-strategy", "7", "--antidpi-port", "10860"])
    assert custom_args.antidpi is True
    assert custom_args.antidpi_strategy == 7
    assert custom_args.antidpi_port == 10860


def test_setup_environment_antidpi_flags() -> None:
    from proxy_probe.cli import _setup_environment

    parser = build_arg_parser()
    args = parser.parse_args([
        "--antidpi",
        "--antidpi-strategy",
        "3",
        "--antidpi-port",
        "10852",
        "--skip-precheck",
        "--no-cache",
    ])

    with patch("proxy_probe.cli._resolve_agy_bin", return_value="agy"), \
         patch("proxy_probe.cli.detect_throne_versions", return_value=("1.0", "1.0")), \
         patch("proxy_probe.cli.ensure_binaries", return_value=(Path("sb"), Path("xr"))):
        ctx = _setup_environment(args)

    assert ctx.antidpi is True
    assert ctx.antidpi_strategy == 3
    assert ctx.antidpi_port == 10852


def test_execute_antidpi_stage_disabled() -> None:
    from proxy_probe.cli import RuntimeContext, _execute_antidpi_stage

    ctx = RuntimeContext(
        agy_bin="fake",
        agy_model=None,
        agy_concurrency=2,
        initial_circuit_breaker=None,
        cache=None,
        cache_path=Path("fake"),
        ttl_map={},
        report_path=Path("fake"),
        import_path=Path("fake"),
        ver_sb="1.0",
        ver_xr="1.0",
        sb_exe=Path("sb"),
        xr_exe=Path("xr"),
        antidpi=False,
    )
    s = Server(
        group_id=1,
        group_name="Test",
        name="s1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={},
        source="fresh",
        result=RESULT_DEAD,
    )
    rescued = _execute_antidpi_stage([s], [s], ctx, {}, "5s")
    assert rescued == 0
    assert s.result == RESULT_DEAD


def test_execute_antidpi_stage_rescues_dead() -> None:
    from proxy_probe.antidpi.models import StrategyProfile
    from proxy_probe.cli import RuntimeContext, _execute_antidpi_stage

    ctx = RuntimeContext(
        agy_bin="fake",
        agy_model=None,
        agy_concurrency=2,
        initial_circuit_breaker=None,
        cache=None,
        cache_path=Path("fake"),
        ttl_map={},
        report_path=Path("fake"),
        import_path=Path("fake"),
        ver_sb="1.0",
        ver_xr="1.0",
        sb_exe=Path("sb"),
        xr_exe=Path("xr"),
        antidpi=True,
        antidpi_strategy=1,
    )
    s = Server(
        group_id=1,
        group_name="Test",
        name="dead_srv",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"server": "1.2.3.4", "server_port": 443},
        source="fresh",
        result=RESULT_DEAD,
    )

    dummy_strat = StrategyProfile(
        number=1,
        family_number=1,
        family_name="Golden",
        variant=1,
        name="Fake Strategy",
        chain="fake",
        args=("--fake",),
        is_golden=True,
    )
    mock_res = {
        "result": RESULT_OK,
        "country": "Germany",
        "ip_out": "1.2.3.4",
        "country_code": "DE",
        "city": "Frankfurt",
        "org": "Hetzner",
        "latency_ms": 55,
    }

    with patch("proxy_probe.antidpi.engine.ensure_zapret_binaries", return_value=Path("bin/zapret")), \
         patch("proxy_probe.antidpi.catalogue.get_strategy_by_number", return_value=dummy_strat), \
         patch("proxy_probe.antidpi.relay.ZapretRelay") as mock_relay, \
         patch("proxy_probe.antidpi.engine.WinwsRunner") as mock_runner, \
         patch("proxy_probe.cli._probe_worker", return_value=mock_res):
        mock_relay.return_value.__enter__.return_value = None
        mock_runner.return_value.__enter__.return_value = None

        to_probe: list[Server] = []
        rescued = _execute_antidpi_stage([s], to_probe, ctx, {}, "5s")

    assert rescued == 1
    assert s.result == RESULT_OK
    assert s.antidpi_strategy == 1
    assert s.country_code == "DE"
    assert s in to_probe




