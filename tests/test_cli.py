from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from conftest import make_runtime_context
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

    def mock_as_completed(futures):
        raise KeyboardInterrupt()

    with patch("proxy_probe.cli.concurrent.futures.as_completed", side_effect=mock_as_completed):
        completed, interrupted = _execute_probe_pool(
            to_probe=servers,
            jobs=2,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=make_runtime_context(use_tcp_prefilter=False),
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
            ctx=make_runtime_context(use_tcp_prefilter=False),
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
            ctx=make_runtime_context(use_tcp_prefilter=True),
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
            ctx=make_runtime_context(use_tcp_prefilter=True),
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
            ctx=make_runtime_context(use_tcp_prefilter=False),
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
            ctx=make_runtime_context(use_tcp_prefilter=True),
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
            ctx=make_runtime_context(use_tcp_prefilter=False, use_rep_filter=True),
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
            ctx=make_runtime_context(use_tcp_prefilter=False, use_rep_filter=True),
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
    # Defaults: Anti-DPI теперь включен по умолчанию
    args = parser.parse_args([])
    assert args.antidpi is True
    assert args.antidpi_strategy is None
    assert args.antidpi_port == 10850

    # Флаг отключения
    no_args = parser.parse_args(["--no-antidpi"])
    assert no_args.antidpi is False

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
    from proxy_probe.antidpi.stage2 import execute_antidpi_stage

    ctx = make_runtime_context(antidpi=False)
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
    rescued = execute_antidpi_stage([s], [s], ctx, {}, "5s")
    assert rescued == 0
    assert s.result == RESULT_DEAD


def test_execute_antidpi_stage_rescues_dead() -> None:
    from proxy_probe.antidpi.isp import IspIdentity
    from proxy_probe.antidpi.models import StrategyProfile
    from proxy_probe.antidpi.stage2 import execute_antidpi_stage

    ctx = make_runtime_context(antidpi=True, antidpi_strategy=1)
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
        family_name="fake",
        variant=1,
        name="Fake Strategy",
        chain="fake",
        args=("--fake",),
    )
    dummy_isp = IspIdentity(asn=12389, isp_name="TestISP", org_name="TestISP", ingress_ip="1.1.1.1")
    mock_res = {
        "result": RESULT_OK,
        "country": "Germany",
        "ip_out": "1.2.3.4",
        "country_code": "DE",
        "city": "Frankfurt",
        "org": "Hetzner",
        "latency_ms": 55,
    }

    with patch("proxy_probe.antidpi.runner.is_relay_running", return_value=False), \
         patch("proxy_probe.antidpi.isp.detect_current_isp", return_value=dummy_isp), \
         patch("proxy_probe.antidpi.engine.ensure_zapret_binaries", return_value=Path("bin/zapret")), \
         patch("proxy_probe.antidpi.catalogue.get_strategy_by_number", return_value=dummy_strat), \
         patch("proxy_probe.antidpi.relay.ZapretRelay") as mock_relay, \
         patch("proxy_probe.antidpi.engine.WinwsRunner") as mock_runner, \
         patch("proxy_probe.antidpi.elevation.is_admin", return_value=True), \
         patch("proxy_probe.antidpi.stage2._probe_worker", return_value=mock_res):
        mock_relay.return_value.__enter__.return_value = None
        mock_runner.return_value.__enter__.return_value = None

        to_probe: list[Server] = []
        rescued = execute_antidpi_stage([s], to_probe, ctx, {}, "5s")

    assert rescued == 1
    assert mock_relay.call_args.kwargs["port"] != ctx.antidpi_port
    assert s.result == RESULT_OK
    assert s.antidpi_strategy == 1
    assert s.country_code == "DE"
    assert s in to_probe


def test_execute_antidpi_stage_no_elevate() -> None:
    from proxy_probe.antidpi.stage2 import execute_antidpi_stage

    ctx = make_runtime_context(antidpi=True, no_elevate=True)
    s = Server(
        group_id=1,
        group_name="Test",
        name="s1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"server": "1.1.1.1", "server_port": 443},
        source="fresh",
        result=RESULT_DEAD,
    )
    with patch("proxy_probe.antidpi.elevation.is_admin", return_value=False):
        rescued = execute_antidpi_stage([s], [s], ctx, {}, "5s")
    assert rescued == 0
    assert s.result == RESULT_DEAD


def test_execute_antidpi_stage_uac_cancelled() -> None:
    from proxy_probe.antidpi.stage2 import execute_antidpi_stage

    ctx = make_runtime_context(antidpi=True, no_elevate=False)
    s = Server(
        group_id=1,
        group_name="Test",
        name="s1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"server": "1.1.1.1", "server_port": 443},
        source="fresh",
        result=RESULT_DEAD,
    )

    def mock_run_elevated(**_):
        raise PermissionError("UAC rejected")

    with patch("proxy_probe.antidpi.runner.is_relay_running", return_value=False), \
         patch("proxy_probe.antidpi.elevation.is_admin", return_value=False), \
         patch("proxy_probe.antidpi.elevation.run_elevated_and_wait", side_effect=mock_run_elevated):
        rescued = execute_antidpi_stage([s], [s], ctx, {}, "5s")

    assert rescued == 0
    assert s.result == RESULT_DEAD


def test_execute_antidpi_stage_delegation(tmp_path: Path) -> None:
    import json

    from proxy_probe.antidpi.stage2 import execute_antidpi_stage

    ctx = make_runtime_context(
        cache_path=tmp_path / "results.json",
        antidpi=True,
        no_elevate=False,
    )
    s = Server(
        group_id=1,
        group_name="Test",
        name="s1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"server": "1.1.1.1", "server_port": 443},
        source="fresh",
        result=RESULT_DEAD,
    )

    def fake_run_elevated(executable, params, cwd):
        for part in params.split():
            if "stage2_task_" in part and part.endswith(".json"):
                task_file = Path(part)
                if task_file.is_file():
                    data = json.loads(task_file.read_text(encoding="utf-8"))
                    res_file = Path(data["result_path"])
                    res_file.write_text(
                        json.dumps({
                            "rescued": [{
                                "config_identity": s.config_identity,
                                "cache_key": s.cache_key,
                                "result": RESULT_OK,
                                "country_code": "DE",
                                "antidpi_strategy": 15,
                                "state": "ACTIVE",
                                "note": "rescued",
                            }]
                        }),
                        encoding="utf-8",
                    )
        return 0

    to_probe: list[Server] = []
    with patch("proxy_probe.antidpi.runner.is_relay_running", return_value=False), \
         patch("proxy_probe.antidpi.elevation.is_admin", return_value=False), \
         patch("proxy_probe.antidpi.elevation.run_elevated_and_wait", side_effect=fake_run_elevated):
        rescued = execute_antidpi_stage([s], to_probe, ctx, {}, "5s")

    assert rescued == 1
    assert s.result == RESULT_OK
    assert s.country_code == "DE"
    assert s.antidpi_strategy == 15
    assert s in to_probe



def test_sync_and_save_cache_flushes_to_disk(tmp_path: Path) -> None:
    from proxy_probe.cache import ResultCache
    from proxy_probe.cli import _sync_and_save_cache

    cache_file = tmp_path / "results.json"
    cache = ResultCache(path=cache_file)
    s = Server(
        group_id=1,
        group_name="G",
        name="s1",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"server": "1.2.3.4", "server_port": 443},
        source="fresh",
        result=RESULT_OK,
        country_code="DE",
    )

    dummy_ctx = make_runtime_context(cache=cache, cache_path=cache_file)
    _sync_and_save_cache(dummy_ctx, [s], [s], label="Stage 1")

    assert cache_file.is_file()
    assert s.cache_key in cache.entries
    assert cache.entries[s.cache_key]["result"] == RESULT_OK


def test_cli_refresh_dead_flag() -> None:
    parser = build_arg_parser()
    args_default = parser.parse_args([])
    assert args_default.refresh_dead is False

    args_custom = parser.parse_args(["--refresh-dead"])
    assert args_custom.refresh_dead is True


def test_collect_and_select_servers_refresh_dead() -> None:
    from unittest.mock import MagicMock

    from proxy_probe.cli import _collect_and_select_servers
    from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK

    s_ok = Server(1, "g", "s_ok", "sing-box", "1.1.1.1", 443, {"server": "1.1.1.1", "server_port": 443}, "fresh")
    s_block = Server(1, "g", "s_block", "sing-box", "2.2.2.2", 443, {"server": "2.2.2.2", "server_port": 443}, "fresh")
    s_dead = Server(1, "g", "s_dead", "sing-box", "3.3.3.3", 443, {"server": "3.3.3.3", "server_port": 443}, "fresh")

    cache_entries = {
        s_ok.cache_key: {"result": RESULT_OK, "country_code": "DE", "score": 70, "state": "ACTIVE"},
        s_block.cache_key: {"result": RESULT_BLOCK, "score": 0, "state": "DEAD"},
        s_dead.cache_key: {"result": RESULT_DEAD, "score": 0, "state": "DEAD"},
    }

    mock_cache = MagicMock()
    mock_cache.get_valid_server.side_effect = lambda s: cache_entries.get(s.cache_key)

    with patch("proxy_probe.cli.gather_sources", return_value=([s_ok, s_block, s_dead], [])):
        # Case 1: default (без --refresh-dead) — все 3 берутся из кэша
        args_default = build_arg_parser().parse_args(["--group", "1"])
        res1 = _collect_and_select_servers(
            args=args_default, groups=[{"id": 1, "name": "g"}], cache=mock_cache, ttl_map={}
        )
        assert res1 is not None
        assert len(res1.to_probe) == 0
        assert res1.cached_counts.get(RESULT_OK) == 1
        assert res1.cached_counts.get(RESULT_BLOCK) == 1
        assert res1.cached_counts.get(RESULT_DEAD) == 1

        # Case 2: с --refresh-dead — DEAD сервер отправляется на перепроверку
        s_ok.result = ""
        s_block.result = ""
        s_dead.result = ""
        args_refresh = build_arg_parser().parse_args(["--group", "1", "--refresh-dead"])
        res2 = _collect_and_select_servers(
            args=args_refresh, groups=[{"id": 1, "name": "g"}], cache=mock_cache, ttl_map={}
        )
        assert res2 is not None
        assert len(res2.to_probe) == 1
        assert res2.to_probe[0].server == "3.3.3.3"
        assert res2.cached_counts.get(RESULT_OK) == 1
        assert res2.cached_counts.get(RESULT_BLOCK) == 1
        assert res2.cached_counts.get(RESULT_DEAD) is None


def test_cli_antidpi_limit_flag() -> None:
    parser = build_arg_parser()
    args_default = parser.parse_args([])
    assert args_default.antidpi_limit == 0

    args_custom = parser.parse_args(["--antidpi-limit", "300"])
    assert args_custom.antidpi_limit == 300


def test_setup_environment_antidpi_limit() -> None:
    from proxy_probe.cli import _setup_environment

    parser = build_arg_parser()
    args = parser.parse_args(["--antidpi-limit", "150", "--skip-precheck", "--no-cache"])

    with patch("proxy_probe.cli._resolve_agy_bin", return_value="agy"), \
         patch("proxy_probe.cli.detect_throne_versions", return_value=("1.0", "1.0")), \
         patch("proxy_probe.cli.ensure_binaries", return_value=(Path("sb"), Path("xr"))):
        ctx = _setup_environment(args)

    assert ctx.antidpi_limit == 150


def test_execute_antidpi_stage_honors_limit() -> None:
    from proxy_probe.antidpi.stage2 import execute_antidpi_stage

    ctx = make_runtime_context(antidpi=True, antidpi_limit=50)
    servers = [
        Server(
            group_id=1,
            group_name="Test",
            name=f"s_{i}",
            engine="sing-box",
            server=f"10.0.{i // 250}.{i % 250 + 1}",
            server_port=443,
            import_obj={"server": f"10.0.{i // 250}.{i % 250 + 1}", "server_port": 443},
            source="fresh",
            result=RESULT_DEAD,
        )
        for i in range(80)
    ]

    with patch("proxy_probe.antidpi.runner.is_relay_running", return_value=False), \
         patch("proxy_probe.antidpi.elevation.is_admin", return_value=True), \
         patch("proxy_probe.antidpi.stage2.execute_antidpi_stage_core", return_value=0) as mock_core:
        execute_antidpi_stage(servers, servers.copy(), ctx, {}, "5s")
        passed_candidates = mock_core.call_args[1]["dead_candidates"]
        assert len(passed_candidates) == 50

    ctx.antidpi_limit = 0
    with patch("proxy_probe.antidpi.runner.is_relay_running", return_value=False), \
         patch("proxy_probe.antidpi.elevation.is_admin", return_value=True), \
         patch("proxy_probe.antidpi.stage2.execute_antidpi_stage_core", return_value=0) as mock_core:
        execute_antidpi_stage(servers, servers.copy(), ctx, {}, "5s")
        passed_candidates = mock_core.call_args[1]["dead_candidates"]
        assert len(passed_candidates) == 80


def test_execute_antidpi_stage_multi_batch() -> None:
    from proxy_probe.antidpi.isp import IspIdentity
    from proxy_probe.antidpi.models import StrategyProfile
    from proxy_probe.antidpi.stage2 import execute_antidpi_stage

    ctx = make_runtime_context(antidpi=True, antidpi_strategy=1, antidpi_limit=0)
    servers = [
        Server(
            group_id=1,
            group_name="Test",
            name=f"s_{i}",
            engine="sing-box",
            server=f"10.1.{i // 250}.{i % 250 + 1}",
            server_port=443,
            import_obj={"server": f"10.1.{i // 250}.{i % 250 + 1}", "server_port": 443},
            source="fresh",
            result=RESULT_DEAD,
        )
        for i in range(350)
    ]

    dummy_strat = StrategyProfile(
        number=1,
        family_number=1,
        family_name="fake",
        variant=1,
        name="Fake Strategy",
        chain="fake",
        args=("--fake",),
    )
    mock_res = {
        "result": RESULT_OK,
        "country": "Germany",
        "ip_out": "1.2.3.4",
        "country_code": "DE",
        "city": "Frankfurt",
        "org": "Hetzner",
        "latency_ms": 50,
    }

    runner_calls = []

    class MockRunner:
        def __init__(self, **kwargs):
            runner_calls.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            pass

    dummy_isp = IspIdentity(asn=12389, isp_name="TestISP", org_name="TestISP", ingress_ip="1.1.1.1")
    with patch("proxy_probe.antidpi.runner.is_relay_running", return_value=False), \
         patch("proxy_probe.antidpi.isp.detect_current_isp", return_value=dummy_isp), \
         patch("proxy_probe.antidpi.engine.ensure_zapret_binaries", return_value=Path("bin/zapret")), \
         patch("proxy_probe.antidpi.catalogue.get_strategy_by_number", return_value=dummy_strat), \
         patch("proxy_probe.antidpi.relay.ZapretRelay") as mock_relay, \
         patch("proxy_probe.antidpi.engine.WinwsRunner", side_effect=MockRunner), \
         patch("proxy_probe.antidpi.elevation.is_admin", return_value=True), \
         patch("proxy_probe.antidpi.stage2._probe_worker", return_value=mock_res):
        mock_relay.return_value.__enter__.return_value = None

        to_probe: list[Server] = []
        rescued = execute_antidpi_stage(servers, to_probe, ctx, {}, "5s")

    assert rescued == 350
    # ZapretRelay должен быть создан ровно 1 раз
    mock_relay.assert_called_once()
    # WinwsRunner должен быть вызван 3 раза: для пачек 150, 150, 50
    assert len(runner_calls) == 3
    assert len(runner_calls[0]["target_ips"]) == 150
    assert len(runner_calls[1]["target_ips"]) == 150
    assert len(runner_calls[2]["target_ips"]) == 50
    # Все серверы должны стать RESULT_OK
    assert all(s.result == RESULT_OK for s in servers)
    assert len(to_probe) == 350


def test_cli_clear_dead_flag(tmp_path: Path) -> None:
    from proxy_probe.cache import ResultCache
    from proxy_probe.cli import main

    cache_file = tmp_path / "test_results.json"
    cache = ResultCache(path=cache_file)
    cache.entries = {
        "ok": {"result": RESULT_OK},
        "dead": {"result": RESULT_DEAD},
    }
    cache.save()

    test_args = ["pxp", "--cache", str(cache_file), "--clear-dead"]
    with patch("sys.argv", test_args):
        main()

    reloaded = ResultCache(path=cache_file)
    assert len(reloaded.entries) == 1
    assert "ok" in reloaded.entries
    assert "dead" not in reloaded.entries


def test_execute_probe_pool_rep_filter_bypassed_when_tcp_prefilter_enabled() -> None:
    s1 = Server(1, "g", "s1", "sing-box", "1.2.3.4", 443, {"type": "vless", "uuid": "u1"}, "fresh")
    s2 = Server(1, "g", "s2", "sing-box", "1.2.3.4", 443, {"type": "vless", "uuid": "u2"}, "fresh")

    mock_tcp_results = {("1.2.3.4", 443): (True, 40, "")}
    worker_results = [
        {"result": RESULT_DEAD, "country": "", "ip_out": "", "latency_ms": 0, "note": "preflight drop"},
        {"result": RESULT_OK, "country": "DE", "ip_out": "1.2.3.4", "latency_ms": 95, "note": "ok"},
    ]

    with (
        patch("proxy_probe.cli.batch_probe_tcp", return_value=mock_tcp_results),
        patch("proxy_probe.cli._probe_worker", side_effect=worker_results) as mock_worker,
    ):
        completed, interrupted = _execute_probe_pool(
            to_probe=[s1, s2],
            jobs=1,
            timeouts={"start": 1.0, "probe": 1.0, "geo": 1.0},
            ctx=make_runtime_context(use_tcp_prefilter=True, use_rep_filter=True),
            print_timeout="5s",
        )

    assert interrupted is False
    assert completed == 2
    assert mock_worker.call_count == 2
    assert s1.result == RESULT_DEAD
    assert s2.result == RESULT_OK


def test_sync_and_save_cache_mass_outage_guard(tmp_path: Path) -> None:
    from proxy_probe.cache import ResultCache
    from proxy_probe.cli import _sync_and_save_cache
    from proxy_probe.models import STATE_ACTIVE

    cache_file = tmp_path / "results.json"
    cache = ResultCache(path=cache_file)

    servers = [
        Server(
            group_id=1,
            group_name="G",
            name=f"s{i}",
            engine="sing-box",
            server=f"10.0.0.{i}",
            server_port=443,
            import_obj={"server": f"10.0.0.{i}", "server_port": 443},
            source="fresh",
            result=RESULT_OK,
            latency_ms=80,
        )
        for i in range(1, 7)
    ]
    for s in servers:
        cache.update_from_server(s)
    cache.save()

    # Имитируем локальный обрыв сети: все 6 серверов вернули DEAD
    for s in servers:
        s.result = RESULT_DEAD
        s.note = "tcp: таймаут"

    ctx = make_runtime_context(cache=cache, cache_path=cache_file)
    outage = _sync_and_save_cache(ctx, servers, servers)
    assert outage is True

    # Ранее активные серверы в кэше не должны были получить consecutive_fails = 1
    for s in servers:
        rec = cache.entries[s.cache_key]
        assert rec["state"] == STATE_ACTIVE
        assert rec["consecutive_fails"] == 0
        assert rec["score"] == 70


def test_run_serve_fails_fast_on_isp_detection_error(monkeypatch) -> None:
    from proxy_probe.antidpi.isp import IspDetectionError
    from proxy_probe.cli import main

    monkeypatch.setattr("proxy_probe.antidpi.runner.is_relay_running", lambda **_kw: False)
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_admin", lambda: True)

    def _raise_isp_err(**_kw: object) -> None:
        raise IspDetectionError("network unreachable")

    monkeypatch.setattr("proxy_probe.antidpi.runner.detect_current_isp", _raise_isp_err)
    rc = main(["--serve", "--no-elevate"])
    assert rc == 1


def test_main_interactive_tui_loop(monkeypatch) -> None:
    from proxy_probe.cli import main

    actions = iter(["update_catalogue", "exit"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("proxy_probe.cli.select_main_action_interactive", lambda: next(actions))

    called: list[str] = []

    def _mock_update() -> int:
        called.append("update")
        return 0

    monkeypatch.setattr("proxy_probe.cli.run_catalogue_update", _mock_update)

    rc = main([])
    assert rc == 0
    assert called == ["update"]


def test_chunk_candidates_by_limits_ports_and_ips() -> None:
    from proxy_probe.antidpi.stage2 import chunk_candidates_by_limits

    # 25 серверов, у каждого свой уникальный порт (443..467)
    servers = [
        Server(1, "G", f"s{i}", "sing-box", f"10.0.0.{i}", 443 + i, {}, "fresh", result=RESULT_DEAD)
        for i in range(25)
    ]
    batches = chunk_candidates_by_limits(servers, max_ips=150, max_ports=16)
    assert len(batches) == 2
    assert len(batches[0]) == 16
    assert len(batches[1]) == 9
    for b in batches:
        ports_in_batch = {s.server_port for s in b}
        assert len(ports_in_batch) <= 16







