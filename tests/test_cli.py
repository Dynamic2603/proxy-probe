from __future__ import annotations

from unittest.mock import patch

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
