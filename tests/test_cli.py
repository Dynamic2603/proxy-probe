from __future__ import annotations

from unittest.mock import patch

from proxy_probe.cli import _execute_probe_pool
from proxy_probe.models import Server


def test_execute_probe_pool_interrupted() -> None:
    # Setup mock servers
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

    # Simulate KeyboardInterrupt on as_completed
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
