from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from proxy_probe.antidpi.runner import (
    RelayState,
    clear_relay_state,
    is_relay_running,
    load_relay_state,
    print_relay_status,
    run_relay_service,
    save_relay_state,
    stop_relay_service,
    suspend_background_relay,
)
from proxy_probe.cli import main


def test_relay_state_roundtrip(tmp_path: Path) -> None:
    state_file = tmp_path / "relay_state.json"
    state = RelayState(
        pid=1234,
        singbox_pid=2345,
        winws_pid=3456,
        port=10850,
        host="127.0.0.1",
        strategy_number=10,
        strategy_name="Test Strat",
        isp="TestISP (AS123)",
        target_ips_count=42,
        started_at="2026-11-08T12:00:00",
    )
    save_relay_state(state, path=state_file)
    assert state_file.is_file()

    loaded = load_relay_state(path=state_file)
    assert loaded == state

    clear_relay_state(path=state_file)
    assert not state_file.exists()


def test_is_relay_running_cleans_stale_file_when_port_closed(tmp_path: Path) -> None:
    state_file = tmp_path / "relay_state.json"
    state = RelayState(
        pid=111,
        singbox_pid=222,
        winws_pid=333,
        port=10850,
        host="127.0.0.1",
        strategy_number=1,
        strategy_name="S1",
        isp="ISP",
        target_ips_count=5,
        started_at="2026-11-08T12:00:00",
    )
    save_relay_state(state, path=state_file)

    with patch("proxy_probe.antidpi.runner.is_port_in_use", return_value=False):
        assert is_relay_running(port=10850, state_path=state_file) is False
        assert not state_file.exists()


def test_is_relay_running_detects_dead_winws_pid(tmp_path: Path) -> None:
    state_file = tmp_path / "relay_state.json"
    state = RelayState(
        pid=111,
        singbox_pid=222,
        winws_pid=333,
        port=10850,
        host="127.0.0.1",
        strategy_number=1,
        strategy_name="S1",
        isp="ISP",
        target_ips_count=5,
        started_at="2026-11-08T12:00:00",
    )
    save_relay_state(state, path=state_file)

    with (
        patch("proxy_probe.antidpi.runner.is_port_in_use", return_value=True),
        patch("proxy_probe.antidpi.runner.is_process_alive", return_value=False),
    ):
        assert is_relay_running(port=10850, state_path=state_file) is False


def test_stop_relay_service_noop_when_not_running(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("proxy_probe.antidpi.runner.load_relay_state", lambda: None)
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_port_in_use", lambda *_a, **_kw: False)

    rc = main(["--stop-relay"])
    assert rc == 0


def test_stop_relay_service_elevates_when_not_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("proxy_probe.antidpi.runner.load_relay_state", lambda: None)
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_port_in_use", lambda *_a, **_kw: True)
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_admin", lambda: False)

    mock_elev = MagicMock(return_value=0)
    monkeypatch.setattr("proxy_probe.antidpi.runner.run_elevated_and_wait", mock_elev)

    rc = main(["--stop-relay", "--antidpi-port", "10855"])
    assert rc == 0
    assert mock_elev.called
    params = mock_elev.call_args.kwargs.get("params") or mock_elev.call_args.args[1]
    assert "--stop-relay" in params
    assert "10855" in params


def test_stop_relay_service_kills_pids_when_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_state = RelayState(
        pid=1001,
        singbox_pid=1002,
        winws_pid=1003,
        port=10850,
        host="127.0.0.1",
        strategy_number=10,
        strategy_name="S10",
        isp="ISP",
        target_ips_count=10,
        started_at="2026-11-08T12:00:00",
    )
    monkeypatch.setattr("proxy_probe.antidpi.runner.load_relay_state", lambda: fake_state)
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_port_in_use", lambda *_a, **_kw: False)
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_admin", lambda: True)

    killed: list[int | None] = []
    monkeypatch.setattr("proxy_probe.antidpi.runner._kill_pid_tree", lambda p: killed.append(p))
    monkeypatch.setattr("proxy_probe.antidpi.runner._stop_own_windivert_service", lambda: None)
    monkeypatch.setattr("proxy_probe.antidpi.runner.clear_relay_state", lambda: None)

    rc = stop_relay_service(argparse.Namespace(antidpi_port=10850, no_elevate=False, quiet=True))
    assert rc == 0
    assert killed == [1003, 1002, 1001]


def test_run_relay_service_already_running_returns_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_relay_running", lambda **_kw: True)
    monkeypatch.setattr("proxy_probe.antidpi.runner.load_relay_state", lambda: None)

    rc = run_relay_service(argparse.Namespace(antidpi_port=10850, detach=False, no_elevate=True))
    assert rc == 0


def test_status_relay_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_relay_running", lambda **_kw: False)
    monkeypatch.setattr("proxy_probe.antidpi.runner.load_relay_state", lambda: None)

    rc = main(["--status-relay"])
    assert rc == 0
    assert print_relay_status(argparse.Namespace(antidpi_port=10850)) == 0


def test_suspend_background_relay_pauses_and_restarts(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_relay_running", lambda **_kw: True)
    monkeypatch.setattr("proxy_probe.antidpi.runner.load_relay_state", lambda: None)

    def _mock_stop(_a: object) -> int:
        events.append("stop")
        return 0

    def _mock_start(_a: object) -> int:
        events.append("start")
        return 0

    monkeypatch.setattr("proxy_probe.antidpi.runner.stop_relay_service", _mock_stop)
    monkeypatch.setattr("proxy_probe.antidpi.runner.run_relay_service", _mock_start)

    with suspend_background_relay(relay_port=10850) as was_running:
        assert was_running is True
        events.append("work")

    assert events == ["stop", "work", "start"]


def test_suspend_background_relay_detects_custom_port_from_state(monkeypatch: pytest.MonkeyPatch) -> None:
    custom_state = RelayState(
        pid=1001,
        singbox_pid=1002,
        winws_pid=1003,
        port=10855,
        host="127.0.0.1",
        strategy_number=11,
        strategy_name="S11",
        isp="ISP",
        target_ips_count=5,
        started_at="2026-11-08T12:00:00",
    )
    monkeypatch.setattr("proxy_probe.antidpi.runner.load_relay_state", lambda: custom_state)
    monkeypatch.setattr("proxy_probe.antidpi.runner.is_relay_running", lambda port=10850, **_kw: port == 10855)

    seen_ports: list[tuple[str, int]] = []

    def _mock_stop(args: argparse.Namespace) -> int:
        seen_ports.append(("stop", args.antidpi_port))
        return 0

    def _mock_start(args: argparse.Namespace) -> int:
        seen_ports.append(("start", args.antidpi_port))
        return 0

    monkeypatch.setattr("proxy_probe.antidpi.runner.stop_relay_service", _mock_stop)
    monkeypatch.setattr("proxy_probe.antidpi.runner.run_relay_service", _mock_start)

    with suspend_background_relay(relay_port=10850) as was_running:
        assert was_running is True

    assert seen_ports == [("stop", 10855), ("start", 10855)]
