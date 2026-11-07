from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from proxy_probe.antidpi.__main__ import main
from proxy_probe.antidpi.elevation import TeeOutput, is_admin, run_elevated_and_wait


def test_is_admin_returns_bool() -> None:
    res = is_admin()
    assert isinstance(res, bool)


def test_tee_output(tmp_path: Path) -> None:
    log_file = tmp_path / "test.log"
    with TeeOutput(log_file):
        print("Hello from TeeOutput")
        print("Second line")

    assert log_file.is_file()
    content = log_file.read_text(encoding="utf-8")
    assert "Hello from TeeOutput" in content
    assert "Second line" in content


def test_run_elevated_user_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    # Мокаем ShellExecuteExW так, чтобы возвращал 0 и GetLastError() = 1223
    monkeypatch.setattr(ctypes.windll.shell32, "ShellExecuteExW", lambda _: 0)
    monkeypatch.setattr(ctypes, "GetLastError", lambda: 1223)

    with pytest.raises(PermissionError, match="UAC"):
        run_elevated_and_wait("python.exe", "test")


def test_cmd_benchmark_elevates_when_not_admin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("proxy_probe.antidpi.__main__.is_admin", lambda: False)
    mock_run = MagicMock(return_value=0)
    monkeypatch.setattr("proxy_probe.antidpi.__main__.run_elevated_and_wait", mock_run)

    # Запускаем main(['benchmark', '--limit', '5'])
    rc = main(["benchmark", "--limit", "5"])
    assert rc == 0
    assert mock_run.called
    _args, kwargs = mock_run.call_args
    params = kwargs.get("params") or _args[1]
    assert "-m proxy_probe.antidpi benchmark --limit 5" in params
    assert "--log-output" in params


def test_cmd_benchmark_elevates_cancelled_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("proxy_probe.antidpi.__main__.is_admin", lambda: False)

    def mock_run_fail(**_):
        raise PermissionError("Запрос прав Администратора (UAC) был отклонён пользователем.")

    monkeypatch.setattr("proxy_probe.antidpi.__main__.run_elevated_and_wait", mock_run_fail)
    rc = main(["benchmark"])
    assert rc == 1223


def test_cmd_serve_elevates_when_not_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("proxy_probe.antidpi.__main__.is_admin", lambda: False)
    mock_run = MagicMock(return_value=0)
    monkeypatch.setattr("proxy_probe.antidpi.__main__.run_elevated_and_wait", mock_run)

    rc = main(["serve", "--port", "10850"])
    assert rc == 0
    assert mock_run.called
    _args, kwargs = mock_run.call_args
    params = kwargs.get("params") or _args[1]
    assert "-m proxy_probe.antidpi serve --port 10850" in params
