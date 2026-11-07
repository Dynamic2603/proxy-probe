from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from proxy_probe.antidpi.engine import (
    WinwsRunner,
    build_windivert_filter,
    ensure_zapret_binaries,
)
from proxy_probe.antidpi.models import StrategyProfile


def make_test_strategy(num: int = 1) -> StrategyProfile:
    return StrategyProfile(
        number=num,
        family_number=1,
        family_name="fake + multisplit",
        variant=1,
        name="Test Strategy",
        chain="fake + multisplit",
        args=(
            "--payload=tls_client_hello",
            "--lua-desync=fake:blob=fake_default_tls:tcp_ts=-1000",
            "--lua-desync=multisplit:pos=1,midsld",
        ),
    )


def test_build_windivert_filter_single_ip() -> None:
    res = build_windivert_filter(["1.2.3.4"])
    assert res == "ip.DstAddr == 1.2.3.4"


def test_build_windivert_filter_multiple_ips() -> None:
    res = build_windivert_filter(["2.2.2.2", "1.1.1.1", "1.1.1.1"])
    assert res == "(ip.DstAddr == 1.1.1.1 or ip.DstAddr == 2.2.2.2)"


def test_build_windivert_filter_empty_raises() -> None:
    with pytest.raises(ValueError, match="Глобальный перехват трафика запрещен"):
        build_windivert_filter([])

    with pytest.raises(ValueError, match="Глобальный перехват трафика запрещен"):
        build_windivert_filter(["", "  "])


def test_build_windivert_filter_caps_max_ips() -> None:
    # 200 уникальных IP адресов
    many_ips = [f"10.0.{i // 250}.{i % 250}" for i in range(200)]
    flt = build_windivert_filter(many_ips, max_ips=50)
    # Должно быть ровно 50 ip.DstAddr
    assert flt.count("ip.DstAddr ==") == 50


def test_build_command_line(tmp_path: Path) -> None:
    strat = make_test_strategy(1)
    winws_exe = tmp_path / "winws.exe"
    winws_exe.write_text("dummy", encoding="utf-8")

    lua_dir = tmp_path / "lua"
    lua_dir.mkdir(parents=True, exist_ok=True)
    (lua_dir / "zapret-lib.lua").write_text("--", encoding="utf-8")
    (lua_dir / "zapret-antidpi.lua").write_text("--", encoding="utf-8")

    runner = WinwsRunner(
        strategy=strat,
        target_ips=["1.1.1.1", "2.2.2.2"],
        zapret_dir=tmp_path,
        ports="443,8443",
    )
    cmd = runner.build_command_line()

    assert cmd[0] == str(winws_exe)
    assert "--wf-filter-lan=1" in cmd
    assert "--wf-tcp-out=443,8443" in cmd
    assert '--wf-raw-filter=(ip.DstAddr == 1.1.1.1 or ip.DstAddr == 2.2.2.2)' in cmd
    assert any("zapret-lib.lua" in arg for arg in cmd)
    assert any("zapret-antidpi.lua" in arg for arg in cmd)
    assert any("fake_default_tls" in arg for arg in cmd)
    assert "--payload=tls_client_hello" in cmd
    assert "--lua-desync=multisplit:pos=1,midsld" in cmd


def test_resolve_winws_bin_prefers_winws2(tmp_path: Path) -> None:
    (tmp_path / "winws.exe").write_text("v1", encoding="utf-8")
    (tmp_path / "winws2.exe").write_text("v2", encoding="utf-8")
    from proxy_probe.antidpi.engine import resolve_winws_bin

    chosen = resolve_winws_bin(tmp_path)
    assert chosen.name == "winws2.exe"


def test_winws_runner_lifecycle(tmp_path: Path) -> None:
    strat = make_test_strategy(1)
    winws_exe = tmp_path / "winws.exe"
    winws_exe.write_text("dummy", encoding="utf-8")

    runner = WinwsRunner(
        strategy=strat,
        target_ips=["1.1.1.1"],
        zapret_dir=tmp_path,
    )

    mock_proc = MagicMock()
    mock_proc.poll.return_value = None

    with patch("subprocess.Popen", return_value=mock_proc):
        with runner:
            assert runner.process is mock_proc

        mock_proc.terminate.assert_called_once()
        assert runner.process is None


def test_ensure_zapret_binaries_already_exists(tmp_path: Path) -> None:
    (tmp_path / "winws.exe").write_text("exe", encoding="utf-8")
    (tmp_path / "cygwin1.dll").write_text("dll", encoding="utf-8")
    (tmp_path / "WinDivert.dll").write_text("dll", encoding="utf-8")
    (tmp_path / "WinDivert64.sys").write_text("sys", encoding="utf-8")

    res = ensure_zapret_binaries(zapret_dir=tmp_path)
    assert res == tmp_path
