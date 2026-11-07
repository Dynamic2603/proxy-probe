from __future__ import annotations

import atexit
import contextlib
import hashlib
import logging
import shutil
import subprocess
import time
import urllib.request
import zipfile
from pathlib import Path

from ..engines import project_root
from .models import StrategyProfile

logger = logging.getLogger(__name__)

ZAPRET_BUNDLE_URL = "https://codeload.github.com/bol-van/zapret-win-bundle/zip/6eb463a6758fb48cd101bc55dfd057e6e9d98af1"
ZAPRET_BUNDLE_SHA256 = "5f828239310fed0da587bc09eaa22742615b2a85cf41f55ff28128e22231c6de"

# Глобальный реестр запущенных раннеров для гарантированной выгрузки WinDivert при atexit
_ACTIVE_RUNNERS: set[WinwsRunner] = set()


def _cleanup_active_runners() -> None:
    for runner in list(_ACTIVE_RUNNERS):
        with contextlib.suppress(Exception):
            runner.stop()


atexit.register(_cleanup_active_runners)


def default_zapret_dir() -> Path:
    """Возвращает каталог для бинарников Zapret2 (bin/zapret/)."""
    return project_root() / "bin" / "zapret"


def ensure_zapret_binaries(
    zapret_dir: Path | None = None,
    url: str = ZAPRET_BUNDLE_URL,
    expected_sha256: str = ZAPRET_BUNDLE_SHA256,
) -> Path:
    """Скачивает и распаковывает официальный zapret-win-bundle от bol-van с проверкой SHA-256."""
    target_dir = zapret_dir or default_zapret_dir()
    winws_exe = target_dir / "winws.exe"
    divert_dll = target_dir / "WinDivert.dll"
    divert_sys = target_dir / "WinDivert64.sys"

    if winws_exe.is_file() and divert_dll.is_file() and divert_sys.is_file():
        return target_dir

    target_dir.mkdir(parents=True, exist_ok=True)
    zip_path = target_dir / "bundle.zip"

    logger.info("Скачивание zapret-win-bundle: %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": "proxy-probe/antidpi-engine"})
    with urllib.request.urlopen(req, timeout=30.0) as resp:
        data = resp.read()

    actual_sha = hashlib.sha256(data).hexdigest()
    if expected_sha256 and actual_sha.lower() != expected_sha256.lower():
        raise ValueError(
            f"Несовпадение контрольной суммы zapret-win-bundle: получено {actual_sha}, ожидалось {expected_sha256}"
        )

    zip_path.write_bytes(data)

    with zipfile.ZipFile(zip_path, "r") as z:
        for member in z.infolist():
            filename = member.filename
            # Ищем файлы в zapret-winws/
            if "zapret-winws/winws.exe" in filename:
                with z.open(member) as src, open(winws_exe, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            elif "zapret-winws/WinDivert.dll" in filename:
                with z.open(member) as src, open(divert_dll, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            elif "zapret-winws/WinDivert64.sys" in filename:
                with z.open(member) as src, open(divert_sys, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            elif "zapret-winws/lua/" in filename and not member.is_dir():
                rel_name = Path(filename).name
                lua_dir = target_dir / "lua"
                lua_dir.mkdir(parents=True, exist_ok=True)
                with z.open(member) as src, open(lua_dir / rel_name, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    with contextlib.suppress(OSError):
        zip_path.unlink()

    logger.info("Zapret2 успешно развернут в %s", target_dir)
    return target_dir


def build_windivert_filter(target_ips: set[str] | list[str]) -> str:
    """Формирует строгий WinDivert raw-фильтр только по целевым IP адресам (SSOT/Безопасность).

    Гарантирует 100% изоляцию: если список IP пуст, выбрасывает исключение во избежание
    случайного глобального перехвата системного трафика.
    """
    cleaned = sorted({str(ip).strip() for ip in target_ips if str(ip).strip()})
    if not cleaned:
        raise ValueError("Список целевых IP пуст. Глобальный перехват трафика запрещен!")

    if len(cleaned) == 1:
        return f"ip.DstAddr == {cleaned[0]}"
    return f"ip.DstAddr in {{ {', '.join(cleaned)} }}"


class WinwsRunner:
    """Изолированный раннер Zapret2 winws с ограничением перехвата только по целевым IP."""

    def __init__(
        self,
        strategy: StrategyProfile,
        target_ips: set[str] | list[str],
        zapret_dir: Path | None = None,
        ports: str = "443",
    ):
        self.strategy = strategy
        self.target_ips = set(target_ips)
        self.zapret_dir = zapret_dir or default_zapret_dir()
        self.ports = ports
        self.process: subprocess.Popen | None = None

    def build_command_line(self) -> list[str]:
        """Строит аргументы вызова winws.exe со строгим IP-фильтром."""
        winws_exe = self.zapret_dir / "winws.exe"
        if not winws_exe.is_file():
            raise FileNotFoundError(f"winws.exe не найден в {self.zapret_dir}")

        raw_filter = build_windivert_filter(self.target_ips)

        cmd = [
            str(winws_exe),
            "--wf-filter-lan=1",
            f"--wf-tcp-out={self.ports}",
            f"--wf-raw-filter={raw_filter}",
            "--bind-fix4",
        ]

        # Подключение Lua библиотек zapret
        lua_dir = self.zapret_dir / "lua"
        lib_lua = lua_dir / "zapret-lib.lua"
        antidpi_lua = lua_dir / "zapret-antidpi.lua"
        if lib_lua.is_file():
            cmd.append(f"--lua-init=@{lib_lua}")
        if antidpi_lua.is_file():
            cmd.append(f"--lua-init=@{antidpi_lua}")

        actual_guard = self.zapret_dir / "actual_tls_guard.lua"
        if actual_guard.is_file() and any("blob=reasm_data" in a for a in self.strategy.args):
            cmd.append(f"--lua-init=@{actual_guard}")

        # Добавляем аргументы выбранной стратегии
        cmd.extend(self.strategy.args)
        return cmd

    def start(self) -> None:
        """Запускает winws.exe и проверяет, что драйвер WinDivert успешно поднялся."""
        if self.process is not None:
            return

        cmd = self.build_command_line()
        logger.debug("Запуск Zapret2 winws: %s", " ".join(cmd))

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(self.zapret_dir),
        )
        _ACTIVE_RUNNERS.add(self)

        # Даем процессу 150мс проверить инициализацию драйвера WinDivert
        time.sleep(0.15)
        if self.process.poll() is not None:
            out, err = self.process.communicate()
            _ACTIVE_RUNNERS.discard(self)
            self.process = None
            raise RuntimeError(f"Сбой старта winws (exit {self.process}): {err.strip() or out.strip()}")

    def stop(self) -> None:
        """Останавливает winws.exe, гарантируя закрытие дескриптора WinDivert."""
        _ACTIVE_RUNNERS.discard(self)
        if self.process is None:
            return

        p = self.process
        self.process = None

        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=1.0)

    def __enter__(self) -> WinwsRunner:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
