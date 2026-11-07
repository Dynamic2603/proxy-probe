from __future__ import annotations

import atexit
import contextlib
import functools
import hashlib
import ipaddress
import logging
import shutil
import socket
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
    """Возвращает каталог для бинарников Zapret2 (bin/zapret/ или PROXY_PROBE_ZAPRET_DIR)."""
    import os

    custom = os.environ.get("PROXY_PROBE_ZAPRET_DIR")
    if custom and Path(custom).is_dir():
        return Path(custom)
    return project_root() / "bin" / "zapret"


def resolve_winws_bin(zapret_dir: Path | None = None) -> Path:
    """Определяет исполняемый файл Zapret (предпочитая нативный winws2.exe для Zapret 2)."""
    zdir = zapret_dir or default_zapret_dir()
    for name in ("winws2.exe", "winws.exe"):
        candidate = zdir / name
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"winws2.exe или winws.exe не найден в {zdir}")


def ensure_zapret_binaries(
    zapret_dir: Path | None = None,
    url: str = ZAPRET_BUNDLE_URL,
    expected_sha256: str = ZAPRET_BUNDLE_SHA256,
) -> Path:
    """Скачивает и распаковывает официальный zapret-win-bundle от bol-van с проверкой SHA-256."""
    target_dir = zapret_dir or default_zapret_dir()
    winws2_exe = target_dir / "winws2.exe"
    winws_exe = target_dir / "winws.exe"
    cygwin_dll = target_dir / "cygwin1.dll"
    divert_dll = target_dir / "WinDivert.dll"
    divert_sys = target_dir / "WinDivert64.sys"

    has_winws = winws2_exe.is_file() or winws_exe.is_file()
    if has_winws and cygwin_dll.is_file() and divert_dll.is_file() and divert_sys.is_file():
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
            if member.is_dir():
                continue
            marker = "zapret-winws/"
            idx = filename.find(marker)
            if idx != -1:
                rel_path = filename[idx + len(marker) :]
                dest_path = target_dir / rel_path
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with z.open(member) as src, open(dest_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    with contextlib.suppress(OSError):
        zip_path.unlink()

    logger.info("Zapret2 успешно развернут в %s", target_dir)
    return target_dir


@functools.lru_cache(maxsize=2048)
def resolve_ip(target: str) -> str | None:
    """Нормализует целевой хост в IPv4 адрес для WinDivert (кэшировано в памяти)."""
    target = target.strip()
    if not target:
        return None
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None


def build_windivert_filter(target_ips: set[str] | list[str], max_ips: int = 150) -> str:
    """Формирует строгий WinDivert raw-фильтр только по целевым IP адресам (SSOT/Безопасность).

    Гарантирует 100% изоляцию: если список IP пуст, выбрасывает исключение во избежание
    случайного глобального перехвата системного трафика.
    Использует корректный синтаксис WinDivert (логическое 'or' вместо неподдерживаемого 'in').
    Ограничивает число IP (по умолчанию 150) для строгого соблюдения лимитов
    длины фильтра WinDivert (WINDIVERT_FILTER_MAX_LEN = 8192 байт) и командной строки Windows.
    """
    resolved: set[str] = set()
    for item in target_ips:
        ip = resolve_ip(str(item))
        if ip:
            resolved.add(ip)

    cleaned = sorted(resolved)
    if not cleaned:
        raise ValueError("Список целевых IP пуст. Глобальный перехват трафика запрещен!")

    if len(cleaned) > max_ips:
        logger.warning(
            "Список целевых IP (%d) ограничен первыми %d для соблюдения лимитов WinDivert (8KB).",
            len(cleaned),
            max_ips,
        )
        cleaned = cleaned[:max_ips]

    if len(cleaned) == 1:
        return f"ip.DstAddr == {cleaned[0]}"
    return "(" + " or ".join(f"ip.DstAddr == {ip}" for ip in cleaned) + ")"


class WinwsRunner:
    """Изолированный раннер Zapret2 winws2 с ограничением перехвата только по целевым IP."""

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
        self._log_file = None
        self._log_path = self.zapret_dir / "winws.log"

    def build_command_line(self) -> list[str]:
        """Строит аргументы вызова winws2.exe со строгим IP-фильтром."""
        winws_exe = resolve_winws_bin(self.zapret_dir)

        raw_filter = build_windivert_filter(self.target_ips)

        cmd = [
            str(winws_exe),
            "--wf-filter-lan=1",
            f"--wf-tcp-out={self.ports}",
            f"--wf-raw-filter={raw_filter}",
        ]

        # Подключение Lua библиотек zapret2 (строго с прямыми слэшами для Cygwin runtime)
        lua_dir = self.zapret_dir / "lua"
        lib_lua = lua_dir / "zapret-lib.lua"
        antidpi_lua = lua_dir / "zapret-antidpi.lua"
        if lib_lua.is_file():
            cmd.append(f"--lua-init=@{lib_lua.as_posix()}")
        if antidpi_lua.is_file():
            cmd.append(f"--lua-init=@{antidpi_lua.as_posix()}")

        cmd.append("--lua-init=fake_default_tls = tls_mod(fake_default_tls,'rnd,rndsni')")

        if self.strategy.init_script:
            cmd.append(f"--lua-init={self.strategy.init_script}")

        actual_guard = self.zapret_dir / "actual_tls_guard.lua"
        if actual_guard.is_file() and any("blob=reasm_data" in a for a in self.strategy.args):
            cmd.append(f"--lua-init=@{actual_guard.as_posix()}")

        # Добавляем аргументы выбранной стратегии
        cmd.extend(self.strategy.args)
        return cmd

    def start(self) -> None:
        """Запускает winws2.exe и проверяет, что драйвер WinDivert успешно поднялся."""
        if self.process is not None:
            return

        cmd = self.build_command_line()
        logger.debug("Запуск Zapret2 winws: %s", " ".join(cmd))

        self.zapret_dir.mkdir(parents=True, exist_ok=True)
        try:
            self._log_file = open(self._log_path, "w", encoding="utf-8", errors="replace")
        except OSError:
            self._log_file = None

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=self._log_file or subprocess.PIPE,
                stderr=subprocess.STDOUT if self._log_file else subprocess.PIPE,
                text=True,
                cwd=str(self.zapret_dir),
            )
        except OSError as exc:
            if getattr(exc, "winerror", None) == 740:
                raise PermissionError(
                    "Для работы Zapret2 (драйвер WinDivert) требуются права Администратора. "
                    "Пожалуйста, запустите терминал от имени Администратора (Run as Administrator)."
                ) from exc
            raise
        _ACTIVE_RUNNERS.add(self)

        # Даем процессу 350мс проверить инициализацию драйвера WinDivert и загрузку Lua
        time.sleep(0.35)
        if self.process.poll() is not None:
            if self._log_file and not self._log_file.closed:
                self._log_file.close()
            err_text = ""
            if self._log_path.is_file():
                err_text = self._log_path.read_text(encoding="utf-8", errors="replace").strip()
            _ACTIVE_RUNNERS.discard(self)
            rc = self.process.returncode
            self.process = None
            raise RuntimeError(f"Сбой старта {Path(cmd[0]).name} (код {rc}): {err_text}")

    def stop(self) -> None:
        """Останавливает winws2.exe, гарантируя закрытие дескриптора WinDivert."""
        _ACTIVE_RUNNERS.discard(self)
        if self._log_file and not self._log_file.closed:
            with contextlib.suppress(Exception):
                self._log_file.close()
        self._log_file = None

        if self.process is None:
            return

        p = self.process
        self.process = None

        if p.poll() is not None:
            if p.returncode != 0:
                err_text = ""
                if self._log_path.is_file():
                    err_text = self._log_path.read_text(encoding="utf-8", errors="replace").strip()
                logger.warning("winws завершился досрочно с кодом %s: %s", p.returncode, err_text)
            return

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
