from __future__ import annotations

import atexit
import contextlib
import json
import logging
import os
import socket
import subprocess
import time
from pathlib import Path

from ..engines import app_bin_dir

logger = logging.getLogger(__name__)

DEFAULT_RELAY_HOST = "127.0.0.1"
DEFAULT_RELAY_PORT = 10850

_ACTIVE_RELAYS: set[ZapretRelay] = set()


def _cleanup_active_relays() -> None:
    for relay in list(_ACTIVE_RELAYS):
        with contextlib.suppress(Exception):
            relay.stop()


atexit.register(_cleanup_active_relays)


def is_port_in_use(port: int, host: str = DEFAULT_RELAY_HOST) -> bool:
    """Проверяет, занят ли указанный локальный порт."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            return True
        except (ConnectionRefusedError, TimeoutError, OSError):
            return False


def wait_for_port(port: int, host: str = DEFAULT_RELAY_HOST, timeout: float = 3.0) -> bool:
    """Ожидает доступности порта до истечения таймаута."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if is_port_in_use(port, host):
            return True
        time.sleep(0.05)
    return False


def build_relay_config(port: int, host: str = DEFAULT_RELAY_HOST) -> dict:
    """Строит in-memory конфигурацию легковесного SOCKS5-релея sing-box (SSOT)."""
    return {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": host,
                "listen_port": port,
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct",
            }
        ],
    }


class ZapretRelay:
    """Локальный изолированный SOCKS5-релей на базе sing-box для реанимируемых серверов."""

    def __init__(
        self,
        port: int = DEFAULT_RELAY_PORT,
        host: str = DEFAULT_RELAY_HOST,
        engine_bin: str | Path | None = None,
    ):
        self.port = port
        self.host = host
        self._engine_bin = engine_bin
        self.process: subprocess.Popen[bytes] | None = None

    @property
    def engine_path(self) -> str:
        if self._engine_bin:
            return str(self._engine_bin)
        return str(app_bin_dir() / "sing-box.exe")

    def start(self) -> None:
        """Запускает in-memory процесс sing-box SOCKS5 релея."""
        if self.process is not None:
            return

        if is_port_in_use(self.port, self.host):
            raise OSError(f"Порт {self.host}:{self.port} уже занят другим процессом")

        bin_path = self.engine_path
        if not Path(bin_path).is_file():
            raise FileNotFoundError(f"Движок sing-box не найден: {bin_path}")

        cfg = build_relay_config(self.port, self.host)
        cfg_bytes = json.dumps(cfg, ensure_ascii=False).encode("utf-8")

        cmd = [bin_path, "run", "-c", "stdin"]
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        }

        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=clean_env,
        )
        _ACTIVE_RELAYS.add(self)

        if self.process.stdin is not None:
            self.process.stdin.write(cfg_bytes)
            self.process.stdin.close()

        if not wait_for_port(self.port, self.host, timeout=3.0):
            out = ""
            if self.process.stdout:
                out = self.process.stdout.read().decode("utf-8", errors="replace")
            self.stop()
            raise RuntimeError(f"Релей sing-box не смог открыться на {self.host}:{self.port}. Вывод: {out.strip()}")

        logger.info("Локальный Zapret-релей успешно запущен на %s:%d", self.host, self.port)

    def stop(self) -> None:
        """Останавливает процесс sing-box релея."""
        _ACTIVE_RELAYS.discard(self)
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
        logger.info("Локальный Zapret-релей остановлен")

    def __enter__(self) -> ZapretRelay:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
