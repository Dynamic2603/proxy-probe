from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

from proxy_probe.antidpi.relay import (
    ZapretRelay,
    build_relay_config,
    is_port_in_use,
    wait_for_port,
)


def test_build_relay_config() -> None:
    cfg = build_relay_config(10850, "127.0.0.1")
    assert cfg["inbounds"][0]["type"] == "socks"
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"
    assert cfg["inbounds"][0]["listen_port"] == 10850
    assert cfg["outbounds"][0]["type"] == "direct"


def test_is_port_in_use_free_port() -> None:
    # Порт 59998 маловероятно занят
    assert is_port_in_use(59998) is False


def test_wait_for_port_timeout() -> None:
    # Ожидание недоступного порта должно вернуть False по таймауту
    assert wait_for_port(59997, timeout=0.1) is False


def test_relay_mock_lifecycle() -> None:
    relay = ZapretRelay(port=10850)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None

    with patch("proxy_probe.antidpi.relay.is_port_in_use", side_effect=[False, True]), \
         patch("proxy_probe.antidpi.relay.wait_for_port", return_value=True), \
         patch("subprocess.Popen", return_value=mock_proc):
        with relay:
            assert relay.process is mock_proc

        mock_proc.terminate.assert_called_once()
        assert relay.process is None


def test_relay_real_start_and_stop() -> None:
    # Реальный запуск sing-box на тестовом порту 10999
    test_port = 10999
    relay = ZapretRelay(port=test_port)

    assert is_port_in_use(test_port) is False

    with relay:
        assert is_port_in_use(test_port) is True
        # Проверяем подключение
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", test_port))
            # SOCKS5 handshake greeting: VER=5, NMETHODS=1, METHOD=0 (NO_AUTH)
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            assert resp == b"\x05\x00"

    # После выхода из контекста порт должен быть освобожден
    assert is_port_in_use(test_port) is False
