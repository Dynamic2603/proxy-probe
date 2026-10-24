from __future__ import annotations

import pytest

from proxy_probe.cli import build_arg_parser
from proxy_probe.models import Server
from proxy_probe.orchestrator import filter_insecure_servers, gather_sources
from proxy_probe.security import (
    STREAM_CIPHERS,
    SecurityLevel,
    evaluate_security,
    is_insecure_server,
    is_private_host,
)


def test_is_private_host() -> None:
    # IPv4 частные диапазоны
    assert is_private_host("127.0.0.1")
    assert is_private_host("10.0.0.1")
    assert is_private_host("192.168.1.1")
    assert is_private_host("172.16.0.1")
    assert is_private_host("172.31.255.255")
    assert is_private_host("100.64.0.1")
    assert is_private_host("169.254.1.1")

    # IPv6 частные диапазоны
    assert is_private_host("::1")
    assert is_private_host("fc00::1")
    assert is_private_host("fe80::1")
    assert is_private_host("::ffff:192.168.1.1")

    # Локальные доменные суффиксы
    assert is_private_host("router.lan")
    assert is_private_host("myhost.local")
    assert is_private_host("home.internal")
    assert is_private_host("localhost")

    # Dotless имена
    assert is_private_host("myrouter")
    assert is_private_host("nas")

    # Публичные хосты
    assert not is_private_host("8.8.8.8")
    assert not is_private_host("1.1.1.1")
    assert not is_private_host("google.com")
    assert not is_private_host("amp-api-edge.apps.apple.com")


def test_singbox_vless_reality_is_secure() -> None:
    # Reality всегда безопасен, даже если по ошибке выставлен insecure: True
    obj = {
        "type": "vless",
        "server": "1.2.3.4",
        "server_port": 443,
        "uuid": "abc",
        "tls": {
            "enabled": True,
            "insecure": True,
            "reality": {"enabled": True, "public_key": "xyz"},
        },
    }
    info = evaluate_security(obj, engine="sing-box")
    assert info.level == SecurityLevel.SECURE
    assert info.label == "Reality"
    assert not is_insecure_server(obj, "sing-box")


def test_singbox_vless_tls_insecure() -> None:
    # Обычный TLS с insecure: True (без пиннинга) считается небезопасным
    obj = {
        "type": "vless",
        "server": "1.2.3.4",
        "server_port": 443,
        "uuid": "abc",
        "tls": {
            "enabled": True,
            "insecure": True,
            "server_name": "example.com",
        },
    }
    info = evaluate_security(obj, engine="sing-box")
    assert info.level == SecurityLevel.WEAK
    assert info.label == "Insecure TLS"
    assert is_insecure_server(obj, "sing-box")


def test_singbox_vless_tls_pinned_is_secure() -> None:
    # TLS с insecure: True, но с certificate_sha256 пиннингом — безопасен
    obj = {
        "type": "vless",
        "server": "1.2.3.4",
        "server_port": 443,
        "uuid": "abc",
        "tls": {
            "enabled": True,
            "insecure": True,
            "certificate_sha256": "abcdef123456",
        },
    }
    info = evaluate_security(obj, engine="sing-box")
    assert info.level == SecurityLevel.SECURE
    assert info.label == "TLS"
    assert not is_insecure_server(obj, "sing-box")


def test_singbox_vless_raw_is_insecure() -> None:
    # VLESS без TLS передаёт открытый трафик (Raw)
    obj = {
        "type": "vless",
        "server": "1.2.3.4",
        "server_port": 80,
        "uuid": "abc",
    }
    info = evaluate_security(obj, engine="sing-box")
    assert info.level == SecurityLevel.NONE
    assert info.label == "Raw"
    assert is_insecure_server(obj, "sing-box")


def test_xray_vless_reality_and_allow_insecure() -> None:
    # Xray Reality -> Secure
    xray_reality = {
        "protocol": "vless",
        "settings": {"address": "1.2.3.4", "port": 443},
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {"serverName": "example.com"},
        },
    }
    assert evaluate_security(xray_reality, "xray").level == SecurityLevel.SECURE
    assert not is_insecure_server(xray_reality, "xray")

    # Xray TLS allowInsecure -> Weak
    xray_insecure = {
        "protocol": "vless",
        "settings": {"address": "1.2.3.4", "port": 443},
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"serverName": "example.com", "allowInsecure": True},
        },
    }
    assert evaluate_security(xray_insecure, "xray").level == SecurityLevel.WEAK
    assert is_insecure_server(xray_insecure, "xray")

    # Xray TLS allowInsecure с pinnedPeerCertSha256 -> Secure
    xray_pinned = {
        "protocol": "vless",
        "settings": {"address": "1.2.3.4", "port": 443},
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": "example.com",
                "allowInsecure": True,
                "pinnedPeerCertSha256": "aa:bb:cc",
            },
        },
    }
    assert evaluate_security(xray_pinned, "xray").level == SecurityLevel.SECURE
    assert not is_insecure_server(xray_pinned, "xray")


def test_shadowsocks_ciphers() -> None:
    # AEAD шифры -> Secure
    for m in ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm"):
        obj = {"type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388, "method": m}
        info = evaluate_security(obj, "sing-box")
        assert info.level == SecurityLevel.SECURE, f"Expected {m} to be Secure"
        assert not is_insecure_server(obj, "sing-box")

    # Устаревшие потоковые шифры -> Weak (Insecure)
    for m in STREAM_CIPHERS:
        obj = {"type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388, "method": m}
        info = evaluate_security(obj, "sing-box")
        assert info.level == SecurityLevel.WEAK, f"Expected {m} to be Weak"
        assert is_insecure_server(obj, "sing-box")

    # None / plain шифры -> None (Raw)
    for m in ("none", "plain", ""):
        obj = {"type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388, "method": m}
        info = evaluate_security(obj, "sing-box")
        assert info.level == SecurityLevel.NONE, f"Expected {m} to be None"
        assert is_insecure_server(obj, "sing-box")


def test_vmess_security() -> None:
    # VMess без TLS -> Weak (Insecure в Throne)
    vmess_plain = {"type": "vmess", "server": "1.2.3.4", "server_port": 80, "uuid": "abc"}
    assert evaluate_security(vmess_plain, "sing-box").level == SecurityLevel.WEAK
    assert is_insecure_server(vmess_plain, "sing-box")

    # VMess с TLS -> Secure
    vmess_tls = {
        "type": "vmess",
        "server": "1.2.3.4",
        "server_port": 443,
        "uuid": "abc",
        "tls": {"enabled": True, "server_name": "example.com"},
    }
    assert evaluate_security(vmess_tls, "sing-box").level == SecurityLevel.SECURE
    assert not is_insecure_server(vmess_tls, "sing-box")


def test_private_host_exemption() -> None:
    # Небезопасный узел на локальный IP освобождается от небезопасности (WithPrivateServer)
    obj = {
        "type": "vless",
        "server": "192.168.1.100",
        "server_port": 80,
        "uuid": "abc",
    }
    info = evaluate_security(obj, "sing-box")
    assert info.level == SecurityLevel.SECURE
    assert info.label == "Private"
    assert not is_insecure_server(obj, "sing-box")


def test_filter_insecure_servers() -> None:
    s_safe = Server(
        group_id=1,
        group_name="G1",
        name="safe",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"type": "vless", "server": "1.2.3.4", "server_port": 443, "tls": {"enabled": True}},
        source="fresh",
    )
    s_insecure = Server(
        group_id=1,
        group_name="G1",
        name="insecure",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={
            "type": "vless",
            "server": "1.2.3.4",
            "server_port": 443,
            "tls": {"enabled": True, "insecure": True},
        },
        source="fresh",
    )

    safe, insecure = filter_insecure_servers([s_safe, s_insecure])
    assert len(safe) == 1
    assert safe[0].name == "safe"
    assert len(insecure) == 1
    assert insecure[0].name == "insecure"


def test_gather_sources_with_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("proxy_probe.orchestrator.read_profiles_for_group", lambda gid, gname="": [])
    link_safe = "vless://00000000-0000-0000-0000-000000000000@1.1.1.1:443?security=tls#Safe1"
    link_insecure = "vless://00000000-0000-0000-0000-000000000000@1.1.1.1:443?security=none#Insecure1"
    sub_payload = f"{link_safe}\n{link_insecure}".encode()
    prefetched = {"http://example.com/sub": sub_payload}

    # 1. Группа без remove_insecure, filter_insecure=None -> оба сервера загружаются
    groups_no_filter = [{"id": 1, "name": "G1", "url": "http://example.com/sub", "remove_insecure": False}]
    servers, warnings = gather_sources(groups_no_filter, selected={1}, no_fetch=False, prefetched=prefetched)
    assert len(servers) == 2
    assert len(warnings) == 0

    # 2. Группа с remove_insecure=True -> небезопасный отфильтровывается
    groups_with_filter = [{"id": 2, "name": "G2", "url": "http://example.com/sub", "remove_insecure": True}]
    servers, warnings = gather_sources(groups_with_filter, selected={2}, no_fetch=False, prefetched=prefetched)
    assert len(servers) == 1
    assert servers[0].name == "Safe1"
    assert any("Отфильтровано 1 небезопасных" in w for w in warnings)

    # 3. Принудительный filter_insecure=True
    servers, warnings = gather_sources(
        groups_no_filter, selected={1}, no_fetch=False, prefetched=prefetched, filter_insecure=True
    )
    assert len(servers) == 1
    assert servers[0].name == "Safe1"

    # 4. Принудительный filter_insecure=False (allow-insecure)
    servers, warnings = gather_sources(
        groups_with_filter, selected={2}, no_fetch=False, prefetched=prefetched, filter_insecure=False
    )
    assert len(servers) == 2


def test_cli_flags_insecure() -> None:
    parser = build_arg_parser()
    args_default = parser.parse_args([])
    assert args_default.filter_insecure is None
    assert args_default.allow_insecure is False

    args_filter = parser.parse_args(["--filter-insecure"])
    assert args_filter.filter_insecure is True

    args_allow = parser.parse_args(["--allow-insecure"])
    assert args_allow.allow_insecure is True
