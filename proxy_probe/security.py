"""Классификация безопасности прокси-серверов.

Реализует правила оценки безопасности Throne (outbound::EffectiveSecurity,
utils.cpp, custom.cpp, xrayStreamSetting.cpp):
- Определение приватных / локальных адресов (RFC1918, loopback, link-local, .local, etc.)
- Проверка Reality, валидного TLS, сертификатного пиннинга
- Выявление allowInsecure / insecure: true (без пиннинга)
- Выявление устаревших потоковых шифров в Shadowsocks (rc4-md5, aes-*-cfb, chacha20-ietf)
- Выявление открытого трафика (Raw / plaintext) и VMess без TLS
"""

from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import Server

__all__ = [
    "STREAM_CIPHERS",
    "SecurityInfo",
    "SecurityLevel",
    "evaluate_security",
    "is_insecure_server",
    "is_private_host",
]


class SecurityLevel(enum.IntEnum):
    UNKNOWN = 0
    NONE = 1
    WEAK = 2
    SECURE = 3


@dataclass(frozen=True)
class SecurityInfo:
    label: str
    transport: str = ""
    level: SecurityLevel = SecurityLevel.UNKNOWN

    @property
    def is_dangerous(self) -> bool:
        return self.level in (SecurityLevel.NONE, SecurityLevel.WEAK)

    @property
    def is_insecure(self) -> bool:
        return self.is_dangerous


# Приватные подсети из Throne (include/configs/common/utils.cpp -> IsPrivateHost)
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/3"),
    ipaddress.ip_network("::/127"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)

_PRIVATE_SUFFIXES = (
    "lan",
    "localdomain",
    "example",
    "invalid",
    "localhost",
    "test",
    "local",
    "home.arpa",
    "internal",
)

_RE_DOTLESS = re.compile(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

# Устаревшие потоковые шифры Shadowsocks (Pre-AEAD stream ciphers из shadowsocks.cpp)
STREAM_CIPHERS = frozenset({
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
})


def is_private_host(host: str) -> bool:
    """Проверяет, является ли хост приватным/локальным согласно Throne IsPrivateHost."""
    bare = host.strip().lower().strip("[]").rstrip(".")
    if not bare:
        return False

    try:
        ip = ipaddress.ip_address(bare)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        pass

    for suf in _PRIVATE_SUFFIXES:
        if bare == suf or bare.endswith("." + suf):
            return True

    return bool(_RE_DOTLESS.match(bare))


def _extract_transport_name(transport_obj: Any) -> str:
    if not isinstance(transport_obj, dict):
        return ""
    t_type = str(transport_obj.get("type", "")).lower()
    if t_type in ("", "tcp", "raw"):
        return ""
    if t_type == "ws":
        return "WebSocket"
    if t_type == "grpc":
        return "gRPC"
    if t_type in ("http", "httpupgrade", "xhttp", "quic"):
        return t_type.upper()
    return t_type.upper()


def evaluate_security(server_or_obj: Server | dict[str, Any], engine: str = "sing-box") -> SecurityInfo:
    """Определяет уровень безопасности сервера согласно правилам Throne."""
    if hasattr(server_or_obj, "import_obj"):
        server_obj = server_or_obj.import_obj
        eng = getattr(server_or_obj, "engine", engine)
        host = getattr(server_or_obj, "server", "")
    else:
        server_obj = server_or_obj
        eng = engine
        host = str(server_obj.get("server", "")) if isinstance(server_obj, dict) else ""

    if not isinstance(server_obj, dict):
        return SecurityInfo(label="Unknown", level=SecurityLevel.UNKNOWN)

    transport = ""
    if "transport" in server_obj:
        transport = _extract_transport_name(server_obj["transport"])

    # --- Анализ Xray конфигурации ---
    is_xray = (
        eng == "xray"
        or "streamSettings" in server_obj
        or server_obj.get("protocol") == "vless"
    )

    if is_xray:
        ss = server_obj.get("streamSettings")
        if not isinstance(ss, dict):
            ss = {}
        net = str(ss.get("network", "")).lower()
        if net and net not in ("tcp", "raw"):
            transport = "WebSocket" if net == "ws" else net.upper()

        sec = str(ss.get("security", "")).lower()
        settings = server_obj.get("settings")
        if not isinstance(settings, dict):
            settings = {}
        host = host or str(settings.get("address", ""))

        if sec == "reality":
            info = SecurityInfo(label="Reality", transport=transport, level=SecurityLevel.SECURE)
        elif sec in ("tls", "xtls"):
            tls_settings = ss.get("tlsSettings")
            if not isinstance(tls_settings, dict):
                tls_settings = {}
            allow_insecure = bool(tls_settings.get("allowInsecure"))
            pinned_sha = tls_settings.get("pinnedPeerCertSha256")
            pinned_name = tls_settings.get("verifyPeerCertByName")
            pinned = bool(
                (isinstance(pinned_sha, str) and pinned_sha.strip())
                or (isinstance(pinned_name, str) and pinned_name.strip())
            )
            if allow_insecure and not pinned:
                info = SecurityInfo(label="Insecure TLS", transport=transport, level=SecurityLevel.WEAK)
            else:
                info = SecurityInfo(label="TLS", transport=transport, level=SecurityLevel.SECURE)
        else:
            protocol = str(server_obj.get("protocol", "")).lower()
            if protocol == "shadowsocks":
                method = str(settings.get("method", "")).lower()
                if not method or method in ("none", "plain"):
                    info = SecurityInfo(label="Raw", transport=transport, level=SecurityLevel.NONE)
                elif method in STREAM_CIPHERS:
                    info = SecurityInfo(label="Weak Cipher", transport=transport, level=SecurityLevel.WEAK)
                else:
                    info = SecurityInfo(label="Encrypted", transport=transport, level=SecurityLevel.SECURE)
            elif protocol == "wireguard":
                info = SecurityInfo(label="Encrypted", transport=transport, level=SecurityLevel.SECURE)
            elif protocol == "vless":
                enc = str(settings.get("encryption", "")).lower()
                if enc and enc != "none":
                    info = SecurityInfo(label="Encrypted", transport=transport, level=SecurityLevel.SECURE)
                else:
                    info = SecurityInfo(label="Raw", transport=transport, level=SecurityLevel.NONE)
            elif protocol == "vmess":
                info = SecurityInfo(label="Insecure", transport=transport, level=SecurityLevel.WEAK)
            else:
                info = SecurityInfo(label="Raw", transport=transport, level=SecurityLevel.NONE)

    # --- Анализ sing-box конфигурации ---
    else:
        ptype = str(server_obj.get("type", "")).lower()

        if ptype == "shadowsocks":
            method = str(server_obj.get("method", "")).lower()
            if not method or method in ("none", "plain"):
                info = SecurityInfo(label="Raw", transport=transport, level=SecurityLevel.NONE)
            elif method in STREAM_CIPHERS:
                info = SecurityInfo(label="Weak Cipher", transport=transport, level=SecurityLevel.WEAK)
            else:
                info = SecurityInfo(label="Encrypted", transport=transport, level=SecurityLevel.SECURE)

        elif ptype == "vmess":
            tls = server_obj.get("tls")
            if isinstance(tls, dict) and tls.get("enabled"):
                if tls.get("insecure"):
                    info = SecurityInfo(label="Insecure TLS", transport=transport, level=SecurityLevel.WEAK)
                else:
                    info = SecurityInfo(label="TLS", transport=transport, level=SecurityLevel.SECURE)
            else:
                sec = str(server_obj.get("security", "auto")).lower()
                if sec in ("none", "zero"):
                    info = SecurityInfo(label="Raw", transport=transport, level=SecurityLevel.NONE)
                else:
                    info = SecurityInfo(label="Insecure", transport=transport, level=SecurityLevel.WEAK)

        elif ptype == "wireguard":
            info = SecurityInfo(label="Encrypted", transport=transport, level=SecurityLevel.SECURE)

        elif ptype == "ssh":
            if not server_obj.get("host_key"):
                info = SecurityInfo(label="Unverified Host Key", transport=transport, level=SecurityLevel.WEAK)
            else:
                info = SecurityInfo(label="Encrypted", transport=transport, level=SecurityLevel.SECURE)

        else:
            # vless, trojan, hysteria, hysteria2, tuic, juicity, naive, direct, etc.
            tls = server_obj.get("tls")
            if not isinstance(tls, dict):
                tls = {}
            reality = tls.get("reality")
            if not isinstance(reality, dict):
                reality = {}

            if reality.get("enabled"):
                info = SecurityInfo(label="Reality", transport=transport, level=SecurityLevel.SECURE)
            elif tls.get("certificate_sha256") or tls.get("certificate_public_key_sha256"):
                info = SecurityInfo(label="TLS", transport=transport, level=SecurityLevel.SECURE)
            elif tls.get("insecure"):
                info = SecurityInfo(label="Insecure TLS", transport=transport, level=SecurityLevel.WEAK)
            elif tls.get("enabled") or ptype in ("hysteria", "hysteria2", "tuic", "juicity"):
                info = SecurityInfo(label="TLS", transport=transport, level=SecurityLevel.SECURE)
            else:
                info = SecurityInfo(label="Raw", transport=transport, level=SecurityLevel.NONE)

    # Приватный хост освобождает от классификации опасности (WithPrivateServer)
    if info.is_dangerous and is_private_host(host):
        return SecurityInfo(
            label="Private",
            transport=info.transport,
            level=SecurityLevel.SECURE,
        )

    return info


def is_insecure_server(server_or_obj: Server | dict[str, Any], engine: str = "sing-box") -> bool:
    """Возвращает True, если сервер небезопасен (isInsecure в Throne)."""
    return evaluate_security(server_or_obj, engine).is_insecure
