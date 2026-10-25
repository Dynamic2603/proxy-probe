from __future__ import annotations

import dataclasses
import hashlib
import re
from typing import Any

RESULT_OK = "AGY-OK"
RESULT_BLOCK = "AGY-BLOCK"
RESULT_DEAD = "DEAD"
RESULT_UNKNOWN = "UNKNOWN"

DEFAULT_TTLS = {RESULT_OK: 3 * 86400, RESULT_BLOCK: 7 * 86400, RESULT_DEAD: 86400}
RESULT_PRIORITIES = {RESULT_BLOCK: 3, RESULT_OK: 2, RESULT_DEAD: 1, RESULT_UNKNOWN: 0}

BLOCK_MARKERS = ["User location is not supported"]
DEAD_PATTERNS = [
    "connection refused",
    "i/o timeout",
    "dial tcp",
    "proxy connect",
    "EOF",
    "tls: handshake",
    "tls: bad certificate",
    "tls: failed to verify",
    "tls: first record does not look like a TLS handshake",
    "context deadline exceeded",
    "cannot connect",
    "no route",
    "unreachable",
    "forcibly closed",
    "connection reset",
]
UNKNOWN_PATTERNS = [
    "401",
    "403",
    "429",
    "RESOURCE_EXHAUSTED",
    "quota",
    "rate limit",
    "permission denied",
    "invalid_grant",
    "invalid_token",
    "unauthorized",
    "consent",
    "INVALID_ARGUMENT",
    "FAILED_PRECONDITION",
    "UNAUTHENTICATED",
    "token expired",
]

QUOTA_EXHAUSTED_MARKERS: list[str] = [
    "individual quota reached",
]

_RE_RESETS_IN = re.compile(r"Resets in\s+([0-9a-zA-Z]+)", re.IGNORECASE)


@dataclasses.dataclass(frozen=True)
class QuotaInfo:
    is_exhausted: bool
    reset_after: str = ""

    @property
    def clean_note(self) -> str:
        if not self.is_exhausted:
            return ""
        if self.reset_after:
            return f"лимит квоты agy (сброс через {self.reset_after})"
        return "лимит квоты agy"


def parse_quota_info(text: str) -> QuotaInfo:
    if not text:
        return QuotaInfo(is_exhausted=False)
    lower = text.lower()
    is_exhausted = any(m.lower() in lower for m in QUOTA_EXHAUSTED_MARKERS)
    reset_after = ""
    if m := _RE_RESETS_IN.search(text):
        reset_after = m.group(1).strip()
    return QuotaInfo(is_exhausted=is_exhausted, reset_after=reset_after)


@dataclasses.dataclass
class Server:
    group_id: int
    group_name: str
    name: str
    engine: str  # "sing-box" | "xray"
    server: str
    server_port: int
    import_obj: dict[str, Any]
    source: str  # "fresh" | "db"
    index: int = 0
    result: str = ""
    country: str = ""
    ip_out: str = ""
    latency_ms: int = 0
    note: str = ""

    @property
    def host_port(self) -> str:
        return f"{self.server}:{self.server_port}"

    @property
    def is_tcp_protocol(self) -> bool:
        """Определяет, использует ли узел транспорт TCP (False для чистого UDP: Hysteria 2, WireGuard, TUIC)."""
        if not self.import_obj or not isinstance(self.import_obj, dict):
            return True
        proto = str(self.import_obj.get("type") or self.import_obj.get("protocol") or "").strip().lower()
        return proto not in ("hysteria2", "tuic", "wireguard")

    @property
    def config_identity(self) -> str:
        """Канонический идентификатор конфигурации узла (SSOT).

        Нормализует диалекты Xray и sing-box в единый канонический ключ:
        protocol : host : port : cred : sni : reality_pk : fingerprint : flow : alpn : path
        """
        if not self.import_obj or not isinstance(self.import_obj, dict):
            return f"unknown:{self.server}:{self.server_port}"

        obj = self.import_obj
        proto = str(obj.get("type") or obj.get("protocol") or "").strip().lower()

        raw_settings = obj.get("settings")
        s: dict[str, Any] = raw_settings if isinstance(raw_settings, dict) else {}
        user_obj: dict[str, Any] = {}
        vnext = s.get("vnext")
        if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
            users = vnext[0].get("users")
            if isinstance(users, list) and users and isinstance(users[0], dict):
                user_obj = users[0]
        elif (
            (servers_list := s.get("servers"))
            and isinstance(servers_list, list)
            and servers_list
            and isinstance(servers_list[0], dict)
        ):
            user_obj = servers_list[0]

        uuid = obj.get("uuid") or s.get("id") or user_obj.get("id") or user_obj.get("uuid")

        cred_parts: list[str] = []
        if uuid:
            cred_parts.append(f"uuid={uuid}")
        if pwd := (obj.get("password") or s.get("password") or user_obj.get("password")):
            cred_parts.append(f"pwd={pwd}")
        if method := (obj.get("method") or s.get("method") or user_obj.get("method")):
            cred_parts.append(f"method={method}")
        cred = ";".join(sorted(cred_parts))

        raw_flow = str(obj.get("flow") or s.get("flow") or user_obj.get("flow") or "").strip()
        flow = "xtls-rprx-vision" if "vision" in raw_flow.lower() else raw_flow

        sni = ""
        fp = ""
        reality_pk = ""
        alpn_str = ""

        tls = obj.get("tls")
        if isinstance(tls, dict):
            if sn := tls.get("server_name"):
                sni = str(sn).strip()
            utls = tls.get("utls")
            if isinstance(utls, dict) and (f := utls.get("fingerprint")):
                fp = str(f).strip().lower()
            reality = tls.get("reality")
            if isinstance(reality, dict) and (pk := reality.get("public_key")):
                reality_pk = str(pk).strip()
            if "alpn" in tls:
                raw_alpn = tls.get("alpn")
                if isinstance(raw_alpn, list):
                    alpn_str = ",".join(sorted(str(x) for x in raw_alpn))
                elif raw_alpn:
                    alpn_str = str(raw_alpn).strip()

        ss = obj.get("streamSettings")
        if isinstance(ss, dict):
            for sk in ("tlsSettings", "realitySettings"):
                sub = ss.get(sk)
                if isinstance(sub, dict):
                    if not sni and (sn := sub.get("serverName")):
                        sni = str(sn).strip()
                    if not fp and (f := sub.get("fingerprint")):
                        fp = str(f).strip().lower()
                    if not reality_pk and (pk := (sub.get("publicKey") or sub.get("password"))):
                        reality_pk = str(pk).strip()
                    if not alpn_str and "alpn" in sub:
                        raw_alpn = sub.get("alpn")
                        if isinstance(raw_alpn, list):
                            alpn_str = ",".join(sorted(str(x) for x in raw_alpn))
                        elif raw_alpn:
                            alpn_str = str(raw_alpn).strip()

        path = ""
        tr = obj.get("transport")
        if isinstance(tr, dict) and (p := tr.get("path")):
            path = str(p).strip()
        elif isinstance(ss, dict):
            for t_key in ("wsSettings", "xhttpSettings", "httpSettings", "grpcSettings"):
                sub = ss.get(t_key)
                if isinstance(sub, dict):
                    p = sub.get("path") or sub.get("serviceName")
                    if p and not path:
                        path = str(p).strip()

        return f"{proto}:{self.server}:{self.server_port}:{cred}:{sni}:{reality_pk}:{fp}:{flow}:{alpn_str}:{path}"

    @property
    def cache_key(self) -> str:
        h = hashlib.sha256(self.config_identity.encode("utf-8")).hexdigest()[:8]
        return f"{self.server}:{self.server_port}:{self.engine}:{h}"
