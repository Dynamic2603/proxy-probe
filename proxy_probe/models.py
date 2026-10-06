from __future__ import annotations

import dataclasses
from typing import Any

RESULT_OK = "AGY-OK"
RESULT_BLOCK = "AGY-BLOCK"
RESULT_DEAD = "DEAD"
RESULT_UNKNOWN = "UNKNOWN"

DEFAULT_TTLS = {RESULT_OK: 3 * 86400, RESULT_BLOCK: 7 * 86400, RESULT_DEAD: 86400}
RESULT_PRIORITIES = {RESULT_BLOCK: 3, RESULT_OK: 2, RESULT_DEAD: 1, RESULT_UNKNOWN: 0}

BLOCK_MARKERS = ["User location is not supported"]
DEAD_PATTERNS = [
    "connection refused", "i/o timeout", "dial tcp", "proxy connect", "EOF",
    "tls: handshake", "tls: bad certificate", "tls: failed to verify",
    "tls: first record does not look like a TLS handshake",
    "context deadline exceeded", "cannot connect", "no route", "unreachable",
    "forcibly closed", "connection reset",
]
UNKNOWN_PATTERNS = [
    "401", "403", "429", "RESOURCE_EXHAUSTED", "quota", "rate limit", "permission denied",
    "invalid_grant", "invalid_token", "unauthorized", "consent", "INVALID_ARGUMENT",
    "FAILED_PRECONDITION", "UNAUTHENTICATED", "token expired",
]


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
    def cache_key(self) -> str:
        if self.import_obj and isinstance(self.import_obj, dict):
            ident: list[str] = []
            for k in ("uuid", "password", "method", "flow"):
                if val := self.import_obj.get(k):
                    ident.append(f"{k}:{val}")
            s = self.import_obj.get("settings")
            if isinstance(s, dict):
                for k in ("id", "password"):
                    if val := s.get(k):
                        ident.append(f"{k}:{val}")
            tls = self.import_obj.get("tls")
            if isinstance(tls, dict) and (sn := tls.get("server_name")):
                ident.append(f"sni:{sn}")
            ss = self.import_obj.get("streamSettings")
            if isinstance(ss, dict):
                for sk in ("tlsSettings", "realitySettings"):
                    sub = ss.get(sk)
                    if isinstance(sub, dict) and (sn := sub.get("serverName")):
                        ident.append(f"sni:{sn}")
            tr = self.import_obj.get("transport")
            if isinstance(tr, dict) and (p := tr.get("path")):
                ident.append(f"path:{p}")
            if ident:
                import hashlib

                h = hashlib.sha256(";".join(ident).encode("utf-8")).hexdigest()[:8]
                return f"{self.server}:{self.server_port}:{self.engine}:{h}"
        return f"{self.server}:{self.server_port}:{self.engine}"
