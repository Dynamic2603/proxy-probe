from __future__ import annotations

import dataclasses
import hashlib
import re
from typing import Any

RESULT_OK = "AGY-OK"
RESULT_BLOCK = "AGY-BLOCK"
RESULT_DEAD = "DEAD"
RESULT_UNKNOWN = "UNKNOWN"

GEO_PRECHECK_URL = "https://aistudio.google.com"
WEB_CHECK_URL = "https://gemini.google.com"
WEB_STATUS_OK = "ok"
WEB_STATUS_CAPTCHA = "captcha"
WEB_STATUS_BLOCKED = "blocked"

STATE_ACTIVE = "ACTIVE"
STATE_DEGRADED = "DEGRADED"
STATE_DEAD = "DEAD"
MAX_CONSECUTIVE_FAILS = 3

TERMINAL_FAILURES = {RESULT_BLOCK}
TRANSIENT_FAILURES = {RESULT_DEAD, RESULT_UNKNOWN}


def is_exportable(result: str, state: str) -> bool:
    """SSOT-критерий доступности сервера для экспорта в proxy-ok.txt.

    Сервер экспортируется, если:
    1. Он подтвержден как рабочий для Gemini (result == AGY-OK).
    2. Либо он на испытательном сроке по сети (state == STATE_DEGRADED),
       НО строго при условии отсутствия геоблока (result != AGY-BLOCK).
    """
    if result in TERMINAL_FAILURES:
        return False
    return result == RESULT_OK or state == STATE_DEGRADED


def format_score_display(score: int, state: str = STATE_ACTIVE) -> str:
    """Форматирует скор для таблиц отчетов и консоли с суффиксом-эмодзи."""
    if state == STATE_DEGRADED:
        return f"{score}⚠️" if score > 0 else "—"
    if score >= 90:
        return f"{score}⭐"
    return str(score) if score > 0 else "—"

DEFAULT_TTLS = {RESULT_OK: 3 * 86400, RESULT_BLOCK: 7 * 86400, RESULT_DEAD: 86400}
RESULT_PRIORITIES = {RESULT_BLOCK: 3, RESULT_OK: 2, RESULT_DEAD: 1, RESULT_UNKNOWN: 0}

FINGERPRINT_PRIORITIES: dict[str, int] = {
    "chrome": 10,
    "firefox": 8,
    "safari": 7,
    "edge": 6,
    "ios": 5,
    "android": 4,
    "qq": 2,
}

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


def country_code_to_emoji(code: str) -> str:
    """Преобразует 2-буквенный ISO код страны (напр. 'DE') в флаг emoji (🇩🇪)."""
    code = (code or "").strip().upper()
    if len(code) == 2 and code.isalpha():
        return chr(ord(code[0]) - ord("A") + 0x1F1E6) + chr(ord(code[1]) - ord("A") + 0x1F1E6)
    return ""


def normalize_org_name(org: str) -> str:
    """Нормализует пробелы в названии организации/провайдера."""
    raw = str(org or "").strip()
    return " ".join(raw.split()) if raw else ""


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
    country_code: str = ""
    city: str = ""
    org: str = ""
    score: int = 0
    state: str = STATE_ACTIVE
    consecutive_fails: int = 0
    web_status: str = ""
    ingress_country_code: str = ""
    ingress_ip: str = ""
    antidpi_strategy: int | None = None
    from_cache: bool = False
    _config_identity: str | None = dataclasses.field(default=None, repr=False, compare=False)
    _endpoint_identity: str | None = dataclasses.field(default=None, repr=False, compare=False)
    _cache_key: str | None = dataclasses.field(default=None, repr=False, compare=False)
    _sni: str | None = dataclasses.field(default=None, repr=False, compare=False)
    _fingerprint: str | None = dataclasses.field(default=None, repr=False, compare=False)
    _is_tcp_protocol: bool | None = dataclasses.field(default=None, repr=False, compare=False)

    @property
    def is_exportable(self) -> bool:
        """SSOT-критерий: доступен ли узел для выгрузки в proxy-ok.txt."""
        return is_exportable(self.result, self.state)

    @property
    def score_badge(self) -> str:
        """Формирует бейдж скора и статуса с суффиксом-эмодзи (сохраняя алфавитную сортировку)."""
        badge = ""
        if self.state == STATE_ACTIVE:
            badge = f"[{self.score}⭐]" if self.score >= 90 else (f"[{self.score}]" if self.score > 0 else "")
        elif self.state == STATE_DEGRADED:
            badge = f"[{self.score}⚠️]"

        if self.web_status == WEB_STATUS_CAPTCHA:
            badge = f"{badge}[captcha]" if badge else "[captcha]"
        if self.antidpi_strategy is not None:
            zapret_badge = "[zapret]"
            badge = f"{badge}{zapret_badge}" if badge else zapret_badge
        return badge

    @property
    def route_geo(self) -> str:
        """Формирует географическую цепочку узла: '{in_flag} {in_code} ➔ {main_geo}' для реле."""
        flag = country_code_to_emoji(self.country_code)
        loc_parts: list[str] = []
        if self.country_code:
            loc_parts.append(self.country_code.upper())
        if self.city:
            loc_parts.append(self.city)
        loc_str = ", ".join(loc_parts)

        main_geo = f"{flag} {loc_str}".strip() if (flag or loc_str) else ""
        if not main_geo and self.country:
            main_geo = self.country

        in_code = (self.ingress_country_code or "").strip().upper()
        # Показываем маршрут ➔ только если точка входа отличается от точки выхода
        if in_code and (self.server != self.ip_out):
            in_flag = country_code_to_emoji(in_code)
            in_str = f"{in_flag} {in_code}".strip()
            return f"{in_str} ➔ {main_geo}" if main_geo else in_str

        return main_geo

    @property
    def host_port(self) -> str:
        return f"{self.server}:{self.server_port}"

    @property
    def is_tcp_protocol(self) -> bool:
        """Определяет, использует ли узел транспорт TCP (False для чистого UDP: Hysteria 2, WireGuard, TUIC)."""
        if self._is_tcp_protocol is not None:
            return self._is_tcp_protocol
        if not self.import_obj or not isinstance(self.import_obj, dict):
            self._is_tcp_protocol = True
            return True
        proto = str(self.import_obj.get("type") or self.import_obj.get("protocol") or "").strip().lower()
        res = proto not in ("hysteria2", "tuic", "wireguard")
        self._is_tcp_protocol = res
        return res

    @property
    def sni(self) -> str:
        """Извлекает SNI / serverName из конфигурации (sing-box или Xray)."""
        if self._sni is not None:
            return self._sni
        res = ""
        if self.import_obj and isinstance(self.import_obj, dict):
            obj = self.import_obj
            tls = obj.get("tls")
            if isinstance(tls, dict) and (sn := tls.get("server_name")):
                res = str(sn).strip()
            elif isinstance(ss := obj.get("streamSettings"), dict):
                for sk in ("tlsSettings", "realitySettings"):
                    sub = ss.get(sk)
                    if isinstance(sub, dict) and (sn := sub.get("serverName")):
                        res = str(sn).strip()
                        break
        self._sni = res
        return res

    @property
    def fingerprint(self) -> str:
        """Извлекает uTLS fingerprint из конфигурации (sing-box или Xray)."""
        if self._fingerprint is not None:
            return self._fingerprint
        res = ""
        if self.import_obj and isinstance(self.import_obj, dict):
            obj = self.import_obj
            tls = obj.get("tls")
            if isinstance(tls, dict):
                utls = tls.get("utls")
                if isinstance(utls, dict) and (f := utls.get("fingerprint")):
                    res = str(f).strip().lower()
            if not res and isinstance(ss := obj.get("streamSettings"), dict):
                for sk in ("tlsSettings", "realitySettings"):
                    sub = ss.get(sk)
                    if isinstance(sub, dict) and (f := sub.get("fingerprint")):
                        res = str(f).strip().lower()
                        break
        self._fingerprint = res
        return res

    @property
    def formatted_tag(self) -> str:
        """Формирует полностью собственное каноническое имя узла (SSOT).

        Никогда не парсит и не использует сырые имена из подписок.
        Формат:
        [{score}⭐] [{flag_in} {code_in} ➔ ]{flag} {code}, {city} | {clean_org} (sni: {sni}, fp: {fp})
        Фоллбэк при неполном гео:
        {flag} {code} | {clean_org} -> {country} -> {host}:{port}
        """
        main_geo = self.route_geo
        org_str = normalize_org_name(self.org)

        parts: list[str] = []
        if main_geo:
            parts.append(main_geo)

        if org_str:
            parts.append(org_str)

        head = " | ".join(parts) if parts else (self.host_port if self.server else "proxy")

        extra_parts: list[str] = []
        if self.sni:
            extra_parts.append(f"sni: {self.sni}")
        if self.fingerprint:
            extra_parts.append(f"fp: {self.fingerprint}")

        if extra_parts:
            head = f"{head} ({', '.join(extra_parts)})"

        badge = self.score_badge
        if badge:
            head = f"{badge} {head}"

        return head

    def _parse_config_parts(self) -> tuple[str, str, str, str, str, str, str, str, str, str]:
        """Парсит нормализованные компоненты конфигурации (SSOT).

        Возвращает:
        (proto, host, port, cred, sni, reality_pk, fp, flow, alpn_str, path)
        """
        if not self.import_obj or not isinstance(self.import_obj, dict):
            return ("unknown", str(self.server), str(self.server_port), "", "", "", "", "", "", "")

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

        sni = self.sni
        fp = self.fingerprint
        reality_pk = ""
        alpn_str = ""

        tls = obj.get("tls")
        if isinstance(tls, dict):
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

        return (proto, str(self.server), str(self.server_port), cred, sni, reality_pk, fp, flow, alpn_str, path)

    @property
    def config_identity(self) -> str:
        """Канонический идентификатор конфигурации узла (SSOT).

        Нормализует диалекты Xray и sing-box в единый канонический ключ:
        protocol : host : port : cred : sni : reality_pk : fingerprint : flow : alpn : path
        """
        if self._config_identity is not None:
            return self._config_identity
        parts = self._parse_config_parts()
        res = ":".join(parts)
        self._config_identity = res
        return res

    @property
    def endpoint_identity(self) -> str:
        """Канонический идентификатор эндпоинта/сервиса без учета отпечатка uTLS (SSOT).

        Нормализует диалекты Xray и sing-box в единый ключ сервиса:
        protocol : host : port : cred : sni : reality_pk : flow : alpn : path
        """
        if self._endpoint_identity is not None:
            return self._endpoint_identity
        proto, host, port, cred, sni, reality_pk, _fp, flow, alpn_str, path = self._parse_config_parts()
        res = f"{proto}:{host}:{port}:{cred}:{sni}:{reality_pk}:{flow}:{alpn_str}:{path}"
        self._endpoint_identity = res
        return res

    @property
    def export_rank(self) -> tuple[int, int, int, int, int, int, int]:
        """Критерий сравнительной ценности узла при экспорте в подписку (SSOT).

        Иерархия (от более важных к менее важным):
        1. Состояние: ACTIVE (1) строго выше DEGRADED (0).
        2. Прямой доступ: прямое подключение без Zapret (1) предпочтительнее требующего Zapret (0).
        3. Скор надежности (0..100): стабильные узлы выше (score).
        4. Задержка: меньший пинг предпочтительнее (-latency_ms).
        5. Свежесть источника: живая проверка (fresh/db = 1) предпочтительнее исторического кэша (cache = 0).
        6. Вес TLS-отпечатка: популярные браузерные отпечатки (Chrome > Firefox > ...) выше экзотических.
        7. Порядок подписки: сохранение оригинальной позиции (-index).
        """
        state_weight = 1 if self.state == STATE_ACTIVE else 0
        direct_weight = 1 if self.antidpi_strategy is None else 0
        lat_weight = -self.latency_ms if self.latency_ms > 0 else -999999
        source_weight = 0 if self.source == "cache" else 1
        fp_name = (self.fingerprint or "").strip().lower()
        fp_rank = FINGERPRINT_PRIORITIES.get(fp_name, 1 if fp_name else 0)
        return (state_weight, direct_weight, self.score, lat_weight, source_weight, fp_rank, -self.index)

    @property
    def cache_key(self) -> str:
        if self._cache_key is not None:
            return self._cache_key
        h = hashlib.sha256(self.config_identity.encode("utf-8")).hexdigest()[:8]
        res = f"{self.server}:{self.server_port}:{self.engine}:{h}"
        self._cache_key = res
        return res
