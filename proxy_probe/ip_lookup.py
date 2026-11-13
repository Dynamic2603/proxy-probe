from __future__ import annotations

import dataclasses
import html
import ipaddress
import json
import logging
import re
import urllib.request
from collections.abc import Callable
from typing import Any

from .models import country_code_to_emoji
from .parsers import USER_AGENT

logger = logging.getLogger(__name__)

IPWHO_BASE_URL = "http://ipwho.is/"
IPAPI_BASE_URL = "https://ipapi.co"
WHOIS_RU_BASE_URL = "https://whois.ru"

_RE_WHOIS_PRE_CLASS = re.compile(
    r'<pre[^>]*class=["\'][^"\']*raw-domain-info-pre[^"\']*["\'][^>]*>(.*?)</pre>',
    re.IGNORECASE | re.DOTALL,
)
_RE_WHOIS_PRE_ANY = re.compile(r"<pre[^>]*>(.*?)</pre>", re.IGNORECASE | re.DOTALL)
_RE_HTML_TAG = re.compile(r"<[^>]+>")
_RE_WHOIS_KV = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)$")
_RE_HANDLE_SUFFIX = re.compile(r"\s+\([A-Z0-9-]+\)$")
_RE_RIR_ORG_HANDLE = re.compile(r"^ORG-[A-Z0-9-]+-(?:RIPE|AP|AFRINIC|LACNIC|ARIN)$", re.IGNORECASE)


class IpLookupError(RuntimeError):
    """Выбрасывается, когда все зеркала определения IP/гео/провайдера завершились сбоем."""


@dataclasses.dataclass(frozen=True)
class IpGeoInfo:
    """Унифицированные метаданные IP-адреса (геолокация + ASN/провайдер)."""

    ip: str = ""
    country_code: str = ""
    country_name: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: int = 0
    flag: str = ""

    def to_geo_tuple(self) -> tuple[str, str, str, str, str]:
        """Возвращает кортеж (country, ip_out, country_code, city, org) для prober."""
        code = self.country_code.strip().upper()
        flag = self.flag.strip() or (country_code_to_emoji(code) if code else "")
        label = self.country_name.strip() or code
        country = f"{flag} {label}".strip()
        org = self.org.strip() or self.isp.strip()
        return country, self.ip.strip(), code, self.city.strip(), org


def parse_asn(raw: Any) -> int:
    """Извлекает целочисленный номер ASN из строки или числа."""
    if isinstance(raw, int):
        return raw
    if not raw:
        return 0
    m = re.search(r"\d+", str(raw))
    return int(m.group(0)) if m else 0


def _validate_ip(raw_ip: str) -> str:
    cleaned = (raw_ip or "").strip()
    if not cleaned:
        raise ValueError("Пустой IP-адрес")
    return str(ipaddress.ip_address(cleaned))


def _open_bytes(
    url: str,
    *,
    timeout: float,
    headers: dict[str, str],
    opener: urllib.request.OpenerDirector | None = None,
) -> bytes:
    req = urllib.request.Request(url, headers=headers)
    if opener is not None:
        with opener.open(req, timeout=timeout) as resp:
            return resp.read()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def parse_ipwho_payload(data: dict[str, Any]) -> IpGeoInfo:
    """Разбирает JSON-ответ от ipwho.is в канонический IpGeoInfo."""
    if not isinstance(data, dict):
        raise ValueError("ipwho.is вернул некорректный JSON")
    if not data.get("success", True):
        raise ValueError(str(data.get("message") or "ipwho.is returned failure"))

    country_code = str(data.get("country_code") or "").strip().upper()
    flag_raw = data.get("flag", "")
    flag = str(flag_raw.get("emoji") or "").strip() if isinstance(flag_raw, dict) else str(flag_raw or "").strip()
    country_name = str(data.get("country") or "").strip()
    ip_out = str(data.get("ip") or "").strip()
    city = str(data.get("city") or "").strip()

    conn = data.get("connection")
    conn_dict = conn if isinstance(conn, dict) else {}
    asn = parse_asn(conn_dict.get("asn") if conn_dict else data.get("asn"))
    isp = str(conn_dict.get("isp") or data.get("isp") or "").strip()
    org = str(conn_dict.get("org") or data.get("org") or "").strip()

    return IpGeoInfo(
        ip=ip_out,
        country_code=country_code,
        country_name=country_name,
        city=city,
        isp=isp,
        org=org,
        asn=asn,
        flag=flag,
    )


def parse_ipapi_payload(data: dict[str, Any]) -> IpGeoInfo:
    """Разбирает JSON-ответ от ipapi.co в канонический IpGeoInfo."""
    if not isinstance(data, dict):
        raise ValueError("ipapi.co вернул некорректный JSON")
    if data.get("error"):
        raise ValueError(str(data.get("reason") or data.get("message") or "ipapi.co returned error"))

    raw_code = str(data.get("country_code") or "").strip().upper()
    if not raw_code:
        raw_country = str(data.get("country") or "").strip().upper()
        if len(raw_country) == 2 and raw_country.isalpha():
            raw_code = raw_country
    country_name = str(data.get("country_name") or "").strip()
    ip_out = str(data.get("ip") or "").strip()
    city = str(data.get("city") or "").strip()
    asn = parse_asn(data.get("asn"))
    org = str(data.get("org") or "").strip()

    return IpGeoInfo(
        ip=ip_out,
        country_code=raw_code,
        country_name=country_name,
        city=city,
        isp=org,
        org=org,
        asn=asn,
    )


def _extract_whois_pre(html_text: str) -> str:
    match = _RE_WHOIS_PRE_CLASS.search(html_text) or _RE_WHOIS_PRE_ANY.search(html_text)
    if not match:
        raise ValueError("whois.ru не вернул блок WHOIS")
    plain = _RE_HTML_TAG.sub("", match.group(1))
    return html.unescape(plain)


def parse_whois_ru_html(html_text: str, ip: str) -> IpGeoInfo:
    """Извлекает гео и данные ASN/провайдера из HTML-страницы https://whois.ru/<ip>."""
    whois_text = _extract_whois_pre(html_text)

    in_route_section = False
    asn = 0
    country_code = ""
    fallback_country = ""
    city = ""
    org_name = ""
    owner = ""
    organization = ""
    inet_descr = ""
    route_descr = ""
    as_name = ""
    netname = ""
    raw_org = ""

    for raw_line in whois_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("%", "#")):
            continue
        m = _RE_WHOIS_KV.match(line)
        if not m:
            continue
        key = m.group(1).lower()
        val = m.group(2).strip()
        if key in ("route", "route6", "aut-num"):
            in_route_section = True
        if not val:
            continue

        if key in ("origin", "originas", "aut-num") and not asn:
            asn = parse_asn(val)
        elif key == "country":
            head = val.split("#", 1)[0].strip()
            token = head.split()[0].upper() if head.split() else ""
            if len(token) == 2 and token.isalpha():
                if token != "ZZ" and not country_code:
                    country_code = token
                elif not fallback_country:
                    fallback_country = token
        elif key == "city" and not city:
            city = val
        elif key in ("org-name", "orgname") and not org_name:
            org_name = val
        elif key == "owner" and not owner:
            owner = val
        elif key == "organization" and not organization:
            organization = _RE_HANDLE_SUFFIX.sub("", val).strip() or val
        elif key == "descr":
            if in_route_section:
                if not route_descr:
                    route_descr = val
            elif not inet_descr:
                inet_descr = val
        elif key == "as-name" and not as_name:
            as_name = val
        elif key == "netname" and not netname:
            netname = val
        elif key == "org" and not raw_org and not _RE_RIR_ORG_HANDLE.match(val):
            raw_org = val

    resolved_org = org_name or owner or organization or inet_descr or route_descr or as_name or netname or raw_org
    final_country = country_code or fallback_country

    if not any((asn, final_country, resolved_org, city)):
        raise ValueError("whois.ru не содержит распознаваемых WHOIS-полей")

    return IpGeoInfo(
        ip=ip.strip(),
        country_code=final_country,
        country_name="",
        city=city,
        isp=resolved_org,
        org=resolved_org,
        asn=asn,
    )


def query_ipwho(
    ip: str | None = None,
    timeout: float = 4.0,
    opener: urllib.request.OpenerDirector | None = None,
    user_agent: str = USER_AGENT,
) -> IpGeoInfo:
    """Запрашивает метаданные IP через http://ipwho.is/."""
    target = _validate_ip(ip) if ip and ip.strip() else ""
    url = f"{IPWHO_BASE_URL}{target}"
    raw = _open_bytes(
        url,
        timeout=timeout,
        headers={"User-Agent": user_agent, "Accept": "application/json"},
        opener=opener,
    ).decode("utf-8", "replace")
    data = json.loads(raw)
    return parse_ipwho_payload(data)


def query_ipapi(
    ip: str | None = None,
    timeout: float = 4.0,
    opener: urllib.request.OpenerDirector | None = None,
    user_agent: str = USER_AGENT,
) -> IpGeoInfo:
    """Запрашивает метаданные IP через https://ipapi.co/."""
    target = _validate_ip(ip) if ip and ip.strip() else ""
    url = f"{IPAPI_BASE_URL}/{target}/json/" if target else f"{IPAPI_BASE_URL}/json/"
    raw = _open_bytes(
        url,
        timeout=timeout,
        headers={"User-Agent": user_agent, "Accept": "application/json"},
        opener=opener,
    ).decode("utf-8", "replace")
    data = json.loads(raw)
    return parse_ipapi_payload(data)


def _fetch_self_ip_whois_ru(
    *,
    timeout: float,
    opener: urllib.request.OpenerDirector | None,
    user_agent: str,
) -> str:
    raw = (
        _open_bytes(
            f"{WHOIS_RU_BASE_URL}/tools/get-my-ip",
            timeout=timeout,
            headers={
                "User-Agent": user_agent,
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/plain, */*",
            },
            opener=opener,
        )
        .decode("utf-8", "replace")
        .strip()
    )

    ip_candidate = raw
    if raw.startswith("{"):
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("whois.ru/tools/get-my-ip вернул некорректный JSON")
        ip_candidate = str(data.get("output") or data.get("ip") or "").strip()
    return _validate_ip(ip_candidate)


def query_whois_ru(
    ip: str | None = None,
    timeout: float = 4.0,
    opener: urllib.request.OpenerDirector | None = None,
    user_agent: str = USER_AGENT,
) -> IpGeoInfo:
    """Запрашивает метаданные IP через зеркало https://whois.ru/ (HTML WHOIS)."""
    target_ip = (
        _validate_ip(ip)
        if ip and ip.strip()
        else _fetch_self_ip_whois_ru(timeout=timeout, opener=opener, user_agent=user_agent)
    )
    html_text = _open_bytes(
        f"{WHOIS_RU_BASE_URL}/{target_ip}",
        timeout=timeout,
        headers={"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml"},
        opener=opener,
    ).decode("utf-8", "replace")
    return parse_whois_ru_html(html_text, ip=target_ip)


ProviderFn = Callable[[str | None, float, urllib.request.OpenerDirector | None, str], IpGeoInfo]

IP_LOOKUP_PROVIDERS: tuple[tuple[str, ProviderFn], ...] = (
    ("ipwho.is", query_ipwho),
    ("ipapi.co", query_ipapi),
    ("whois.ru", query_whois_ru),
)


def lookup_ip_info(
    ip: str | None = None,
    *,
    timeout: float = 4.0,
    opener: urllib.request.OpenerDirector | None = None,
    user_agent: str = USER_AGENT,
    require_isp: bool = False,
) -> IpGeoInfo:
    """Определяет метаданные IP по цепочке зеркал: ipwho.is -> ipapi.co -> whois.ru."""
    errors: list[str] = []
    for name, provider in IP_LOOKUP_PROVIDERS:
        try:
            info = provider(ip, timeout, opener, user_agent)
            if require_isp:
                if not (info.asn or info.isp or info.org):
                    raise ValueError(f"{name} не вернул данных ASN/ISP")
            elif not (info.ip or info.country_code or info.country_name):
                raise ValueError(f"{name} не вернул гео-данных")
            return info
        except Exception as exc:
            logger.debug("Сбой запроса к %s: %s", name, exc)
            errors.append(f"{name}: {exc}")
    raise IpLookupError("; ".join(errors) or "Все сервисы определения IP недоступны")
