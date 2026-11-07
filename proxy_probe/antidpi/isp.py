from __future__ import annotations

import dataclasses
import json
import logging
import re
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


class IspDetectionError(RuntimeError):
    """Выбрасывается при невозможности определить текущего интернет-провайдера."""


def slugify_isp(name: str) -> str:
    """Преобразует произвольное имя провайдера в канонический латинский slug."""
    cleaned = re.sub(r"[^\w\s-]", "", name.lower())
    slug = re.sub(r"[-\s]+", "-", cleaned).strip("-")
    return slug or "unknown"


@dataclasses.dataclass(frozen=True)
class IspIdentity:
    """Идентичность интернет-провайдера на основе Автономной Системы (SSOT)."""

    asn: int
    isp_name: str
    org_name: str
    ingress_ip: str

    @property
    def slug(self) -> str:
        raw = self.isp_name or self.org_name or "unknown"
        return slugify_isp(raw)

    @property
    def key(self) -> str:
        """Канонический уникальный идентификатор провайдера для базы рейтингов."""
        if self.asn > 0:
            return f"AS{self.asn}_{self.slug}"
        return self.slug

    @property
    def display_name(self) -> str:
        """Человекочитаемое название с ASN."""
        name = self.isp_name or self.org_name or "Unknown ISP"
        if self.asn > 0:
            return f"{name} (AS{self.asn})"
        return name


def _parse_asn(raw: Any) -> int:
    """Извлекает целочисленный номер ASN из строки или числа."""
    if isinstance(raw, int):
        return raw
    if not raw:
        return 0
    m = re.search(r"\d+", str(raw))
    return int(m.group(0)) if m else 0


def _query_ipwho(timeout: float = 3.0) -> IspIdentity:
    req = urllib.request.Request("http://ipwho.is/", headers={"User-Agent": "proxy-probe/antidpi-isp"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data.get("success", True):
        raise ValueError(data.get("message", "ipwho.is returned failure"))

    conn = data.get("connection") or {}
    asn = _parse_asn(conn.get("asn"))
    isp = str(conn.get("isp") or data.get("isp") or "").strip()
    org = str(conn.get("org") or data.get("org") or "").strip()
    ip = str(data.get("ip") or "").strip()

    if not asn and not isp and not org:
        raise ValueError("ipwho.is не вернул данных ASN/ISP")

    return IspIdentity(asn=asn, isp_name=isp, org_name=org, ingress_ip=ip)


def _query_ipapi(timeout: float = 3.0) -> IspIdentity:
    req = urllib.request.Request("https://ipapi.co/json/", headers={"User-Agent": "proxy-probe/antidpi-isp"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    asn = _parse_asn(data.get("asn"))
    org = str(data.get("org") or "").strip()
    ip = str(data.get("ip") or "").strip()

    if not asn and not org:
        raise ValueError("ipapi.co не вернул данных ASN/ISP")

    return IspIdentity(asn=asn, isp_name=org, org_name=org, ingress_ip=ip)


def detect_current_isp(timeout: float = 3.0, explicit_override: str | None = None) -> IspIdentity:
    """Определяет входящего интернет-провайдера (Ingress ISP) строго без фоллбэков на default.

    При явном указании explicit_override (CLI-флаг --isp) использует его.
    При сетевом сбое или отсутствии связи выбрасывает IspDetectionError (Fail-Fast),
    гарантируя изоляцию профилей и исключая порчу рейтингов других сетей.
    """
    if explicit_override and explicit_override.strip():
        val = explicit_override.strip()
        asn = _parse_asn(val)
        return IspIdentity(asn=asn, isp_name=val, org_name=val, ingress_ip="")

    # 1. Основной эндпоинт ipwho.is
    try:
        return _query_ipwho(timeout=timeout)
    except Exception as exc1:
        logger.debug("Сбой запроса к ipwho.is: %s. Попытка резервного сервиса...", exc1)

    # 2. Резервный эндпоинт ipapi.co
    try:
        return _query_ipapi(timeout=timeout)
    except Exception as exc2:
        logger.debug("Сбой запроса к ipapi.co: %s", exc2)

    # Строгий отказ: фоллбэк на 'default' или вымышленные значения запрещен!
    raise IspDetectionError(
        "Не удалось достоверно определить входящего интернет-провайдера (Ingress ISP). "
        "Проверьте сетевое подключение. Работа Anti-DPI без точной идентификации провайдера "
        "запрещена во избежание взаимного повреждения профилей сетей (дом/работа)."
    )
