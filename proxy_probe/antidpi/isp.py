from __future__ import annotations

import dataclasses
import logging
import re

from ..ip_lookup import IpLookupError, lookup_ip_info, parse_asn

logger = logging.getLogger(__name__)
_parse_asn = parse_asn


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


def detect_current_isp(timeout: float = 3.0, explicit_override: str | None = None) -> IspIdentity:
    """Определяет входящего интернет-провайдера (Ingress ISP) строго без фоллбэков на default.

    Цепочка зеркал: ipwho.is -> ipapi.co -> whois.ru.
    При явном указании explicit_override (CLI-флаг --isp) использует его.
    При сетевом сбое или отсутствии связи выбрасывает IspDetectionError (Fail-Fast),
    гарантируя изоляцию профилей и исключая порчу рейтингов других сетей.
    """
    if explicit_override and explicit_override.strip():
        val = explicit_override.strip()
        asn = _parse_asn(val)
        return IspIdentity(asn=asn, isp_name=val, org_name=val, ingress_ip="")

    try:
        info = lookup_ip_info(
            ip=None,
            timeout=timeout,
            user_agent="proxy-probe/antidpi-isp",
            require_isp=True,
        )
        return IspIdentity(
            asn=info.asn,
            isp_name=info.isp,
            org_name=info.org,
            ingress_ip=info.ip,
        )
    except IpLookupError as exc:
        logger.debug("Сбой всех сервисов определения ISP: %s", exc)
        # Строгий отказ: фоллбэк на 'default' или вымышленные значения запрещен!
        raise IspDetectionError(
            "Не удалось достоверно определить входящего интернет-провайдера (Ingress ISP). "
            "Проверьте сетевое подключение. Работа Anti-DPI без точной идентификации провайдера "
            "запрещена во избежание взаимного повреждения профилей сетей (дом/работа)."
        ) from exc
