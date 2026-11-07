from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from proxy_probe.antidpi.isp import (
    IspDetectionError,
    IspIdentity,
    _parse_asn,
    detect_current_isp,
    slugify_isp,
)


def test_slugify_isp() -> None:
    assert slugify_isp("PJSC Rostelecom") == "pjsc-rostelecom"
    assert slugify_isp("MTS PJSC") == "mts-pjsc"
    assert slugify_isp("1337 Services GmbH") == "1337-services-gmbh"
    assert slugify_isp("ПАО \"Ростелеком\"") == "пао-ростелеком"
    assert slugify_isp("   ") == "unknown"


def test_isp_identity_properties() -> None:
    ident = IspIdentity(
        asn=12389,
        isp_name="PJSC Rostelecom",
        org_name="Rostelecom",
        ingress_ip="178.72.1.1",
    )
    assert ident.asn == 12389
    assert ident.slug == "pjsc-rostelecom"
    assert ident.key == "AS12389_pjsc-rostelecom"
    assert ident.display_name == "PJSC Rostelecom (AS12389)"

    # Без ASN
    ident_no_asn = IspIdentity(
        asn=0,
        isp_name="LocalNet",
        org_name="LocalNet",
        ingress_ip="192.168.1.1",
    )
    assert ident_no_asn.key == "localnet"
    assert ident_no_asn.display_name == "LocalNet"


def test_parse_asn() -> None:
    assert _parse_asn(12389) == 12389
    assert _parse_asn("AS12389") == 12389
    assert _parse_asn("AS 8359 ") == 8359
    assert _parse_asn(None) == 0
    assert _parse_asn("") == 0
    assert _parse_asn("invalid") == 0


def test_detect_current_isp_explicit_override() -> None:
    ident = detect_current_isp(explicit_override="AS8359_mts")
    assert ident.asn == 8359
    assert ident.key == "AS8359_as8359_mts"


def test_detect_current_isp_ipwho_success() -> None:
    content = json.dumps({
        "success": True,
        "ip": "1.2.3.4",
        "connection": {
            "asn": 12389,
            "isp": "PJSC Rostelecom",
            "org": "Rostelecom",
        },
    }).encode("utf-8")

    mock_resp = MagicMock()
    mock_resp.read.return_value = content
    mock_resp.__enter__.return_value.read.return_value = content

    with patch("urllib.request.urlopen", return_value=mock_resp):
        ident = detect_current_isp()
        assert ident.asn == 12389
        assert ident.isp_name == "PJSC Rostelecom"
        assert ident.ingress_ip == "1.2.3.4"
        assert ident.key == "AS12389_pjsc-rostelecom"


def test_detect_current_isp_ipapi_fallback_on_ipwho_failure() -> None:
    content = json.dumps({
        "ip": "5.6.7.8",
        "asn": "AS8359",
        "org": "MTS PJSC",
    }).encode("utf-8")

    ipapi_resp = MagicMock()
    ipapi_resp.read.return_value = content
    ipapi_resp.__enter__.return_value.read.return_value = content

    def mock_urlopen(req, timeout=3.0):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "ipwho" in url:
            raise RuntimeError("ipwho is down")
        return ipapi_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        ident = detect_current_isp()
        assert ident.asn == 8359
        assert ident.org_name == "MTS PJSC"
        assert ident.ingress_ip == "5.6.7.8"
        assert ident.key == "AS8359_mts-pjsc"


def test_detect_current_isp_strict_no_fallback_on_total_failure() -> None:
    with (
        patch("urllib.request.urlopen", side_effect=RuntimeError("no network")),
        pytest.raises(IspDetectionError, match="Не удалось достоверно определить"),
    ):
        detect_current_isp()
