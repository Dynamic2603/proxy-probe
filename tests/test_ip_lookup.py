from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from proxy_probe.ip_lookup import parse_whois_ru_html
from proxy_probe.prober import fetch_geo, fetch_geo_for_ip


def _make_resp(payload: bytes) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = payload
    resp.__enter__.return_value = resp
    return resp


def test_parse_whois_ru_html_ripe_inet_and_route_descr() -> None:
    ripe_hetzner = """
    <pre class="raw-domain-info-pre">
% Abuse contact for '5.9.1.0 - 5.9.1.31' is '<a href="/cdn-cgi/l/email-protection">[email&#160;protected]</a>'
inetnum:        5.9.1.0 - 5.9.1.31
netname:        HETZNER-fsn1-dc7
descr:          Hetzner Online GmbH
descr:          Datacenter fsn1-dc7
country:        DE
source:         RIPE
route:          5.9.0.0/16
descr:          HETZNER-RZ-FKS-BLK5
origin:         AS24940
    </pre>
    <pre class="raw-domain-info-pre">
описание:       Перевод
    </pre>
    """
    info = parse_whois_ru_html(ripe_hetzner, ip="5.9.1.1")
    assert info.ip == "5.9.1.1"
    assert info.country_code == "DE"
    assert info.org == "Hetzner Online GmbH"
    assert info.asn == 24940
    assert info.to_geo_tuple() == ("🇩🇪 DE", "5.9.1.1", "DE", "", "Hetzner Online GmbH")

    ripe_route_only_descr = """
    <pre class="raw-domain-info-pre">
inetnum:        178.72.0.0 - 178.72.3.255
netname:        net-178-72-0-0_22
country:        SE
route:          178.72.0.0/22
descr:          Nordisk Mobiltelefon Sweden AB
origin:         AS1299
    </pre>
    """
    info_se = parse_whois_ru_html(ripe_route_only_descr, ip="178.72.1.1")
    assert info_se.country_code == "SE"
    assert info_se.org == "Nordisk Mobiltelefon Sweden AB"
    assert info_se.asn == 1299


def test_parse_whois_ru_html_apnic_and_arin() -> None:
    apnic_html = """
    <pre class="raw-domain-info-pre">
inetnum:        1.1.1.0 - 1.1.1.255
netname:        APNIC-LABS
descr:          APNIC and Cloudflare DNS Resolver project
country:        AU
org:            ORG-ARAD1-AP
org-name:       APNIC Research and Development
country:        ZZ
origin:         AS13335
    </pre>
    """
    info_ap = parse_whois_ru_html(apnic_html, ip="1.1.1.1")
    assert info_ap.country_code == "AU"
    assert info_ap.org == "APNIC Research and Development"
    assert info_ap.asn == 13335

    arin_html = """
    <pre class="raw-domain-info-pre">
NetRange:       104.248.0.0 - 104.248.255.255
NetName:        DIGITALOCEAN-104-248-0-0
OriginAS:
Organization:   DigitalOcean, LLC (DO-13)
OrgName:        DigitalOcean, LLC
City:           Broomfield
Country:        US
    </pre>
    """
    info_us = parse_whois_ru_html(arin_html, ip="104.248.1.1")
    assert info_us.country_code == "US"
    assert info_us.city == "Broomfield"
    assert info_us.org == "DigitalOcean, LLC"
    assert info_us.to_geo_tuple() == ("🇺🇸 US", "104.248.1.1", "US", "Broomfield", "DigitalOcean, LLC")


def test_parse_whois_ru_html_rejects_missing_pre() -> None:
    with pytest.raises(ValueError, match="WHOIS"):
        parse_whois_ru_html("<html><body>Captcha or error page</body></html>", ip="1.2.3.4")


def test_fetch_geo_fallback_to_ipapi_on_ipwho_rate_limit() -> None:
    called_urls: list[str] = []

    def mock_open(_self, req, timeout=8.0):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        called_urls.append(url)
        if "ipwho.is" in url:
            return _make_resp(json.dumps({"success": False, "message": "Monthly limit reached"}).encode("utf-8"))
        if "ipapi.co" in url:
            return _make_resp(
                json.dumps(
                    {
                        "ip": "8.8.8.8",
                        "country": "US",
                        "country_name": "United States",
                        "country_code": "US",
                        "city": "Mountain View",
                        "org": "Google LLC",
                        "asn": "AS15169",
                    }
                ).encode("utf-8")
            )
        raise AssertionError(f"Unexpected URL: {url}")

    with patch("urllib.request.OpenerDirector.open", side_effect=mock_open, autospec=True):
        res = fetch_geo(12345)
        assert res == ("🇺🇸 United States", "8.8.8.8", "US", "Mountain View", "Google LLC")

    assert called_urls == ["http://ipwho.is/", "https://ipapi.co/json/"]


def test_fetch_geo_fallback_to_whois_ru_through_proxy_opener() -> None:
    called_urls: list[str] = []
    whois_html = b"""
    <pre class="raw-domain-info-pre">
inetnum:        5.9.1.0 - 5.9.1.31
descr:          Hetzner Online GmbH
country:        DE
origin:         AS24940
    </pre>
    """

    def mock_open(_self, req, timeout=8.0):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        called_urls.append(url)
        if "ipwho.is" in url or "ipapi.co" in url:
            raise RuntimeError("mirror unreachable")
        if url == "https://whois.ru/tools/get-my-ip":
            assert req.get_header("X-requested-with") == "XMLHttpRequest"
            return _make_resp(json.dumps({"output": "5.9.1.1"}).encode("utf-8"))
        if url == "https://whois.ru/5.9.1.1":
            return _make_resp(whois_html)
        raise AssertionError(f"Unexpected URL: {url}")

    with patch("urllib.request.OpenerDirector.open", side_effect=mock_open, autospec=True):
        res = fetch_geo(12345)
        assert res == ("🇩🇪 DE", "5.9.1.1", "DE", "", "Hetzner Online GmbH")

    assert called_urls == [
        "http://ipwho.is/",
        "https://ipapi.co/json/",
        "https://whois.ru/tools/get-my-ip",
        "https://whois.ru/5.9.1.1",
    ]


def test_fetch_geo_for_ip_fallback_to_whois_ru_and_loopback_skip() -> None:
    with patch("urllib.request.urlopen", side_effect=AssertionError("should not be called")):
        assert fetch_geo_for_ip("127.0.0.1") == ("", "", "", "", "")
        assert fetch_geo_for_ip("::1") == ("", "", "", "", "")
        assert fetch_geo_for_ip("localhost") == ("", "", "", "", "")

    called_urls: list[str] = []
    whois_html = b"""
    <pre class="raw-domain-info-pre">
inetnum:        77.88.8.0 - 77.88.8.255
descr:          Yandex enterprise network
country:        RU
origin:         AS13238
    </pre>
    """

    def mock_urlopen(req, timeout=4.0):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        called_urls.append(url)
        if "ipwho.is" in url:
            raise RuntimeError("ipwho down")
        if "ipapi.co" in url:
            return _make_resp(json.dumps({"error": True, "reason": "RateLimited"}).encode("utf-8"))
        if url == "https://whois.ru/77.88.8.8":
            return _make_resp(whois_html)
        raise AssertionError(f"Unexpected URL: {url}")

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = fetch_geo_for_ip("77.88.8.8")
        assert res == ("🇷🇺 RU", "77.88.8.8", "RU", "", "Yandex enterprise network")

    assert called_urls == [
        "http://ipwho.is/77.88.8.8",
        "https://ipapi.co/77.88.8.8/json/",
        "https://whois.ru/77.88.8.8",
    ]


def test_fetch_geo_returns_empty_when_all_mirrors_fail() -> None:
    with patch("urllib.request.OpenerDirector.open", side_effect=RuntimeError("all down")):
        assert fetch_geo(12345) == ("", "", "", "", "")
