from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from proxy_probe.cache import ResultCache
from proxy_probe.models import (
    RESULT_OK,
    Server,
    country_code_to_emoji,
    normalize_org_name,
)
from proxy_probe.prober import fetch_geo
from proxy_probe.reporter import write_import_file


def test_country_code_to_emoji() -> None:
    assert country_code_to_emoji("DE") == "🇩🇪"
    assert country_code_to_emoji("us") == "🇺🇸"
    assert country_code_to_emoji("Nl") == "🇳🇱"
    assert country_code_to_emoji("fi") == "🇫🇮"
    assert country_code_to_emoji("pl") == "🇵🇱"
    # Невалидные коды
    assert country_code_to_emoji("") == ""
    assert country_code_to_emoji("USA") == ""
    assert country_code_to_emoji("12") == ""


def test_normalize_org_name() -> None:
    assert normalize_org_name("  Hetzner   Online  GmbH ") == "Hetzner Online GmbH"
    assert normalize_org_name("DigitalOcean, LLC") == "DigitalOcean, LLC"
    assert normalize_org_name("OVH SAS") == "OVH SAS"
    assert normalize_org_name("") == ""


def test_server_sni_and_fingerprint_singbox() -> None:
    obj = {
        "type": "vless",
        "server": "1.1.1.1",
        "server_port": 443,
        "tls": {
            "enabled": True,
            "server_name": "yahoo.com",
            "utls": {"enabled": True, "fingerprint": "Chrome"},
        },
    }
    s = Server(1, "grp", "srv", "sing-box", "1.1.1.1", 443, obj, "fresh")
    assert s.sni == "yahoo.com"
    assert s.fingerprint == "chrome"


def test_server_sni_and_fingerprint_xray() -> None:
    obj = {
        "protocol": "vless",
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": "dl.google.com",
                "fingerprint": "Firefox",
            },
        },
    }
    s = Server(1, "grp", "srv", "xray", "2.2.2.2", 443, obj, "fresh")
    assert s.sni == "dl.google.com"
    assert s.fingerprint == "firefox"


def test_server_sni_and_fingerprint_reality() -> None:
    obj = {
        "protocol": "vless",
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": "gateway.icloud.com",
                "fingerprint": "Safari",
                "publicKey": "key123",
            },
        },
    }
    s = Server(1, "grp", "srv", "xray", "3.3.3.3", 443, obj, "fresh")
    assert s.sni == "gateway.icloud.com"
    assert s.fingerprint == "safari"


def test_server_formatted_tag_full_geo_and_masking() -> None:
    obj = {
        "type": "vless",
        "server": "1.2.3.4",
        "server_port": 443,
        "tls": {
            "server_name": "yahoo.com",
            "utls": {"fingerprint": "chrome"},
        },
    }
    s = Server(
        group_id=1,
        group_name="grp",
        name="old-name",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj=obj,
        source="fresh",
        country_code="DE",
        city="Frankfurt",
        org="Hetzner Online GmbH",
    )
    assert s.formatted_tag == "🇩🇪 DE, Frankfurt | Hetzner Online GmbH (sni: yahoo.com, fp: chrome)"


def test_server_formatted_tag_geo_without_masking() -> None:
    obj = {"type": "shadowsocks", "server": "5.6.7.8", "server_port": 8388}
    s = Server(
        group_id=1,
        group_name="grp",
        name="old-name",
        engine="sing-box",
        server="5.6.7.8",
        server_port=8388,
        import_obj=obj,
        source="fresh",
        country_code="NL",
        city="Amsterdam",
        org="DigitalOcean, LLC",
    )
    assert s.formatted_tag == "🇳🇱 NL, Amsterdam | DigitalOcean, LLC"


def test_server_formatted_tag_sni_only() -> None:
    obj = {
        "type": "vless",
        "tls": {"server_name": "dl.google.com"},
    }
    s = Server(
        group_id=1,
        group_name="grp",
        name="old-name",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj=obj,
        source="fresh",
        country_code="PL",
        city="Warsaw",
        org="OVH SAS",
    )
    assert s.formatted_tag == "🇵🇱 PL, Warsaw | OVH SAS (sni: dl.google.com)"


def test_server_formatted_tag_fallback_to_name() -> None:
    obj = {"type": "direct"}
    s = Server(
        group_id=1,
        group_name="grp",
        name="MyCustomProxy",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj=obj,
        source="fresh",
    )
    assert s.formatted_tag == "MyCustomProxy"


def test_server_formatted_tag_fallback_to_host_port() -> None:
    obj = {"type": "direct"}
    s = Server(
        group_id=1,
        group_name="grp",
        name="",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj=obj,
        source="fresh",
    )
    assert s.formatted_tag == "1.1.1.1:443"


def test_write_import_file_tags(tmp_path: Path) -> None:
    import_file = tmp_path / "proxy-ok.txt"
    obj1 = {
        "type": "vless",
        "server": "1.1.1.1",
        "server_port": 443,
        "tls": {"server_name": "yahoo.com"},
    }
    obj2 = {
        "type": "vless",
        "server": "1.1.1.1",
        "server_port": 8443,
        "tls": {"server_name": "yahoo.com"},
    }
    s1 = Server(
        group_id=1,
        group_name="g",
        name="n1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj=obj1,
        source="fresh",
        result=RESULT_OK,
        country_code="DE",
        city="Frankfurt",
        org="Hetzner Online GmbH",
    )
    s2 = Server(
        group_id=1,
        group_name="g",
        name="n2",
        engine="sing-box",
        server="1.1.1.1",
        server_port=8443,
        import_obj=obj2,
        source="fresh",
        result=RESULT_OK,
        country_code="DE",
        city="Frankfurt",
        org="Hetzner Online GmbH",
    )

    sb_cnt, xr_cnt = write_import_file(None, import_file, fallback_servers=[s1, s2])
    assert sb_cnt == 2
    assert xr_cnt == 0

    lines = import_file.read_text(encoding="utf-8").strip().splitlines()
    data = json.loads(lines[0])
    assert len(data) == 2
    assert data[0]["tag"] == "🇩🇪 DE, Frankfurt | Hetzner Online GmbH (sni: yahoo.com)"
    assert data[1]["tag"] == "🇩🇪 DE, Frankfurt | Hetzner Online GmbH (sni: yahoo.com)"


def test_fetch_geo_mock_parsing() -> None:
    mock_payload = {
        "ip": "95.217.1.1",
        "success": True,
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt am Main",
        "flag": {"emoji": "🇩🇪"},
        "connection": {"org": "Hetzner Online GmbH"},
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
        country, ip_out, country_code, city, org = fetch_geo(12345)
        assert country == "🇩🇪 Germany"
        assert ip_out == "95.217.1.1"
        assert country_code == "DE"
        assert city == "Frankfurt am Main"
        assert org == "Hetzner Online GmbH"


def test_result_cache_geo_metadata_persistence(tmp_path: Path) -> None:
    cache_path = tmp_path / "results.json"
    cache = ResultCache(path=cache_path, ttl_map={RESULT_OK: 3600})

    s = Server(
        group_id=1,
        group_name="g",
        name="n",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"type": "vless"},
        source="fresh",
        result=RESULT_OK,
        country="🇩🇪 Germany",
        ip_out="1.2.3.4",
        country_code="DE",
        city="Frankfurt",
        org="Hetzner Online GmbH",
    )
    cache.update_from_server(s)
    cache.save()

    # Загружаем заново с диска
    cache_loaded = ResultCache(path=cache_path, ttl_map={RESULT_OK: 3600})
    rec = cache_loaded.get_valid_server(s)
    assert rec is not None
    assert rec.get("country_code") == "DE"
    assert rec.get("city") == "Frankfurt"
    assert rec.get("org") == "Hetzner Online GmbH"
