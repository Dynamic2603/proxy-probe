from __future__ import annotations

import datetime as _dt
from pathlib import Path

from proxy_probe.cache import ResultCache
from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, Server


def test_cache_put_and_get(tmp_path: Path) -> None:
    cache_file = tmp_path / "test_results.json"
    cache = ResultCache(path=cache_file, ttl_map={RESULT_OK: 3600, RESULT_BLOCK: 7200, RESULT_DEAD: 1800})

    now = _dt.datetime(2026, 1, 1, 12, 0, 0)
    record = {
        "checked": now.isoformat(),
        "result": RESULT_OK,
        "country": "US",
        "ip_out": "1.1.1.1",
        "latency_ms": 100,
        "note": "OK",
    }
    cache.put("1.1.1.1:443", record)
    assert cache.is_valid("1.1.1.1:443", now=now)

    # Проверка истечения TTL
    future = now + _dt.timedelta(seconds=4000)
    assert not cache.is_valid("1.1.1.1:443", now=future)


def test_cache_priority_resolution(tmp_path: Path) -> None:
    cache_file = tmp_path / "test_prio.json"
    cache = ResultCache(path=cache_file, ttl_map={RESULT_OK: 3600, RESULT_BLOCK: 7200, RESULT_DEAD: 1800})

    now = _dt.datetime(2026, 1, 1, 12, 0, 0)
    # Сначала заносим AGY-BLOCK (приоритет 3)
    rec_block = {"checked": now.isoformat(), "result": RESULT_BLOCK}
    cache.put("host:443", rec_block, now=now)

    # Попытка понизить результат до DEAD (приоритет 1) не должна перезаписать BLOCK
    rec_dead = {"checked": now.isoformat(), "result": RESULT_DEAD}
    cache.put("host:443", rec_dead, force=False, now=now)
    assert cache.entries["host:443"]["result"] == RESULT_BLOCK

    # Попытка записать OK (приоритет 2) тоже не должна перетереть BLOCK
    rec_ok = {"checked": now.isoformat(), "result": RESULT_OK}
    cache.put("host:443", rec_ok, force=False, now=now)
    assert cache.entries["host:443"]["result"] == RESULT_BLOCK


def test_cache_equal_priority_not_overwritten(tmp_path: Path) -> None:
    cache_file = tmp_path / "test_equal_prio.json"
    cache = ResultCache(path=cache_file, ttl_map={RESULT_OK: 3600})
    now = _dt.datetime(2026, 1, 1, 12, 0, 0)

    # Первая запись с import_obj
    rec1 = {
        "checked": now.isoformat(),
        "result": RESULT_OK,
        "import_obj": {"tag": "first"},
    }
    cache.put("1.1.1.1:443", rec1, now=now)

    # Вторая запись с тем же приоритетом (RESULT_OK) не должна перезаписывать первую
    rec2 = {
        "checked": now.isoformat(),
        "result": RESULT_OK,
        "import_obj": None,
    }
    cache.put("1.1.1.1:443", rec2, force=False, now=now)
    assert cache.entries["1.1.1.1:443"]["import_obj"] == {"tag": "first"}


def test_cache_distinct_servers_same_host_port(tmp_path: Path) -> None:
    cache_file = tmp_path / "test_cdn_collision.json"
    cache = ResultCache(path=cache_file, ttl_map={RESULT_OK: 3600, RESULT_DEAD: 1800})
    now = _dt.datetime(2026, 1, 1, 12, 0, 0)

    # Две разные конфигурации на одном IP:порту (Cloudflare CDN)
    s1 = Server(
        group_id=1,
        group_name="grp",
        name="server1",
        engine="sing-box",
        server="104.16.1.1",
        server_port=443,
        import_obj={"type": "vless", "uuid": "uuid-1", "tls": {"server_name": "host1.com"}},
        source="fresh",
        result=RESULT_OK,
    )
    s2 = Server(
        group_id=1,
        group_name="grp",
        name="server2",
        engine="sing-box",
        server="104.16.1.1",
        server_port=443,
        import_obj={"type": "vless", "uuid": "uuid-2", "tls": {"server_name": "host2.com"}},
        source="fresh",
        result=RESULT_DEAD,
    )

    assert s1.host_port == s2.host_port
    assert s1.cache_key != s2.cache_key

    cache.update_from_server(s1, now=now)
    cache.update_from_server(s2, now=now)

    # Оба должны сохраниться независимо
    rec1 = cache.get_valid_server(s1, now=now)
    rec2 = cache.get_valid_server(s2, now=now)

    assert rec1 is not None and rec1["result"] == RESULT_OK
    assert rec2 is not None and rec2["result"] == RESULT_DEAD


def test_cache_key_utls_fingerprint_isolation(tmp_path: Path) -> None:
    cache_file = tmp_path / "test_utls_cache.json"
    cache = ResultCache(path=cache_file, ttl_map={RESULT_OK: 3600, RESULT_DEAD: 1800})
    now = _dt.datetime(2026, 1, 1, 12, 0, 0)

    s_chrome = Server(
        group_id=1,
        group_name="grp",
        name="server_chrome",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={
            "type": "vless",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "u1",
            "tls": {"server_name": "example.com", "utls": {"fingerprint": "chrome"}},
        },
        source="fresh",
        result=RESULT_OK,
    )
    s_firefox = Server(
        group_id=1,
        group_name="grp",
        name="server_firefox",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={
            "type": "vless",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "u1",
            "tls": {"server_name": "example.com", "utls": {"fingerprint": "firefox"}},
        },
        source="fresh",
        result=RESULT_DEAD,
    )

    assert s_chrome.cache_key != s_firefox.cache_key

    cache.update_from_server(s_chrome, now=now)
    cache.update_from_server(s_firefox, now=now)

    rec_chrome = cache.get_valid_server(s_chrome, now=now)
    rec_firefox = cache.get_valid_server(s_firefox, now=now)

    assert rec_chrome is not None and rec_chrome["result"] == RESULT_OK
    assert rec_firefox is not None and rec_firefox["result"] == RESULT_DEAD


def test_cache_key_cross_dialect_equivalence() -> None:
    s_xray = Server(
        group_id=1,
        group_name="grp",
        name="s_xray",
        engine="xray",
        server="1.2.3.4",
        server_port=443,
        import_obj={
            "protocol": "vless",
            "settings": {
                "vnext": [{"address": "1.2.3.4", "port": 443, "users": [{"id": "u1", "flow": "xtls-rprx-vision"}]}]
            },
            "streamSettings": {
                "security": "reality",
                "realitySettings": {"serverName": "sni.com", "publicKey": "pk1", "fingerprint": "chrome"},
            },
            "packet_encoding": "xudp",
        },
        source="db",
    )
    s_singbox = Server(
        group_id=1,
        group_name="grp",
        name="s_singbox",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={
            "type": "vless",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "u1",
            "flow": "xtls-rprx-vision",
            "tls": {
                "server_name": "sni.com",
                "utls": {"fingerprint": "chrome"},
                "reality": {"public_key": "pk1"},
            },
        },
        source="fresh",
    )

    assert s_xray.config_identity == s_singbox.config_identity
    # Хэш конфигурации (SSOT) совпадает между диалектами Xray и sing-box
    assert s_xray.cache_key.rsplit(":", 1)[1] == s_singbox.cache_key.rsplit(":", 1)[1]

    # При совпадении движка cache_key совпадает полностью
    s_xray_as_singbox = Server(
        group_id=s_xray.group_id,
        group_name=s_xray.group_name,
        name=s_xray.name,
        engine="sing-box",
        server=s_xray.server,
        server_port=s_xray.server_port,
        import_obj=s_xray.import_obj,
        source=s_xray.source,
    )
    assert s_xray_as_singbox.cache_key == s_singbox.cache_key
