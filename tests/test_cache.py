from __future__ import annotations

import datetime as _dt
import json
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


def test_calculate_score() -> None:
    from proxy_probe.cache import calculate_score

    # Базовый скор для первого успеха с хорошим пингом
    assert calculate_score(ok_count=1, consecutive_fails=0, latency_ms=100) == 70

    # Накопление истории (бонус +3 за каждый успех)
    assert calculate_score(ok_count=4, consecutive_fails=0, latency_ms=100) == 79

    # Максимальный бонус истории (+20 при 8+ успехах)
    assert calculate_score(ok_count=10, consecutive_fails=0, latency_ms=80) == 90

    # Штраф за задержку (150мс база, 350мс -> -10 очков)
    assert calculate_score(ok_count=1, consecutive_fails=0, latency_ms=350) == 60

    # Штраф за сбои (-30 за каждый сбой подряд)
    assert calculate_score(ok_count=5, consecutive_fails=1, latency_ms=100) == 52  # 70 + 12 - 30 = 52
    assert calculate_score(ok_count=5, consecutive_fails=2, latency_ms=100) == 22  # 70 + 12 - 60 = 22

    # При исчерпании лимита (3 сбоя) скор обнуляется
    assert calculate_score(ok_count=5, consecutive_fails=3, latency_ms=100) == 0

    # Без единого успеха скор 0
    assert calculate_score(ok_count=0, consecutive_fails=0, latency_ms=100) == 0


def test_resolve_lifecycle() -> None:
    from proxy_probe.cache import resolve_lifecycle
    from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, STATE_ACTIVE, STATE_DEAD, STATE_DEGRADED

    # Первый успех
    st, fails, oks = resolve_lifecycle(ok_count=0, consecutive_fails=0, probe_result=RESULT_OK)
    assert st == STATE_ACTIVE and fails == 0 and oks == 1

    # Первый сбой для ранее работавшего узла -> переходит в DEGRADED (1/3)
    st, fails, oks = resolve_lifecycle(ok_count=1, consecutive_fails=0, probe_result=RESULT_DEAD)
    assert st == STATE_DEGRADED and fails == 1 and oks == 1

    # Второй сбой подряд -> остается в DEGRADED (2/3)
    st, fails, oks = resolve_lifecycle(ok_count=1, consecutive_fails=1, probe_result=RESULT_BLOCK)
    assert st == STATE_DEGRADED and fails == 2 and oks == 1

    # Третий сбой подряд -> исчерпание лимита, переходит в DEAD (3/3)
    st, fails, oks = resolve_lifecycle(ok_count=1, consecutive_fails=2, probe_result=RESULT_DEAD)
    assert st == STATE_DEAD and fails == 3 and oks == 1

    # Реабилитация из DEGRADED при успехе -> сброс сбоев в 0, возврат в ACTIVE
    st, fails, oks = resolve_lifecycle(ok_count=1, consecutive_fails=2, probe_result=RESULT_OK)
    assert st == STATE_ACTIVE and fails == 0 and oks == 2

    # Узел, который никогда не работал (ok_count=0), при первом же сбое сразу DEAD
    st, fails, oks = resolve_lifecycle(ok_count=0, consecutive_fails=0, probe_result=RESULT_DEAD)
    assert st == STATE_DEAD and fails == 1 and oks == 0


def test_cache_grace_period_and_scoring_lifecycle(tmp_path: Path) -> None:
    from proxy_probe.cache import ResultCache
    from proxy_probe.models import RESULT_DEAD, RESULT_OK, STATE_ACTIVE, STATE_DEAD, STATE_DEGRADED

    cache_file = tmp_path / "test_lifecycle.json"
    cache = ResultCache(path=cache_file, ttl_map={RESULT_OK: 3600, RESULT_DEAD: 1800})

    s = Server(
        group_id=1,
        group_name="grp",
        name="server1",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"type": "vless", "server": "1.2.3.4", "server_port": 443},
        source="fresh",
    )

    # 1. Первый запуск: AGY-OK -> Score 70, State ACTIVE
    s.result = RESULT_OK
    s.latency_ms = 120
    cache.update_from_server(s)
    rec1 = cache.entries[s.cache_key]
    assert rec1["state"] == STATE_ACTIVE
    assert rec1["score"] == 70
    assert rec1["consecutive_fails"] == 0
    assert rec1["ok_count"] == 1
    assert rec1["import_obj"] is not None

    # 2. Второй запуск: временный сетевой сбой DEAD -> Grace Period (1/3), DEGRADED
    s.result = RESULT_DEAD
    s.latency_ms = 120
    cache.update_from_server(s)
    rec2 = cache.entries[s.cache_key]
    assert rec2["state"] == STATE_DEGRADED
    assert rec2["consecutive_fails"] == 1
    assert rec2["score"] == 40  # 70 - 30 = 40
    # import_obj сохранен для удержания в proxy-ok.txt!
    assert rec2["import_obj"] is not None

    # 3. Третий запуск: повторный сбой DEAD -> Grace Period (2/3), DEGRADED
    s.result = RESULT_DEAD
    cache.update_from_server(s)
    rec3 = cache.entries[s.cache_key]
    assert rec3["state"] == STATE_DEGRADED
    assert rec3["consecutive_fails"] == 2
    assert rec3["score"] == 10  # 70 - 60 = 10
    assert rec3["import_obj"] is not None

    # 4. Четвертый запуск: реабилитация AGY-OK -> сброс сбоев, возврат в ACTIVE
    s.result = RESULT_OK
    s.latency_ms = 90
    cache.update_from_server(s)
    rec4 = cache.entries[s.cache_key]
    assert rec4["state"] == STATE_ACTIVE
    assert rec4["consecutive_fails"] == 0
    assert rec4["ok_count"] == 2
    assert rec4["score"] == 73  # 70 + 3 = 73

    # 5. Три сбоя подряд -> окончательный перевод в DEAD
    s.result = RESULT_DEAD
    cache.update_from_server(s)  # fail 1
    assert cache.entries[s.cache_key]["state"] == STATE_DEGRADED

    cache.update_from_server(s)  # fail 2
    assert cache.entries[s.cache_key]["state"] == STATE_DEGRADED

    cache.update_from_server(s)  # fail 3 -> исчерпание лимита
    rec_dead = cache.entries[s.cache_key]
    assert rec_dead["state"] == STATE_DEAD
    assert rec_dead["score"] == 0
    assert rec_dead["consecutive_fails"] == 3


def test_cache_lazy_normalization_backward_compatibility(tmp_path: Path) -> None:
    from proxy_probe.cache import ResultCache
    from proxy_probe.models import RESULT_DEAD, RESULT_OK, STATE_ACTIVE, STATE_DEAD

    # Симуляция старого results.json без полей score и state
    old_data = {
        "version": 1,
        "servers": {
            "1.1.1.1:443": {
                "checked": "2026-10-20T12:00:00",
                "result": RESULT_OK,
                "country": "Germany",
                "latency_ms": 100,
            },
            "2.2.2.2:443": {
                "checked": "2026-10-20T12:00:00",
                "result": RESULT_DEAD,
                "latency_ms": 500,
            },
        },
    }
    cache_file = tmp_path / "old_results.json"
    cache_file.write_text(json.dumps(old_data), encoding="utf-8")

    cache = ResultCache(path=cache_file)
    rec_ok = cache.entries["1.1.1.1:443"]
    assert rec_ok["state"] == STATE_ACTIVE
    assert rec_ok["score"] == 70
    assert rec_ok["consecutive_fails"] == 0
    assert rec_ok["ok_count"] == 1
    assert rec_ok["first_seen"] == "2026-10-20T12:00:00"

    rec_dead = cache.entries["2.2.2.2:443"]
    assert rec_dead["state"] == STATE_DEAD
    assert rec_dead["score"] == 0

