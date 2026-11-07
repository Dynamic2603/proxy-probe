from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from proxy_probe.cache import ResultCache
from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, Server
from proxy_probe.reporter import deduplicate_by_endpoint, write_import_file, write_report


def test_write_report(tmp_path: Path) -> None:
    rep_file = tmp_path / "report.md"
    s1 = Server(
        group_id=1,
        group_name="Group1",
        name="Server|1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"type": "vless"},
        source="fresh",
        index=1,
        result=RESULT_OK,
        country="US",
        ip_out="1.1.1.1",
        latency_ms=120,
        note="Line 1\nLine 2 | Pipe",
    )
    s2 = Server(
        group_id=1,
        group_name="Group1",
        name="Server 2",
        engine="xray",
        server="2.2.2.2",
        server_port=443,
        import_obj={"protocol": "vless"},
        source="fresh",
        index=2,
        result=RESULT_BLOCK,
        country="RU",
        ip_out="2.2.2.2",
        latency_ms=80,
        note="blocked",
    )
    servers = [s1, s2]
    warnings = ["Внимание: тестовое предупреждение"]
    write_report(
        servers=servers,
        report_path=rep_file,
        ver_sb="1.13.16",
        ver_xr="26.7.28",
        warnings=warnings,
        time_s=15.2,
        cached_counts={RESULT_OK: 1},
        cache_note="Тестовое примечание кэша",
    )

    assert rep_file.is_file()
    content = rep_file.read_text(encoding="utf-8")
    assert "# Отчёт о проверке серверов подписок" in content
    assert "sing-box v1.13.16, Xray v26.7.28" in content
    assert "- Время проверки:" in content
    assert "15" in content
    assert "Внимание: тестовое предупреждение" in content
    assert "| US |" in content
    assert "Line 1 Line 2 \\| Pipe" in content
    # Проверка, что AGY-OK идет в таблице раньше, чем AGY-BLOCK
    pos_ok = content.find("| 1 | AGY-OK |")
    pos_block = content.find("| 2 | AGY-BLOCK |")
    assert pos_ok != -1 and pos_block != -1 and pos_ok < pos_block


def test_write_report_unique_hosts_formatting(tmp_path: Path) -> None:
    rep_file = tmp_path / "report_unique.md"
    s = Server(
        group_id=1,
        group_name="Group1",
        name="s1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"type": "vless"},
        source="fresh",
        index=1,
        result=RESULT_OK,
    )
    write_report(
        servers=[s],
        report_path=rep_file,
        ver_sb="1.0.0",
        ver_xr="2.0.0",
        warnings=[],
        time_s=1.0,
        cached_counts={RESULT_OK: 10, RESULT_BLOCK: 2},
        cached_unique_hosts={
            RESULT_OK: {"1.1.1.1:443", "2.2.2.2:443"},
            RESULT_BLOCK: {"3.3.3.3:443", "4.4.4.4:443"},
        },
    )

    content = rep_file.read_text(encoding="utf-8")
    assert "AGY-OK = 10 (2 уникальных узлов)" in content
    assert "AGY-BLOCK = 2" in content
    assert "AGY-BLOCK = 2 (" not in content


def test_write_import_file_from_cache(tmp_path: Path) -> None:
    import_file = tmp_path / "proxy-ok.txt"
    cache_file = tmp_path / "results.json"
    cache = ResultCache(path=cache_file, ttl_map={RESULT_OK: 0, RESULT_DEAD: 0})
    now = _dt.datetime.now(_dt.UTC).replace(tzinfo=None)

    # 1. sing-box OK
    cache.put(
        "1.1.1.1:443",
        {
            "checked": now.isoformat(),
            "result": RESULT_OK,
            "engine": "sing-box",
            "import_obj": {"type": "vless", "server": "1.1.1.1", "server_port": 443},
        },
        now=now,
    )
    # 2. xray OK
    cache.put(
        "2.2.2.2:443",
        {
            "checked": now.isoformat(),
            "result": RESULT_OK,
            "engine": "xray",
            "import_obj": {"protocol": "vless", "settings": {}},
        },
        now=now,
    )
    # 3. DEAD (не должен попасть в import file)
    cache.put(
        "3.3.3.3:443",
        {
            "checked": now.isoformat(),
            "result": RESULT_DEAD,
            "engine": "sing-box",
            "import_obj": {"type": "vless"},
        },
        now=now,
    )

    sb_cnt, xr_cnt = write_import_file(cache, import_file)
    assert sb_cnt == 1
    assert xr_cnt == 1
    assert import_file.is_file()

    lines = import_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    sb_list = json.loads(lines[0])
    xr_list = json.loads(lines[1])
    assert isinstance(sb_list, list) and sb_list[0]["server"] == "1.1.1.1"
    assert isinstance(xr_list, list) and xr_list[0]["protocol"] == "vless"

    # Проверка создания бэкапа при перезаписи
    write_import_file(cache, import_file)
    bak_file = import_file.with_suffix(".txt.bak")
    assert bak_file.is_file()
    assert not import_file.with_suffix(".tmp").exists()


def test_write_import_file_fallback(tmp_path: Path) -> None:
    import_file = tmp_path / "fallback-ok.txt"
    s_ok = Server(
        group_id=1,
        group_name="Group1",
        name="s_ok",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"type": "shadowsocks", "server": "1.1.1.1", "server_port": 443},
        source="fresh",
        result=RESULT_OK,
    )
    s_block = Server(
        group_id=1,
        group_name="Group1",
        name="s_block",
        engine="sing-box",
        server="2.2.2.2",
        server_port=443,
        import_obj={"type": "shadowsocks", "server": "2.2.2.2", "server_port": 443},
        source="fresh",
        result=RESULT_BLOCK,
    )

    sb_cnt, xr_cnt = write_import_file(None, import_file, fallback_servers=[s_ok, s_block])
    assert sb_cnt == 1
    assert xr_cnt == 0
    content = import_file.read_text(encoding="utf-8").strip()
    data = json.loads(content)
    assert len(data) == 1
    assert data[0]["type"] == "shadowsocks"


def test_write_import_file_scoring_and_degraded_retention(tmp_path: Path) -> None:
    from proxy_probe.models import STATE_ACTIVE, STATE_DEAD, STATE_DEGRADED

    import_file = tmp_path / "test-ranked-ok.txt"
    s_top = Server(
        group_id=1,
        group_name="Group1",
        name="s_top",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"type": "vless", "server": "1.1.1.1", "server_port": 443},
        source="fresh",
        result=RESULT_OK,
        score=95,
        state=STATE_ACTIVE,
        latency_ms=100,
    )
    s_mid = Server(
        group_id=1,
        group_name="Group1",
        name="s_mid",
        engine="sing-box",
        server="2.2.2.2",
        server_port=443,
        import_obj={"type": "vless", "server": "2.2.2.2", "server_port": 443},
        source="fresh",
        result=RESULT_OK,
        score=70,
        state=STATE_ACTIVE,
        latency_ms=80,
    )
    s_degraded = Server(
        group_id=1,
        group_name="Group1",
        name="s_degraded",
        engine="sing-box",
        server="3.3.3.3",
        server_port=443,
        import_obj={"type": "vless", "server": "3.3.3.3", "server_port": 443},
        source="fresh",
        result=RESULT_DEAD,
        score=40,
        state=STATE_DEGRADED,
        consecutive_fails=1,
        latency_ms=200,
    )
    s_dead = Server(
        group_id=1,
        group_name="Group1",
        name="s_dead",
        engine="sing-box",
        server="4.4.4.4",
        server_port=443,
        import_obj={"type": "vless", "server": "4.4.4.4", "server_port": 443},
        source="fresh",
        result=RESULT_DEAD,
        score=0,
        state=STATE_DEAD,
        consecutive_fails=3,
        latency_ms=0,
    )

    sb_cnt, xr_cnt = write_import_file(None, import_file, fallback_servers=[s_degraded, s_mid, s_top, s_dead])
    assert sb_cnt == 3
    assert xr_cnt == 0

    content = import_file.read_text(encoding="utf-8").strip()
    data = json.loads(content)
    assert len(data) == 3
    assert data[0]["server"] == "1.1.1.1"
    assert data[1]["server"] == "2.2.2.2"
    assert data[2]["server"] == "3.3.3.3"


def test_write_report_includes_org_ranking(tmp_path: Path) -> None:
    rep_file = tmp_path / "report_org.md"
    s1 = Server(
        group_id=1,
        group_name="Group1",
        name="Server 1",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"type": "vless"},
        source="fresh",
        index=1,
        result=RESULT_OK,
        country="Германия",
        country_code="DE",
        ip_out="1.1.1.1",
        latency_ms=65,
        score=95,
        org="Hetzner Online GmbH",
    )
    s2 = Server(
        group_id=1,
        group_name="Group1",
        name="Server 2",
        engine="sing-box",
        server="2.2.2.2",
        server_port=443,
        import_obj={"type": "vless"},
        source="fresh",
        index=2,
        result=RESULT_OK,
        country="Нидерланды",
        country_code="NL",
        ip_out="2.2.2.2",
        latency_ms=90,
        score=75,
        org="DigitalOcean, LLC",
    )
    write_report(
        servers=[s1, s2],
        report_path=rep_file,
        ver_sb="1.0",
        ver_xr="2.0",
        warnings=[],
        time_s=10.0,
    )
    content = rep_file.read_text(encoding="utf-8")
    assert "## Рейтинг хостинг-провайдеров (Дата-центры / ISP)" in content
    assert "Hetzner Online GmbH" in content
    assert "DigitalOcean, LLC" in content
    assert "| 1 | Hetzner Online GmbH | 1 | 1 | 65 мс | 95⭐ | DE |" in content


def test_write_import_file_never_exports_agy_block(tmp_path: Path) -> None:
    from proxy_probe.models import RESULT_BLOCK, STATE_DEGRADED

    import_file = tmp_path / "test-block.txt"
    s_block = Server(
        group_id=1,
        group_name="Group1",
        name="s_block",
        engine="sing-box",
        server="5.5.5.5",
        server_port=443,
        import_obj={"type": "vless", "server": "5.5.5.5", "server_port": 443},
        source="fresh",
        result=RESULT_BLOCK,
        score=25,
        state=STATE_DEGRADED,  # Даже если бы старая запись имела DEGRADED
        consecutive_fails=1,
        latency_ms=200,
    )
    sb_cnt, xr_cnt = write_import_file(None, import_file, fallback_servers=[s_block])
    assert sb_cnt == 0
    assert xr_cnt == 0


def test_deduplicate_by_endpoint_fingerprints() -> None:
    from proxy_probe.models import STATE_ACTIVE

    def make_server(fp: str, idx: int) -> Server:
        return Server(
            group_id=1,
            group_name="G1",
            name=f"s_{fp}",
            engine="sing-box",
            server="novonl.subv.ru",
            server_port=443,
            import_obj={
                "type": "vless",
                "server": "novonl.subv.ru",
                "server_port": 443,
                "uuid": "test-uuid",
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": "golos.mail.ru",
                    "utls": {"enabled": True, "fingerprint": fp},
                    "reality": {"enabled": True, "public_key": "test-pk"},
                },
            },
            source="fresh",
            index=idx,
            result=RESULT_OK,
            score=70,
            state=STATE_ACTIVE,
            latency_ms=80,
        )

    s_qq = make_server("qq", 1)
    s_firefox = make_server("firefox", 2)
    s_chrome = make_server("chrome", 3)

    # Подаем в разном порядке, Chrome должен победить по весу отпечатка
    res1 = deduplicate_by_endpoint([s_qq, s_firefox, s_chrome])
    assert len(res1) == 1
    assert res1[0].fingerprint == "chrome"

    res2 = deduplicate_by_endpoint([s_chrome, s_qq, s_firefox])
    assert len(res2) == 1
    assert res2[0].fingerprint == "chrome"


def test_deduplicate_quality_overrides_fingerprint() -> None:
    from proxy_probe.models import STATE_ACTIVE

    # Firefox со скором 95 и меньшей задержкой должен победить Chrome со скором 70
    s_firefox = Server(
        group_id=1,
        group_name="G1",
        name="s_firefox",
        engine="sing-box",
        server="novonl.subv.ru",
        server_port=443,
        import_obj={
            "type": "vless",
            "server": "novonl.subv.ru",
            "server_port": 443,
            "uuid": "test-uuid",
            "tls": {"utls": {"fingerprint": "firefox"}},
        },
        source="fresh",
        index=1,
        result=RESULT_OK,
        score=95,
        state=STATE_ACTIVE,
        latency_ms=60,
    )
    s_chrome = Server(
        group_id=1,
        group_name="G1",
        name="s_chrome",
        engine="sing-box",
        server="novonl.subv.ru",
        server_port=443,
        import_obj={
            "type": "vless",
            "server": "novonl.subv.ru",
            "server_port": 443,
            "uuid": "test-uuid",
            "tls": {"utls": {"fingerprint": "chrome"}},
        },
        source="fresh",
        index=2,
        result=RESULT_OK,
        score=70,
        state=STATE_ACTIVE,
        latency_ms=150,
    )

    res = deduplicate_by_endpoint([s_chrome, s_firefox])
    assert len(res) == 1
    assert res[0].fingerprint == "firefox"
    assert res[0].score == 95


def test_deduplicate_active_overrides_degraded() -> None:
    from proxy_probe.models import STATE_ACTIVE, STATE_DEGRADED

    # Узел ACTIVE с отпечатком qq должен победить узел DEGRADED с chrome
    s_chrome_deg = Server(
        group_id=1,
        group_name="G1",
        name="s_chrome",
        engine="sing-box",
        server="novonl.subv.ru",
        server_port=443,
        import_obj={
            "type": "vless",
            "server": "novonl.subv.ru",
            "server_port": 443,
            "uuid": "test-uuid",
            "tls": {"utls": {"fingerprint": "chrome"}},
        },
        source="fresh",
        index=1,
        result=RESULT_DEAD,
        score=40,
        state=STATE_DEGRADED,
        consecutive_fails=1,
        latency_ms=100,
    )
    s_qq_active = Server(
        group_id=1,
        group_name="G1",
        name="s_qq",
        engine="sing-box",
        server="novonl.subv.ru",
        server_port=443,
        import_obj={
            "type": "vless",
            "server": "novonl.subv.ru",
            "server_port": 443,
            "uuid": "test-uuid",
            "tls": {"utls": {"fingerprint": "qq"}},
        },
        source="fresh",
        index=2,
        result=RESULT_OK,
        score=70,
        state=STATE_ACTIVE,
        latency_ms=80,
    )

    res = deduplicate_by_endpoint([s_chrome_deg, s_qq_active])
    assert len(res) == 1
    assert res[0].fingerprint == "qq"
    assert res[0].state == STATE_ACTIVE


def test_distinct_ports_not_deduplicated() -> None:
    from proxy_probe.models import STATE_ACTIVE

    # Узлы на одном хосте, но разных портах — это разные службы, они не должны удаляться
    s_p1 = Server(
        group_id=1,
        group_name="G1",
        name="s_5443",
        engine="sing-box",
        server="84.252.100.138",
        server_port=5443,
        import_obj={"type": "hysteria2", "server": "84.252.100.138", "server_port": 5443},
        source="fresh",
        index=1,
        result=RESULT_OK,
        score=70,
        state=STATE_ACTIVE,
        latency_ms=75,
    )
    s_p2 = Server(
        group_id=1,
        group_name="G1",
        name="s_2443",
        engine="sing-box",
        server="84.252.100.138",
        server_port=2443,
        import_obj={"type": "hysteria2", "server": "84.252.100.138", "server_port": 2443},
        source="fresh",
        index=2,
        result=RESULT_OK,
        score=70,
        state=STATE_ACTIVE,
        latency_ms=80,
    )

    res = deduplicate_by_endpoint([s_p1, s_p2])
    assert len(res) == 2
    ports = {s.server_port for s in res}
    assert ports == {5443, 2443}


def test_write_import_file_fingerprint_deduplication(tmp_path: Path) -> None:
    from proxy_probe.models import STATE_ACTIVE

    import_file = tmp_path / "dedup-ok.txt"

    def make_s(fp: str, idx: int) -> Server:
        return Server(
            group_id=1,
            group_name="G1",
            name=f"s_{fp}",
            engine="sing-box",
            server="novonl.subv.ru",
            server_port=443,
            import_obj={
                "type": "vless",
                "server": "novonl.subv.ru",
                "server_port": 443,
                "uuid": "test-uuid",
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": "golos.mail.ru",
                    "utls": {"enabled": True, "fingerprint": fp},
                    "reality": {"enabled": True, "public_key": "test-pk"},
                },
            },
            source="fresh",
            index=idx,
            result=RESULT_OK,
            score=70,
            state=STATE_ACTIVE,
            latency_ms=85,
        )

    s1 = make_s("qq", 1)
    s2 = make_s("firefox", 2)
    s3 = make_s("chrome", 3)

    sb_cnt, xr_cnt = write_import_file(None, import_file, fallback_servers=[s1, s2, s3])
    assert sb_cnt == 1
    assert xr_cnt == 0

    content = import_file.read_text(encoding="utf-8").strip()
    data = json.loads(content)
    assert len(data) == 1
    assert data[0]["tls"]["utls"]["fingerprint"] == "chrome"
    assert "fp: chrome" in data[0]["tag"]


def test_write_import_file_antidpi_detour(tmp_path: Path) -> None:
    from proxy_probe.models import STATE_ACTIVE

    import_file = tmp_path / "antidpi-ok.txt"

    s_direct = Server(
        group_id=1,
        group_name="G1",
        name="s_direct",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"type": "vless", "server": "1.1.1.1", "server_port": 443},
        source="fresh",
        index=1,
        result=RESULT_OK,
        score=70,
        state=STATE_ACTIVE,
        antidpi_strategy=None,
    )
    s_zapret = Server(
        group_id=1,
        group_name="G1",
        name="s_zapret",
        engine="sing-box",
        server="2.2.2.2",
        server_port=443,
        import_obj={"type": "vless", "server": "2.2.2.2", "server_port": 443},
        source="fresh",
        index=2,
        result=RESULT_OK,
        score=70,
        state=STATE_ACTIVE,
        antidpi_strategy=1,
    )

    sb_cnt, xr_cnt = write_import_file(None, import_file, fallback_servers=[s_direct, s_zapret])
    assert sb_cnt == 3  # 2 сервера + 1 zapret-relay outbound
    assert xr_cnt == 0

    content = import_file.read_text(encoding="utf-8").strip()
    data = json.loads(content)
    assert len(data) == 3

    # Прямой сервер
    direct_obj = next(d for d in data if d.get("server") == "1.1.1.1")
    assert "detour" not in direct_obj
    assert "[zapret" not in direct_obj.get("tag", "")

    # Реанимированный сервер
    zapret_obj = next(d for d in data if d.get("server") == "2.2.2.2")
    assert zapret_obj.get("detour") == "zapret-relay"
    assert "[zapret]" in zapret_obj.get("tag", "")

    # Объект zapret-relay
    relay_obj = next(d for d in data if d.get("tag") == "zapret-relay")
    assert relay_obj["type"] == "socks"
    assert relay_obj["server_port"] == 10850

