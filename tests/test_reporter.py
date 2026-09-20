from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from proxy_probe.cache import ResultCache
from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, Server
from proxy_probe.reporter import write_import_file, write_report


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
    assert "Server\\|1" in content
    assert "Line 1 Line 2 \\| Pipe" in content
    # Проверка, что AGY-OK идет в таблице раньше, чем AGY-BLOCK
    pos_ok = content.find("| 1 | AGY-OK |")
    pos_block = content.find("| 2 | AGY-BLOCK |")
    assert pos_ok != -1 and pos_block != -1 and pos_ok < pos_block


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
