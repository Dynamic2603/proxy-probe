from __future__ import annotations

import datetime as _dt
from pathlib import Path

from proxy_probe.cache import ResultCache
from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK


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
