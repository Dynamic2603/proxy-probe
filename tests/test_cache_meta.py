from __future__ import annotations

import json
import time
import unittest.mock as mock
from pathlib import Path

from proxy_probe.cache import ResultCache
from proxy_probe.prober import detect_best_agy_model


def test_cache_meta_storage_and_compact_save(tmp_path: Path) -> None:
    cache_file = tmp_path / "test_meta.json"
    cache = ResultCache(path=cache_file)

    assert cache.meta == {}
    assert cache.get_meta("key") is None
    assert cache.get_meta("key", "default") == "default"

    cache.set_meta("best_model", "gemini-3.8-flash-low")
    cache.set_meta("number", 42)
    assert cache.get_meta("best_model") == "gemini-3.8-flash-low"

    cache.save()

    # Проверка, что файл сохранён в компактном формате (без лишних пробелов и переносов строк внутри)
    raw_text = cache_file.read_text(encoding="utf-8")
    assert "\n  " not in raw_text  # нет indent=1/indent=2
    parsed = json.loads(raw_text)
    assert parsed["meta"]["best_model"] == "gemini-3.8-flash-low"
    assert parsed["meta"]["number"] == 42

    # Перезагрузка в новый экземпляр
    cache2 = ResultCache(path=cache_file)
    assert cache2.get_meta("best_model") == "gemini-3.8-flash-low"
    assert cache2.get_meta("number") == 42


def test_cache_meta_backward_compatibility(tmp_path: Path) -> None:
    # Имитация старого формата кэша (версия без секции meta)
    cache_file = tmp_path / "old_cache.json"
    old_payload = {
        "version": 1,
        "servers": {
            "1.2.3.4:443:sing-box:abcdef": {
                "result": "AGY-OK",
                "score": 70,
            }
        },
    }
    cache_file.write_text(json.dumps(old_payload), encoding="utf-8")

    cache = ResultCache(path=cache_file)
    assert cache.meta == {}
    assert "1.2.3.4:443:sing-box:abcdef" in cache.entries


def test_detect_best_agy_model_with_cache(tmp_path: Path) -> None:
    cache_file = tmp_path / "test_model_cache.json"
    cache = ResultCache(path=cache_file)

    # 1. При свежем кэше вызов CLI 'agy models' не производится
    cache.set_meta("best_model", "cached-flash-model")
    cache.set_meta("best_model_saved_at", time.time())

    with mock.patch("subprocess.run") as mock_sub:
        model = detect_best_agy_model("agy", cache=cache)
        assert model == "cached-flash-model"
        mock_sub.assert_not_called()

    # 2. Если кэш устарел (> 24 часов) — происходит вызов subprocess
    cache.set_meta("best_model_saved_at", time.time() - 90000)
    fake_proc = mock.Mock()
    fake_proc.returncode = 0
    fake_proc.stdout = "gemini-3.8-flash-low\ngemini-2.5-pro\n"

    with mock.patch("subprocess.run", return_value=fake_proc) as mock_sub:
        detect_best_agy_model.cache_clear()
        model = detect_best_agy_model("agy", cache=cache)
        assert model == "gemini-3.8-flash-low"
        mock_sub.assert_called_once()
        assert cache.get_meta("best_model") == "gemini-3.8-flash-low"
