from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from proxy_probe.cache import ResultCache
from proxy_probe.models import (
    RESULT_OK,
    RESULT_UNKNOWN,
    Server,
    parse_quota_info,
)
from proxy_probe.prober import (
    QuotaCircuitBreaker,
    check_agy_health,
    detect_best_agy_model,
    resolve_lightest_flash_model,
    run_probe,
)


def test_parse_quota_info_with_reset_time() -> None:
    raw = (
        'error: Individual quota reached. Please upgrade your subscription to increase your limits. '
        'Resets in 50h28m27s. AGY_ERROR: {"short_error":"RESOURCE_EXHAUSTED (code 429)"}'
    )
    info = parse_quota_info(raw)
    assert info.is_exhausted is True
    assert info.reset_after == "50h28m27s"
    assert info.clean_note == "лимит квоты agy (сброс через 50h28m27s)"


def test_parse_quota_info_without_reset_time() -> None:
    raw = "error: individual quota reached for this account."
    info = parse_quota_info(raw)
    assert info.is_exhausted is True
    assert info.reset_after == ""
    assert info.clean_note == "лимит квоты agy"


def test_parse_quota_info_normal_response() -> None:
    info = parse_quota_info("OK")
    assert info.is_exhausted is False
    assert info.clean_note == ""


def test_parse_quota_info_empty() -> None:
    info = parse_quota_info("")
    assert info.is_exhausted is False


def test_resolve_lightest_flash_model_priority() -> None:
    # 1. flash-low выбирается при наличии flash-high и flash-medium
    models_v4 = ["gemini-4.0-flash-high", "gemini-4.0-flash-low", "gemini-4.0-flash-medium"]
    assert resolve_lightest_flash_model(models_v4) == "gemini-4.0-flash-low"

    # 2. flash-medium выбирается, если low нет
    models_v3 = ["gemini-3.8-flash-high", "gemini-3.8-flash-medium", "claude-sonnet-4-6"]
    assert resolve_lightest_flash_model(models_v3) == "gemini-3.8-flash-medium"

    # 3. Базовый flash
    models_generic = ["claude-sonnet", "gemini-flash", "gpt-4"]
    assert resolve_lightest_flash_model(models_generic) == "gemini-flash"

    # 4. Нет flash
    models_none = ["claude-sonnet", "gpt-4"]
    assert resolve_lightest_flash_model(models_none) is None


def test_detect_best_agy_model_from_cli() -> None:
    mock_stdout = (
        "Fetching available models...\n"
        "gemini-3.8-flash-high\tGemini 3.8 Flash (High)\n"
        "gemini-3.8-flash-medium\tGemini 3.8 Flash (Medium)\n"
        "gemini-3.8-flash-low\tGemini 3.8 Flash (Low)\n"
        "claude-sonnet-4-6\tClaude Sonnet 4.6 (Thinking)\n"
    )
    detect_best_agy_model.cache_clear()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_stdout)
        model = detect_best_agy_model("dummy_agy")
        assert model == "gemini-3.8-flash-low"


def test_detect_best_agy_model_env_override(monkeypatch) -> None:
    detect_best_agy_model.cache_clear()
    monkeypatch.setenv("AGY_MODEL", "custom-fast-model")
    assert detect_best_agy_model("dummy_agy") == "custom-fast-model"


def test_quota_circuit_breaker() -> None:
    cb = QuotaCircuitBreaker()
    assert cb.is_tripped is False
    assert cb.reason == ""

    cb.trip("лимит квоты agy (сброс через 10h)")
    assert cb.is_tripped is True
    assert cb.reason == "лимит квоты agy (сброс через 10h)"

    # Повторный trip не перетирает первую причину
    cb.trip("вторая причина")
    assert cb.reason == "лимит квоты agy (сброс через 10h)"


def test_check_agy_health_ok() -> None:
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="OK\n", stderr="")
        ok, info = check_agy_health("dummy_agy")
        assert ok is True
        assert info.is_exhausted is False


def test_check_agy_health_quota_exhausted() -> None:
    quota_err = "Individual quota reached. Resets in 24h."
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=quota_err)
        ok, info = check_agy_health("dummy_agy")
        assert ok is False
        assert info.is_exhausted is True
        assert info.reset_after == "24h"


def test_run_probe_skips_agy_when_circuit_breaker_tripped() -> None:
    cb = QuotaCircuitBreaker()
    cb.trip("лимит квоты agy")

    with (
        patch("proxy_probe.prober.build_singbox_config", return_value={}),
        patch("subprocess.Popen") as mock_popen,
        patch("proxy_probe.prober.wait_port", return_value=True),
        patch("proxy_probe.prober.preflight_check", return_value=True),
        patch("proxy_probe.prober.fetch_geo", return_value=("🇩🇪 Germany", "1.2.3.4")),
        patch("proxy_probe.prober.agy_probe") as mock_agy,
    ):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        with tempfile.TemporaryDirectory() as td:
            res = run_probe(
                engine_bin="sb.exe",
                is_xray=False,
                import_obj={},
                port=12345,
                run_root=Path(td),
                timeouts={},
                circuit_breaker=cb,
            )

        # agy_probe вообще не должен вызываться
        mock_agy.assert_not_called()
        assert res["result"] == RESULT_UNKNOWN
        assert res["country"] == "🇩🇪 Germany"
        assert res["ip_out"] == "1.2.3.4"
        assert res["note"] == "пропущено (квота agy исчерпана)"


def test_run_probe_trips_circuit_breaker_on_quota_error() -> None:
    cb = QuotaCircuitBreaker()
    quota_err = "Individual quota reached. Resets in 50h."

    with (
        patch("proxy_probe.prober.build_singbox_config", return_value={}),
        patch("subprocess.Popen") as mock_popen,
        patch("proxy_probe.prober.wait_port", return_value=True),
        patch("proxy_probe.prober.preflight_check", return_value=True),
        patch("proxy_probe.prober.fetch_geo", return_value=("🇳🇱 Netherlands", "5.6.7.8")),
        patch("proxy_probe.prober.agy_probe", return_value=(quota_err, 1)),
    ):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        with tempfile.TemporaryDirectory() as td:
            res = run_probe(
                engine_bin="sb.exe",
                is_xray=False,
                import_obj={},
                port=12346,
                run_root=Path(td),
                timeouts={},
                circuit_breaker=cb,
            )

        assert cb.is_tripped is True
        assert "лимит квоты agy" in cb.reason
        assert res["result"] == RESULT_UNKNOWN
        assert "лимит квоты agy (сброс через 50h)" in res["note"]


def test_cache_invariance_on_quota() -> None:
    with tempfile.TemporaryDirectory() as td:
        cache_file = Path(td) / "results.json"
        cache = ResultCache(cache_file)

        # 1. Закешируем валидный сервер
        ok_server = Server(
            group_id=1,
            group_name="G1",
            name="ok_node",
            engine="sing-box",
            server="9.9.9.9",
            server_port=443,
            import_obj={},
            source="fresh",
            result=RESULT_OK,
        )
        cache.update_from_server(ok_server)
        cache.save()
        assert len(cache.entries) == 1

        # 2. Попытка закешировать сервер с UNKNOWN из-за квоты
        unknown_server = Server(
            group_id=1,
            group_name="G1",
            name="quota_node",
            engine="sing-box",
            server="8.8.8.8",
            server_port=443,
            import_obj={},
            source="fresh",
            result=RESULT_UNKNOWN,
            note="лимит квоты agy (сброс через 50h)",
        )
        cache.update_from_server(unknown_server)
        cache.save()

        # UNKNOWN не должен сохраниться в кэш!
        assert len(cache.entries) == 1
        assert "8.8.8.8:443:sing-box" not in cache.entries
