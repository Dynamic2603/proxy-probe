from __future__ import annotations

from pathlib import Path
from typing import Any

from proxy_probe.cli import RuntimeContext


def make_runtime_context(**overrides: Any) -> RuntimeContext:
    """Создаёт типизированный экземпляр RuntimeContext с тестовыми значениями по умолчанию."""
    defaults: dict[str, Any] = {
        "agy_bin": "fake_agy",
        "agy_model": None,
        "agy_concurrency": 2,
        "initial_circuit_breaker": None,
        "cache": None,
        "cache_path": Path("fake_results.json"),
        "ttl_map": {},
        "report_path": Path("fake_report.md"),
        "import_path": Path("fake_proxy-ok.txt"),
        "ver_sb": "1.0",
        "ver_xr": "1.0",
        "sb_exe": Path("fake_sb"),
        "xr_exe": Path("fake_xr"),
        "use_tcp_prefilter": False,
        "tcp_timeout": 1.0,
        "tcp_concurrency": 10,
        "preflight_timeout": 2.5,
        "use_rep_filter": True,
        "use_geo_precheck": True,
        "geo_precheck_timeout": 2.5,
        "check_web": False,
        "table_mode": "ok",
        "table_limit": 20,
        "gist_id": None,
        "antidpi": False,
        "antidpi_strategy": None,
        "antidpi_port": 10850,
        "antidpi_limit": 0,
        "isp": None,
        "no_elevate": False,
        "jobs": 16,
    }
    defaults.update(overrides)
    return RuntimeContext(**defaults)
