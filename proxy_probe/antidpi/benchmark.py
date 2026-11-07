from __future__ import annotations

import concurrent.futures
import contextlib
import copy
import json
import logging
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from ..engines import (
    alloc_port,
    app_bin_dir,
    build_singbox_config,
    build_xray_config,
    project_root,
    wait_port,
    xray_shorthand_to_v2ray,
)
from ..models import RESULT_BLOCK, RESULT_OK, Server
from ..prober import preflight_check
from .models import AntidpiBenchmarkResult

logger = logging.getLogger(__name__)

DEFAULT_RATINGS_FILENAME = "antidpi_ratings.json"
DEFAULT_RELAY_PORT = 10850


def default_ratings_path() -> Path:
    """Возвращает путь к локальному рейтингу стратегий (SSOT)."""
    return project_root() / "data" / DEFAULT_RATINGS_FILENAME


def load_ratings(path: Path | None = None) -> AntidpiBenchmarkResult | None:
    """Загружает сохраненный локальный рейтинг стратегий."""
    p = path or default_ratings_path()
    if not p.is_file():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return AntidpiBenchmarkResult.from_dict(raw)
    except Exception as exc:
        logger.warning("Сбой чтения рейтинга стратегий %s: %s", p, exc)
        return None


def save_ratings(result: AntidpiBenchmarkResult, path: Path | None = None) -> None:
    """Атомарно сохраняет результаты бенчмарка в JSON-файл (SSOT)."""
    p = path or default_ratings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def select_dead_servers(
    servers: list[Server],
    limit: int = 15,
    verify_tcp: bool = False,
    tcp_timeout: float = 0.35,
    tcp_concurrency: int = 30,
) -> list[Server]:
    """Отбирает уникальные по хосту серверы, упавшие по сетевым причинам (L4/TLS).

    Строго исключает геоблоки Google (RESULT_BLOCK), так как Zapret бессилен против санкций сервиса.
    Исключает чистые UDP-протоколы (hysteria2/wireguard), для которых Winws TCP-стратегии неприменимы.
    Приоритет отдается узлам с признаками блокировки DPI (падение туннеля, preflight drop, DEGRADED).
    При verify_tcp=True быстро отсекает хосты с закрытыми/неотвечающими портами на L4.
    """
    candidates: list[Server] = []
    seen_hosts: set[str] = set()

    for s in servers:
        if s.result == RESULT_BLOCK or s.result == RESULT_OK:
            continue
        if not s.is_tcp_protocol:
            continue
        # Отбираем только узлы с признаками сетевого таймаута / drop
        if not s.server or s.server in seen_hosts:
            continue
        if not s.import_obj or not isinstance(s.import_obj, dict):
            continue

        seen_hosts.add(s.server)
        candidates.append(s)

    def _rank(srv: Server) -> tuple[int, int]:
        note = (srv.note or "").lower()
        if "tcp:" in note or "хост не отвечает" in note or "dns" in note:
            # Узлы с подтвержденным падением на L4 имеют минимальный приоритет
            pri = 9
        elif "preflight" in note or "туннель" in note or "reset" in note or "handshake" in note:
            pri = 0
        elif srv.state == "DEGRADED":
            pri = 1
        else:
            pri = 2
        return (pri, srv.index)

    candidates.sort(key=_rank)

    if not verify_tcp or not candidates:
        return candidates[:limit]

    def _is_tcp_alive(srv: Server) -> bool:
        try:
            with socket.create_connection((srv.server, srv.server_port), timeout=tcp_timeout):
                return True
        except Exception:
            return False

    chunk_size = max(limit * 2, 30)
    verified: list[Server] = []
    for idx in range(0, min(len(candidates), 300), chunk_size):
        chunk = candidates[idx : idx + chunk_size]
        workers = min(len(chunk), tcp_concurrency)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(_is_tcp_alive, chunk))
        for srv, alive in zip(chunk, results, strict=True):
            if alive:
                verified.append(srv)
                if len(verified) >= limit:
                    break
        if len(verified) >= limit:
            break

    return verified


def calculate_strategy_score(rescued: int, total: int, avg_latency: int) -> int:
    """Вычисляет скор надежности стратегии (0..100) на выборке упавших узлов (SSOT)."""
    if total <= 0 or rescued <= 0:
        return 0
    rate = rescued / total
    base = int(rate * 80)
    lat_penalty = max(0, (avg_latency - 100) // 10) if avg_latency > 0 else 0
    lat_bonus = max(0, 20 - lat_penalty)
    return max(1, min(100, base + lat_bonus))


def apply_relay_detour(
    outbound: dict[str, Any],
    is_xray: bool,
    relay_tag: str = "zapret-relay",
) -> dict[str, Any]:
    """Глубоко встраивает маршрутизацию через zapret-relay без повреждения других настроек."""
    patched = copy.deepcopy(outbound)
    if is_xray:
        ss = patched.setdefault("streamSettings", {})
        sockopt = ss.setdefault("sockopt", {})
        sockopt["dialerProxy"] = relay_tag
    else:
        patched["detour"] = relay_tag
    return patched


def build_relay_outbound(
    is_xray: bool,
    relay_port: int,
    relay_host: str = "127.0.0.1",
    relay_tag: str = "zapret-relay",
) -> dict[str, Any]:
    """Создает объект outbound для локального SOCKS5-релея (SSOT)."""
    if is_xray:
        return {
            "protocol": "socks",
            "tag": relay_tag,
            "settings": {"servers": [{"address": relay_host, "port": relay_port}]},
        }
    return {
        "type": "socks",
        "tag": relay_tag,
        "server": relay_host,
        "server_port": relay_port,
    }


def build_relay_detour(
    is_xray: bool,
    relay_port: int,
    relay_host: str = "127.0.0.1",
    relay_tag: str = "zapret-relay",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Создает модификацию конфига outbound и объект relay-прокси для sing-box или Xray (SSOT)."""
    detour_patch = (
        {"streamSettings": {"sockopt": {"dialerProxy": relay_tag}}}
        if is_xray
        else {"detour": relay_tag}
    )
    relay_outbound = build_relay_outbound(
        is_xray=is_xray,
        relay_port=relay_port,
        relay_host=relay_host,
        relay_tag=relay_tag,
    )
    return detour_patch, relay_outbound


def probe_proxy_tunnel(
    srv: Server,
    relay_port: int = DEFAULT_RELAY_PORT,
    timeout: float = 2.0,
    bin_dir: Path | None = None,
) -> tuple[bool, int]:
    """Запускает изолированный прокси-туннель через zapret-relay и проверяет связность (preflight).

    Возвращает (success, latency_ms).
    """
    if not srv.import_obj or not isinstance(srv.import_obj, dict):
        return False, 0

    is_xray = srv.engine == "xray" or (not srv.engine and bool(srv.import_obj.get("protocol")))
    target_bin = (bin_dir or app_bin_dir()) / ("xray.exe" if is_xray else "sing-box.exe")
    if not target_bin.is_file():
        return False, 0

    local_port = alloc_port()
    relay_outbound = build_relay_outbound(is_xray, relay_port)
    test_import_obj = apply_relay_detour(srv.import_obj, is_xray)

    if is_xray:
        test_out = xray_shorthand_to_v2ray(test_import_obj)
        ss = test_out.setdefault("streamSettings", {})
        sockopt = ss.setdefault("sockopt", {})
        sockopt["dialerProxy"] = "zapret-relay"
        cfg = build_xray_config(test_out, local_port, extra_outbounds=[relay_outbound])
        cmd = [str(target_bin), "run", "-c", "stdin:"]
    else:
        cfg = build_singbox_config(test_import_obj, local_port, extra_outbounds=[relay_outbound])
        cmd = [str(target_bin), "run", "-c", "stdin"]

    cfg_bytes = json.dumps(cfg, ensure_ascii=False).encode("utf-8")
    clean_env = {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
    }

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=clean_env,
        )
    except OSError:
        return False, 0

    try:
        if proc.stdin is not None:
            proc.stdin.write(cfg_bytes)
            proc.stdin.close()

        if not wait_port(local_port, proc, timeout=1.5):
            return False, 0

        t0 = time.time()
        ok = preflight_check(local_port, timeout=timeout)
        latency_ms = int((time.time() - t0) * 1000) if ok else 0
        return ok, latency_ms
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            proc.wait(timeout=0.4)
        if proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.kill()


def format_benchmark_table(result: AntidpiBenchmarkResult) -> str:
    """Форматирует сводную таблицу результатов бенчмарка в читаемый Markdown/консольный вид."""
    lines: list[str] = [
        f"### Рейтинг Anti-DPI стратегий (Дата: {result.tested_at[:19]}, Провайдер: {result.isp or 'Default'})",
        "",
        "| № | Стратегия | Семейство | Спасено | Успех | Задержка | Скор |",
        "|---|---|---|---|---|---|---|",
    ]

    for r in result.ratings:
        is_best = r.strategy_number == result.best_strategy_number
        mark = "⭐ " if is_best else ""
        pct = f"{int(r.success_rate * 100)}%"
        lat = f"{r.avg_latency_ms} мс" if r.avg_latency_ms > 0 else "—"
        name = r.strategy_name[:40] + ("..." if len(r.strategy_name) > 40 else "")
        lines.append(
            f"| {mark}S{r.strategy_number:02d} | {name} | {r.family_name} | "
            f"{r.rescued_count}/{r.total_tested} | {pct} | {lat} | {r.score} |"
        )

    return "\n".join(lines)
