from __future__ import annotations

import concurrent.futures
import contextlib
import copy
import json
import logging
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..engines import (
    alloc_port,
    app_bin_dir,
    build_singbox_config,
    build_xray_config,
    clean_proxy_env,
    project_root,
    wait_port,
    xray_shorthand_to_v2ray,
)
from ..models import RESULT_BLOCK, RESULT_OK, Server
from ..prober import PREFLIGHT_URL
from .catalogue import select_mechanical_diversity_sample
from .isp import IspIdentity
from .models import CALIBRATION_LEVELS, AntidpiBenchmarkResult, AntidpiDatabase, StrategyProfile
from .relay import DEFAULT_RELAY_PORT

logger = logging.getLogger(__name__)

DEFAULT_RATINGS_FILENAME = "antidpi_ratings.json"


def default_ratings_path() -> Path:
    """Возвращает путь к локальному рейтингу стратегий (SSOT)."""
    return project_root() / "data" / DEFAULT_RATINGS_FILENAME


def load_ratings(
    path: Path | None = None,
    isp_identity: IspIdentity | None = None,
) -> AntidpiBenchmarkResult | None:
    """Загружает сохраненный локальный живой рейтинг стратегий для указанного или текущего провайдера (SSOT)."""
    p = path or default_ratings_path()
    if not p.is_file():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        db = AntidpiDatabase.from_dict(raw, current_identity=isp_identity)
        if isp_identity:
            res = db.get_or_create(isp_identity)
        elif db.last_detected_isp and db.last_detected_isp in db.providers:
            res = db.providers[db.last_detected_isp]
        elif db.providers:
            res = next(iter(db.providers.values()))
        else:
            return None
        res.sort_ratings()
        return res
    except Exception as exc:
        logger.warning("Сбой чтения рейтинга стратегий %s: %s", p, exc)
        return None


def save_ratings(
    result: AntidpiBenchmarkResult,
    path: Path | None = None,
    isp_identity: IspIdentity | None = None,
) -> None:
    """Атомарно обновляет и сохраняет живой рейтинг провайдера в многопровайдерной базе (SSOT)."""
    result.sort_ratings()
    p = path or default_ratings_path()
    p.parent.mkdir(parents=True, exist_ok=True)

    db = AntidpiDatabase()
    if p.is_file():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            db = AntidpiDatabase.from_dict(raw, current_identity=isp_identity)
        except Exception as exc:
            logger.warning("Сбой парсинга базы при сохранении: %s. Пересоздание...", exc)

    key = result.isp_key or (isp_identity.key if isp_identity else (result.isp or "default"))
    result.isp_key = key
    db.providers[key] = result
    db.last_detected_isp = key

    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(db.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
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
        return candidates[:limit] if limit > 0 else candidates[:100]

    def _is_tcp_alive(srv: Server) -> bool:
        try:
            with socket.create_connection((srv.server, srv.server_port), timeout=tcp_timeout):
                return True
        except Exception:
            return False

    effective_limit = limit if limit > 0 else 100
    chunk_size = max(min(effective_limit * 2, 200), 30)
    verified: list[Server] = []
    for idx in range(0, len(candidates), chunk_size):
        chunk = candidates[idx : idx + chunk_size]
        workers = min(len(chunk), tcp_concurrency)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(_is_tcp_alive, chunk))
        for srv, alive in zip(chunk, results, strict=True):
            if alive:
                verified.append(srv)
                if len(verified) >= effective_limit:
                    break
        if len(verified) >= effective_limit:
            break

    return verified


def calculate_strategy_score(rescued: int, total: int, avg_latency: int, failures: int = 0) -> int:
    """Вычисляет скор надежности стратегии (0..100) на выборке упавших узлов (SSOT)."""
    if total <= 0 or rescued <= 0:
        return 0
    rate = rescued / total
    base = int(rate * 70)  # до 70 баллов за долю успеха
    lat_penalty = max(0, (avg_latency - 100) // 10) if avg_latency > 0 else 0
    lat_bonus = max(0, 30 - lat_penalty)  # до 30 баллов за скорость
    penalty = failures * 25  # штраф за повторные провалы
    return max(1, min(100, base + lat_bonus - penalty))


def prepare_strategies_for_level(
    level: int,
    catalogue: list[StrategyProfile],
    living_ratings: AntidpiBenchmarkResult | None,
) -> list[StrategyProfile]:
    """Формирует адаптивную очередь стратегий для конкретного калибровочного уровня (SSOT).

    - Уровень 2: Экспресс-калибровка разнообразия механик (~20-25 стратегий).
    - Уровень 3: ТОП-стратегии живого рейтинга.
    - Уровень 4: Полный перебор всех 484 стратегий каталога.
    """
    cfg = CALIBRATION_LEVELS.get(level, CALIBRATION_LEVELS[2])
    cat_by_num = {p.number: p for p in catalogue}
    living = living_ratings.ratings if living_ratings else []

    if cfg.strategy_mode == "diversity":
        # Сначала проверенные топ-лидеры живого рейтинга (до 3), затем срез разнообразия механик (суммарно до 25)
        selected: list[StrategyProfile] = []
        seen: set[int] = set()

        for r in living:
            if r.score > 0 and r.strategy_number in cat_by_num:
                selected.append(cat_by_num[r.strategy_number])
                seen.add(r.strategy_number)
            if len(selected) >= 3:
                break

        for p in select_mechanical_diversity_sample(catalogue, limit=25):
            if p.number not in seen:
                selected.append(p)
                seen.add(p.number)
            if len(selected) >= 25:
                break

        return selected

    if cfg.strategy_mode == "top_living":
        # ТОП живого рейтинга
        selected = []
        seen = set()
        for r in living:
            if r.score > 0 and r.strategy_number in cat_by_num:
                selected.append(cat_by_num[r.strategy_number])
                seen.add(r.strategy_number)
            if len(selected) >= 15:
                break
        # Если живой рейтинг пуст или содержит мало работающих стратегий, дополняем срезом разнообразия
        if len(selected) < 15:
            for p in select_mechanical_diversity_sample(catalogue, limit=25):
                if p.number not in seen:
                    selected.append(p)
                    seen.add(p.number)
                if len(selected) >= 15:
                    break
        return selected

    # strategy_mode == "all": все 484 стратегии, причем проверенные ранее лидеры идут первыми
    selected = []
    seen = set()
    for r in living:
        if r.score > 0 and r.strategy_number in cat_by_num:
            selected.append(cat_by_num[r.strategy_number])
            seen.add(r.strategy_number)
    for p in catalogue:
        if p.number not in seen:
            selected.append(p)
            seen.add(p.number)
    return selected


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
) -> tuple[bool, int, str]:
    """Запускает изолированный прокси-туннель через zapret-relay и проверяет связность (preflight).

    Возвращает (success, latency_ms, reason).
    """
    if not srv.import_obj or not isinstance(srv.import_obj, dict):
        return False, 0, "нет import_obj"

    is_xray = srv.engine == "xray" or (not srv.engine and bool(srv.import_obj.get("protocol")))
    target_bin = (bin_dir or app_bin_dir()) / ("xray.exe" if is_xray else "sing-box.exe")
    if not target_bin.is_file():
        return False, 0, f"бинарник {target_bin.name} не найден"

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

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=clean_proxy_env(),
        )
    except OSError as exc:
        return False, 0, f"сбой запуска: {exc}"

    try:
        if proc.stdin is not None:
            proc.stdin.write(cfg_bytes)
            proc.stdin.close()

        if not wait_port(local_port, proc, timeout=1.5):
            err_snip = ""
            if proc.poll() is not None and proc.stderr:
                try:
                    raw_err = proc.stderr.read()
                    err_snip = raw_err.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            if err_snip:
                first_line = err_snip.splitlines()[0]
                return False, 0, f"движок упал ({first_line[:40]})"
            return False, 0, "таймаут старта движка"

        proxy_url = f"http://127.0.0.1:{local_port}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        req = urllib.request.Request(PREFLIGHT_URL, headers={"User-Agent": "curl/7.88.1"})
        t0 = time.time()
        try:
            with opener.open(req, timeout=timeout) as resp:
                code = getattr(resp, "status", getattr(resp, "code", 200))
                lat_ms = int((time.time() - t0) * 1000)
                if code in (200, 204):
                    return True, lat_ms, "OK"
                return False, 0, f"HTTP {code}"
        except urllib.error.HTTPError as exc:
            return False, 0, f"HTTP {exc.code}"
        except TimeoutError:
            return False, 0, f"таймаут туннеля (>{timeout}с)"
        except urllib.error.URLError as exc:
            reason_str = str(exc.reason).lower()
            if "timed out" in reason_str:
                return False, 0, f"таймаут туннеля (>{timeout}с)"
            elif "connection reset" in reason_str or "10054" in reason_str:
                return False, 0, "сброс соединения (DPI RST)"
            elif "eof" in reason_str:
                return False, 0, "обрыв соединения (EOF)"
            elif "certificate" in reason_str or "ssl" in reason_str:
                return False, 0, "ошибка TLS сертификата"
            return False, 0, f"ошибка сети ({str(exc.reason)[:30]})"
        except Exception as exc:
            return False, 0, f"сбой ({type(exc).__name__})"
    finally:
        with contextlib.suppress(Exception):
            proc.terminate()
            proc.wait(timeout=0.4)
        if proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.kill()


def format_benchmark_table(result: AntidpiBenchmarkResult) -> str:
    """Форматирует сводную таблицу живого рейтинга в читаемый консольный вид (SSOT)."""
    lines: list[str] = [
        f"### Живой рейтинг Anti-DPI стратегий (Дата: {result.tested_at[:19]}, Провайдер: {result.isp or 'Default'})",
        "",
        "| № | Стратегия | Механика | Статус | Спасено | Успех | Задержка | Скор |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for r in result.ratings:
        is_best = r.strategy_number == result.best_strategy_number
        mark = "⭐ " if is_best else ""
        pct = f"{int(r.success_rate * 100)}%"
        lat = f"{r.avg_latency_ms} мс" if r.avg_latency_ms > 0 else "—"
        name = r.strategy_name[:36] + ("..." if len(r.strategy_name) > 36 else "")
        status_b = r.status_badge
        lines.append(
            f"| {mark}S{r.strategy_number:02d} | {name} | {r.technical_family} | {status_b} | "
            f"{r.rescued_count}/{r.total_tested} | {pct} | {lat} | {r.score} |"
        )

    return "\n".join(lines)
