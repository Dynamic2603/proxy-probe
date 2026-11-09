#!/usr/bin/env python3
"""Интерфейс командной строки proxy-probe (pxp).

Проверка серверов подписок на пригодность к работе с целевыми утилитами (agy / Gemini API).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import copy
import dataclasses
import os
import shutil
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from tqdm import tqdm

from .antidpi.elevation import disable_quick_edit_mode
from .antidpi.runner import (
    print_relay_status,
    run_calibration,
    run_catalogue_update,
    run_relay_service,
    stop_relay_service,
)
from .antidpi.stage2 import execute_antidpi_stage, run_stage2_worker
from .cache import ResultCache, default_cache_path
from .engines import alloc_port, ensure_binaries
from .gist import mask_gist_id, resolve_gist_id, sync_file_to_gist
from .models import (
    DEFAULT_TTLS,
    RESULT_DEAD,
    RESULT_OK,
    RESULT_UNKNOWN,
    STATE_ACTIVE,
    STATE_DEAD,
    STATE_DEGRADED,
    Server,
)
from .orchestrator import (
    dedupe_servers,
    gather_sources,
    interactive_select,
    pause_on_exit,
)
from .prober import (
    AGY_PRINT_TIMEOUT_DEFAULT,
    ProcessRegistry,
    QuotaCircuitBreaker,
    batch_probe_tcp,
    check_agy_health,
    detect_best_agy_model,
    enrich_cached_ok_geo,
    get_default_agy_bin,
    run_probe,
)
from .reporter import write_import_file, write_report
from .stats import compute_summary_stats
from .throne import (
    default_throne_dir,
    detect_throne_versions,
    read_groups,
    read_profiles_for_group,
    set_throne_dir,
)
from .ui import (
    console,
    format_cached_counters,
    format_live_counters,
    print_results_table,
    print_summary_panel,
    select_calibration_level_interactive,
    select_main_action_interactive,
)

__all__ = ["main"]


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pxp",
        description="proxy-probe (pxp): проверка серверов подписок на работу с целевыми утилитами (agy/Gemini)",
    )
    cpu_n = os.cpu_count() or 4
    default_jobs = min(32, max(8, cpu_n * 2))
    ap.add_argument(
        "--jobs",
        type=int,
        default=default_jobs,
        help=f"число параллельных проверок (по умолчанию {default_jobs})",
    )
    ap.add_argument("--subset", type=int, default=0, help="проверить только первые N серверов (0 = все)")
    ap.add_argument("--group", type=int, action="append", default=[], help="id группы (можно несколько; иначе — выбор)")
    ap.add_argument("--no-fetch", action="store_true", help="не обновлять подписки, использовать данные из БД Throne")
    ap.add_argument("--timeout", type=float, default=35.0, help="секунд таймаут на одну проверку (по умолчанию 35)")
    ap.add_argument(
        "--agy-bin",
        type=str,
        default=None,
        help="путь к agy.exe (CLI Antigravity, по умолчанию поиск в PATH и AppData)",
    )
    ap.add_argument(
        "--agy-model",
        type=str,
        default=None,
        help="модель для agy (по умолчанию автоопределение легчайшей Flash-модели через 'agy models')",
    )
    ap.add_argument(
        "--agy-concurrency",
        type=int,
        default=2,
        help="максимальное число одновременных процессов agy (по умолчанию 2)",
    )
    ap.add_argument(
        "--skip-precheck",
        action="store_true",
        help="пропустить предстартовую проверку доступности квоты agy",
    )
    ap.add_argument(
        "--print-timeout", type=str, default=AGY_PRINT_TIMEOUT_DEFAULT, help="--print-timeout для agy (например 45s)"
    )
    ap.add_argument("--out", type=Path, default=None, help="каталог для отчётов (по умолчанию каталог запуска)")
    ap.add_argument("--cache", type=Path, default=None, help="путь к кэшу результатов (по умолчанию results.json)")
    ap.add_argument(
        "--ttl-ok",
        type=int,
        default=DEFAULT_TTLS["AGY-OK"],
        help=f"TTL кэша AGY-OK (сек, default {DEFAULT_TTLS['AGY-OK'] // 3600}ч; 0 = вечно)",
    )
    ap.add_argument(
        "--ttl-blocked",
        type=int,
        default=DEFAULT_TTLS["AGY-BLOCK"],
        help=f"TTL кэша AGY-BLOCK (сек, default {DEFAULT_TTLS['AGY-BLOCK'] // 86400}д; 0 = вечно)",
    )
    ap.add_argument(
        "--ttl-dead",
        type=int,
        default=DEFAULT_TTLS["DEAD"],
        help=f"TTL кэша DEAD (сек, default {DEFAULT_TTLS['DEAD'] // 3600}ч; 0 = вечно)",
    )
    ap.add_argument(
        "--throne-dir",
        type=Path,
        default=None,
        help="путь к каталогу Throne (по умолчанию автоопределение: %%LOCALAPPDATA%%\\Throne или %%APPDATA%%\\Throne)",
    )
    ap.add_argument("--no-cache", action="store_true", help="не читать и не сохранять кэш результатов")
    ap.add_argument("--refresh-cache", action="store_true", help="принудительно перепроверить серверы из кэша")
    ap.add_argument(
        "--refresh-dead",
        action="store_true",
        help="принудительно перепроверить серверы со статусом DEAD из кэша (сохраняя AGY-OK и AGY-BLOCK)",
    )
    ap.add_argument(
        "--clear-dead",
        action="store_true",
        help="удалить из кэша results.json все записи со статусом DEAD и сразу завершить работу",
    )
    ap.add_argument(
        "--filter-insecure",
        action="store_true",
        default=None,
        help="принудительно фильтровать небезопасные серверы (allowInsecure TLS, слабые шифры, открытый трафик)",
    )
    ap.add_argument(
        "--allow-insecure",
        action="store_true",
        default=False,
        help="разрешить небезопасные серверы (отключить фильтрацию, даже если она включена в Throne)",
    )
    ap.add_argument(
        "--no-tcp-prefilter",
        action="store_true",
        help="отключить быстрый предварительный L4 TCP-фильтр (Stage 0)",
    )
    ap.add_argument(
        "--tcp-timeout",
        type=float,
        default=1.5,
        help="таймаут L4 TCP-хэндшейка для Stage 0 (сек, по умолчанию 1.5)",
    )
    ap.add_argument(
        "--tcp-concurrency",
        type=int,
        default=200,
        help="число параллельных потоков L4 TCP-фильтра (по умолчанию 200)",
    )
    ap.add_argument(
        "--preflight-timeout",
        type=float,
        default=2.5,
        help="таймаут HTTP preflight-проверки туннеля (сек, по умолчанию 2.5)",
    )
    ap.add_argument(
        "--no-rep-filter",
        action="store_true",
        help="отключить предварительную фильтрацию хостов по представителям эндпоинтов",
    )
    ap.add_argument(
        "--no-geo-precheck",
        action="store_true",
        help="отключить быстрый предварительный отсев геоблоков Google до запуска agy (Geo Precheck)",
    )
    ap.add_argument(
        "--geo-precheck-timeout",
        type=float,
        default=2.5,
        help="таймаут быстрого предфильтра геоблока в секундах (по умолчанию 2.5)",
    )
    ap.add_argument(
        "--check-web",
        action="store_true",
        help="дополнительно проверять доступность gemini.google.com и выявлять капчу",
    )
    ap.add_argument(
        "--table",
        choices=["ok", "all", "none"],
        default="ok",
        help="какие серверы выводить в итоговую таблицу консоли (ok - только рабочие, all - все, none - скрыть)",
    )
    ap.add_argument(
        "--table-limit",
        type=int,
        default=20,
        help="максимальное число строк в итоговой таблице консоли (0 = без ограничений, по умолчанию 20)",
    )
    ap.add_argument(
        "--gist",
        dest="gist_id",
        metavar="ID",
        default=None,
        help="ID GitHub Secret Gist для автоматической публикации proxy-ok.txt (или переменная PROXY_PROBE_GIST_ID)",
    )
    ap.add_argument(
        "--antidpi",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "оживлять заблокированные серверы (DEAD) через изолированный Zapret2 SOCKS5-релей "
            "(по умолчанию включено, отключение: --no-antidpi)"
        ),
    )
    ap.add_argument(
        "--antidpi-strategy",
        type=int,
        default=None,
        help="номер стратегии Zapret2 для релея (по умолчанию лучшая из локального рейтинга)",
    )
    ap.add_argument(
        "--antidpi-port",
        type=int,
        default=10850,
        help="порт локального изолированного SOCKS5-релея (по умолчанию 10850)",
    )
    ap.add_argument(
        "--antidpi-limit",
        type=int,
        default=0,
        help="максимум DEAD-серверов для проверки в Stage 2 или калибровке (0 = по умолчанию)",
    )
    ap.add_argument(
        "--antidpi-top",
        type=int,
        default=None,
        help="ограничить количество проверяемых стратегий при калибровке",
    )
    ap.add_argument(
        "--calibrate",
        type=int,
        choices=[2, 3, 4],
        default=None,
        help="запустить калибровку стратегий Anti-DPI (уровень 2, 3 или 4)",
    )
    ap.add_argument(
        "--serve",
        action="store_true",
        help="запустить постоянный локальный SOCKS5-релей Zapret2",
    )
    ap.add_argument(
        "--detach",
        action="store_true",
        help="запустить релей Zapret2 в фоновом режиме (detached)",
    )
    ap.add_argument(
        "--stop-relay",
        action="store_true",
        help="остановить работающий фоновый релей Zapret2 и выгрузить WinDivert",
    )
    ap.add_argument(
        "--status-relay",
        action="store_true",
        help="показать текущий статус фонового релея Zapret2",
    )
    ap.add_argument(
        "--update-catalogue",
        action="store_true",
        help="обновить каталог 484 стратегий Anti-DPI из upstream",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="подробная детализация причин сбоев при калибровке",
    )
    ap.add_argument(
        "--profile",
        action="store_true",
        help="включить профилирование cProfile при калибровке",
    )
    ap.add_argument(
        "--isp",
        type=str,
        default=None,
        help="принудительно указать имя/ASN провайдера (по умолчанию автодетект Ingress сети)",
    )
    ap.add_argument(
        "--no-elevate",
        action="store_true",
        help="не запрашивать повышение прав через UAC автоматически",
    )
    ap.add_argument("--stage2-worker", type=str, default=None, help=argparse.SUPPRESS)
    ap.add_argument("--log-output", type=str, default=None, help=argparse.SUPPRESS)
    ap.add_argument("--no-pause", action="store_true", help="не ждать нажатия Enter перед выходом")
    return ap


def _resolve_agy_bin(args_agy_bin: str | None) -> str:
    agy_raw = args_agy_bin or os.environ.get("AGY_BIN") or get_default_agy_bin()
    agy_candidate = Path(agy_raw)
    if agy_candidate.is_file():
        return str(agy_candidate.resolve())
    which_path = shutil.which(agy_raw)
    if which_path and Path(which_path).is_file():
        return str(Path(which_path).resolve())
    raise SystemExit(f"agy.exe не найден: {agy_raw} (задайте --agy-bin или AGY_BIN)")


@dataclasses.dataclass
class RuntimeContext:
    agy_bin: str
    agy_model: str | None
    agy_concurrency: int
    initial_circuit_breaker: QuotaCircuitBreaker | None
    cache: ResultCache | None
    cache_path: Path
    ttl_map: dict[str, int]
    report_path: Path
    import_path: Path
    ver_sb: str
    ver_xr: str
    sb_exe: Path
    xr_exe: Path
    use_tcp_prefilter: bool = True
    tcp_timeout: float = 1.5
    tcp_concurrency: int = 100
    preflight_timeout: float = 2.5
    use_rep_filter: bool = True
    use_geo_precheck: bool = True
    geo_precheck_timeout: float = 2.5
    check_web: bool = False
    table_mode: str = "ok"
    table_limit: int = 20
    gist_id: str | None = None
    antidpi: bool = True
    antidpi_strategy: int | None = None
    antidpi_port: int = 10850
    antidpi_limit: int = 0
    isp: str | None = None
    no_elevate: bool = False
    jobs: int = 16


def _setup_environment(args: argparse.Namespace) -> RuntimeContext:
    agy_bin = _resolve_agy_bin(args.agy_bin)
    console.print(f"Пробер agy: {agy_bin}")

    cache_path = Path(args.cache) if args.cache else default_cache_path()
    ttl_map = {"AGY-OK": args.ttl_ok, "AGY-BLOCK": args.ttl_blocked, "DEAD": args.ttl_dead}
    cache = ResultCache(path=cache_path, ttl_map=ttl_map) if not args.no_cache else None

    if cache:
        ttl_txt = ", ".join(f"{k}={v // 3600}ч" if v > 0 else f"{k}=∞" for k, v in ttl_map.items())
        console.print(f"Кэш: {cache_path} (записей: {len(cache.entries)}, TTL: {ttl_txt})")
        try:
            enr = enrich_cached_ok_geo(cache)
            if enr > 0:
                console.print(f"Кэш: обогащено гео-данными {enr} записей AGY-OK")
        except Exception:
            pass

    agy_model = args.agy_model or detect_best_agy_model(agy_bin, cache=cache)
    if agy_model:
        console.print(f"Модель agy: {agy_model}")

    initial_cb: QuotaCircuitBreaker | None = None
    if not args.skip_precheck:
        health_ok, quota_info = check_agy_health(agy_bin, model=agy_model)
        if not health_ok:
            initial_cb = QuotaCircuitBreaker()
            initial_cb.trip(quota_info.clean_note)
            console.print(
                f"\n[bold yellow]⚠️ Внимание: квота agy исчерпана ({quota_info.clean_note})![/bold yellow]"
            )
            if not args.no_pause and sys.stdin and sys.stdin.isatty():
                prompt_text = "Продолжить проверку узлов в режиме preflight/geo (без agy) [y/N]? "
                try:
                    ans = input(prompt_text).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ans = ""
                if ans not in ("y", "yes", "д", "да"):
                    console.print("[dim]Проверка отменена пользователем.[/dim]")
                    sys.exit(0)
            else:
                console.print(
                    "[dim]Проверка будет выполнена в режиме preflight/geo (без обращений к agy).[/dim]"
                )

    out_dir = args.out or Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.md"
    import_path = out_dir / "proxy-ok.txt"

    ver_sb, ver_xr = detect_throne_versions(default_throne_dir())
    console.print(f"Версии движков Throne: sing-box v{ver_sb}, Xray v{ver_xr}")

    sb_exe, xr_exe = ensure_binaries(ver_sb, ver_xr, force=False)
    console.print(f"Движки: {sb_exe}, {xr_exe}")

    gist_id = resolve_gist_id(getattr(args, "gist_id", None))
    if gist_id:
        console.print(f"Синхронизация Gist: включена (ID: {mask_gist_id(gist_id)})")

    return RuntimeContext(
        agy_bin=agy_bin,
        agy_model=agy_model,
        agy_concurrency=args.agy_concurrency,
        initial_circuit_breaker=initial_cb,
        cache=cache,
        cache_path=cache_path,
        ttl_map=ttl_map,
        report_path=report_path,
        import_path=import_path,
        ver_sb=ver_sb,
        ver_xr=ver_xr,
        sb_exe=sb_exe,
        xr_exe=xr_exe,
        use_tcp_prefilter=not getattr(args, "no_tcp_prefilter", False),
        tcp_timeout=float(getattr(args, "tcp_timeout", 1.5)),
        tcp_concurrency=int(getattr(args, "tcp_concurrency", 100)),
        preflight_timeout=float(getattr(args, "preflight_timeout", 2.5)),
        use_rep_filter=not getattr(args, "no_rep_filter", False),
        use_geo_precheck=not getattr(args, "no_geo_precheck", False),
        geo_precheck_timeout=float(getattr(args, "geo_precheck_timeout", 2.5)),
        check_web=bool(getattr(args, "check_web", False)),
        table_mode=str(getattr(args, "table", "ok")),
        table_limit=int(getattr(args, "table_limit", 20)),
        gist_id=gist_id,
        antidpi=bool(getattr(args, "antidpi", True)),
        antidpi_strategy=getattr(args, "antidpi_strategy", None),
        antidpi_port=int(getattr(args, "antidpi_port", 10850)),
        antidpi_limit=int(getattr(args, "antidpi_limit", 0)),
        isp=getattr(args, "isp", None),
        no_elevate=bool(getattr(args, "no_elevate", False)),
        jobs=int(getattr(args, "jobs", 16)),
    )


@dataclasses.dataclass(frozen=True, slots=True)
class ServerSelection:
    servers: list[Server]
    to_probe: list[Server]
    cached_counts: dict[str, int]
    cached_unique_hosts: dict[str, set[str]]
    warnings: list[str]


def _collect_and_select_servers(
    args: argparse.Namespace,
    groups: list[dict[str, Any]],
    cache: ResultCache | None,
    ttl_map: dict[str, int],
) -> ServerSelection | None:
    selected = set(int(x) for x in args.group)
    if not selected:
        counts: dict[int, int] = {}
        for g in groups:
            gid = g["id"]
            counts[gid] = len(read_profiles_for_group(gid, g.get("name", "")))
        selected = interactive_select(groups, counts)
        if not selected:
            return None

    filter_insecure: bool | None = None
    if args.filter_insecure:
        filter_insecure = True
    elif args.allow_insecure:
        filter_insecure = False

    raw_servers, warnings = gather_sources(
        groups,
        selected,
        no_fetch=args.no_fetch,
        filter_insecure=filter_insecure,
    )
    servers = dedupe_servers(raw_servers)
    if args.subset > 0:
        servers = servers[: args.subset]

    for i, s in enumerate(servers, 1):
        s.index = i

    cached_counts: dict[str, int] = {}
    cached_unique_hosts: dict[str, set[str]] = {}
    to_probe: list[Server] = []

    for s in servers:
        rec = cache.get_valid_server(s) if (cache and not args.refresh_cache) else None
        if rec and getattr(args, "refresh_dead", False) and rec.get("result") == RESULT_DEAD:
            rec = None
        if rec:
            res = rec.get("result", "")
            s.result = res
            s.country = rec.get("country", "")
            s.ip_out = rec.get("ip_out", "")
            s.country_code = rec.get("country_code", "")
            s.city = rec.get("city", "")
            s.org = rec.get("org", "")
            s.latency_ms = rec.get("latency_ms", 0)
            s.note = rec.get("note", "")
            s.score = int(rec.get("score", 70 if res == RESULT_OK else 0))
            s.state = str(rec.get("state", STATE_ACTIVE if res == RESULT_OK else STATE_DEAD))
            s.consecutive_fails = int(rec.get("consecutive_fails", 0))
            s.web_status = str(rec.get("web_status", ""))
            s.ingress_country_code = str(rec.get("ingress_country_code", ""))
            s.ingress_ip = str(rec.get("ingress_ip", ""))
            s.from_cache = True
            cached_counts[res] = cached_counts.get(res, 0) + 1
            cached_unique_hosts.setdefault(res, set()).add(s.host_port)
        else:
            to_probe.append(s)

    return ServerSelection(
        servers=servers,
        to_probe=to_probe,
        cached_counts=cached_counts,
        cached_unique_hosts=cached_unique_hosts,
        warnings=warnings,
    )


def _probe_worker(
    bin_path: str,
    is_xray: bool,
    import_obj: dict[str, Any],
    timeouts: dict[str, float],
    agy_bin: str,
    print_timeout: str,
    agy_model: str | None = None,
    agy_semaphore: threading.Semaphore | None = None,
    circuit_breaker: QuotaCircuitBreaker | None = None,
    stop_event: threading.Event | None = None,
    registry: ProcessRegistry | None = None,
    use_geo_precheck: bool = True,
    check_web: bool = False,
    extra_outbounds: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    port = alloc_port()
    return run_probe(
        engine_bin=bin_path,
        is_xray=is_xray,
        import_obj=import_obj,
        port=port,
        timeouts=timeouts,
        agy_bin=agy_bin,
        print_timeout=print_timeout,
        agy_model=agy_model,
        agy_semaphore=agy_semaphore,
        circuit_breaker=circuit_breaker,
        stop_event=stop_event,
        registry=registry,
        use_geo_precheck=use_geo_precheck,
        check_web=check_web,
        extra_outbounds=extra_outbounds,
    )


def _execute_probe_pool(
    to_probe: list[Server],
    jobs: int,
    timeouts: dict[str, float],
    ctx: RuntimeContext,
    print_timeout: str,
    cached_counts: dict[str, int] | None = None,
    circuit_breaker: QuotaCircuitBreaker | None = None,
    cached_unique_hosts: dict[str, set[str]] | None = None,
) -> tuple[int, bool]:
    cb = circuit_breaker or ctx.initial_circuit_breaker
    cache_line = format_cached_counters(cached_counts or {}, cached_unique_hosts=cached_unique_hosts)
    if cache_line:
        console.print(f"[dim]{cache_line}[/dim]")

    # Счётчик результатов проверки движками (изолирован от кэша и Stage 0)
    engine_counts: Counter[str] = Counter()
    registry = ProcessRegistry()
    stop_event = threading.Event()
    concurrency = getattr(ctx, "agy_concurrency", 2)
    agy_semaphore = threading.Semaphore(concurrency)
    model = getattr(ctx, "agy_model", None)
    completed_count = 0
    interrupted = False

    # Stage 0: Быстрый предварительный L4 TCP-фильтр (отсечение мёртвых хостов до запуска движков)
    to_probe_engine: list[Server] = to_probe
    if getattr(ctx, "use_tcp_prefilter", True) and to_probe:
        tcp_endpoints = {(s.server, s.server_port) for s in to_probe if s.is_tcp_protocol}
        if tcp_endpoints:
            t0_tcp = time.perf_counter()
            pbar_tcp = tqdm(
                total=len(tcp_endpoints),
                desc="L4 TCP предфильтр",
                unit="host",
                dynamic_ncols=True,
            )
            try:
                tcp_results = batch_probe_tcp(
                    tcp_endpoints,
                    timeout=getattr(ctx, "tcp_timeout", 1.5),
                    max_workers=getattr(ctx, "tcp_concurrency", 100),
                    stop_event=stop_event,
                    progress_callback=lambda _c, _t: pbar_tcp.update(1),
                )
            except KeyboardInterrupt:
                interrupted = True
                stop_event.set()
                pbar_tcp.close()
                return completed_count, interrupted
            finally:
                pbar_tcp.close()

            dt_tcp = time.perf_counter() - t0_tcp
            stage0_dead_cnt = 0
            survivors: list[Server] = []
            for s in to_probe:
                if s.is_tcp_protocol:
                    res = tcp_results.get((s.server, s.server_port))
                    if res is not None:
                        is_alive, tcp_lat, tcp_note = res
                        if not is_alive:
                            s.result = RESULT_DEAD
                            s.latency_ms = tcp_lat
                            s.note = tcp_note
                            completed_count += 1
                            stage0_dead_cnt += 1
                            continue
                survivors.append(s)

            if stage0_dead_cnt:
                dead_endpoints_cnt = sum(1 for is_alive, _, _ in tcp_results.values() if not is_alive)
                console.print(
                    f"[dim]L4 TCP-предфильтр: проверено {len(tcp_endpoints)} эндпоинтов, "
                    f"отсеяно {stage0_dead_cnt} серверов ({dead_endpoints_cnt} узлов) за {dt_tcp:.1f} с[/dim]"
                )
            to_probe_engine = survivors

    if not to_probe_engine or stop_event.is_set():
        return completed_count, interrupted

    # Stage 1: Полноценная проверка через движки sing-box / Xray (In-Memory)
    # Фильтр представителей применяется только если Stage 0 TCP-предфильтр был отключён
    tcp_prefilter_enabled = bool(getattr(ctx, "use_tcp_prefilter", True))
    use_rep_filter = bool(getattr(ctx, "use_rep_filter", True)) and not tcp_prefilter_enabled
    total = len(to_probe_engine)
    pbar = tqdm(
        total=total,
        desc="Проверка движками",
        unit="srv",
        dynamic_ncols=True,
    )
    pbar.set_postfix_str(format_live_counters(engine_counts), refresh=True)

    def _apply_result(server: Server, future: concurrent.futures.Future[Any]) -> None:
        nonlocal completed_count
        try:
            probe_res: dict[str, Any] = future.result()
        except Exception as e:
            server.result = RESULT_UNKNOWN
            server.note = f"ошибка: {e}"
        else:
            server.result = probe_res["result"]
            server.country = probe_res.get("country", "")
            server.ip_out = probe_res.get("ip_out", "")
            server.country_code = probe_res.get("country_code", "")
            server.city = probe_res.get("city", "")
            server.org = probe_res.get("org", "")
            server.latency_ms = probe_res.get("latency_ms", 0)
            server.note = probe_res.get("note", "")
            server.web_status = probe_res.get("web_status", "")
            server.ingress_country_code = probe_res.get("ingress_country_code", "")
            server.ingress_ip = probe_res.get("ingress_ip", "")
        completed_count += 1
        engine_counts[server.result] += 1
        pbar.set_postfix_str(format_live_counters(engine_counts), refresh=False)
        pbar.update(1)

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)

    def _submit_server(server: Server) -> concurrent.futures.Future[Any]:
        bin_path = str(ctx.xr_exe if server.engine == "xray" else ctx.sb_exe)
        return ex.submit(
            _probe_worker,
            bin_path,
            server.engine == "xray",
            server.import_obj,
            timeouts,
            ctx.agy_bin,
            print_timeout,
            agy_model=model,
            agy_semaphore=agy_semaphore,
            circuit_breaker=cb,
            stop_event=stop_event,
            registry=registry,
            use_geo_precheck=getattr(ctx, "use_geo_precheck", True),
            check_web=getattr(ctx, "check_web", False),
        )

    try:
        if use_rep_filter:
            ep_to_servers: dict[tuple[str, int], list[Server]] = {}
            for s in to_probe_engine:
                ep_to_servers.setdefault((s.server, s.server_port), []).append(s)

            representatives = [srvs[0] for srvs in ep_to_servers.values()]
            siblings_map = {ep: srvs[1:] for ep, srvs in ep_to_servers.items() if len(srvs) > 1}
            surviving_siblings: list[Server] = []

            # 1a: Проверка представителей уникальных узлов
            fut_map = {_submit_server(s): s for s in representatives}
            for fut in concurrent.futures.as_completed(fut_map):
                s = fut_map[fut]
                if stop_event.is_set():
                    break
                _apply_result(s, fut)
                ep = (s.server, s.server_port)
                if ep in siblings_map:
                    if s.result == RESULT_DEAD:
                        for sib in siblings_map[ep]:
                            sib.result = RESULT_DEAD
                            sib.latency_ms = s.latency_ms
                            sib.note = f"отсев по узлу ({s.note})"
                            completed_count += 1
                            engine_counts[RESULT_DEAD] += 1
                            pbar.update(1)
                        pbar.set_postfix_str(format_live_counters(engine_counts), refresh=False)
                    else:
                        surviving_siblings.extend(siblings_map[ep])

            # 1b: Проверка оставшихся профилей для живых узлов
            if surviving_siblings and not stop_event.is_set():
                fut_map2 = {_submit_server(s): s for s in surviving_siblings}
                for fut in concurrent.futures.as_completed(fut_map2):
                    s = fut_map2[fut]
                    if stop_event.is_set():
                        break
                    _apply_result(s, fut)
        else:
            fut_map = {_submit_server(s): s for s in to_probe_engine}
            for fut in concurrent.futures.as_completed(fut_map):
                s = fut_map[fut]
                if stop_event.is_set():
                    break
                _apply_result(s, fut)
    except KeyboardInterrupt:
        interrupted = True
        msg = (
            f"\n[bold yellow]Прерывание (Ctrl+C). Остановка задач "
            f"(завершено {completed_count}/{total})...[/bold yellow]"
        )
        console.print(msg)
        stop_event.set()
        registry.kill_all()
        ex.shutdown(wait=False, cancel_futures=True)
    finally:
        pbar.close()
        if interrupted:
            stop_event.set()
            registry.kill_all()
            ex.shutdown(wait=False, cancel_futures=True)
        else:
            ex.shutdown(wait=True)

    return completed_count, interrupted



MIN_PROBED_FOR_OUTAGE_GUARD: int = 5


def _is_mass_network_outage(
    to_probe: list[Server],
    min_probed: int = MIN_PROBED_FOR_OUTAGE_GUARD,
) -> bool:
    """Выявляет тотальный сбой локальной сети: проверено >= min_probed узлов и 100% вернули DEAD."""
    probed = [s for s in to_probe if s.result]
    if len(probed) < min_probed:
        return False
    return all(s.result == RESULT_DEAD for s in probed)


def _sync_and_save_cache(
    ctx: RuntimeContext,
    servers: list[Server],
    to_probe: list[Server],
    label: str = "",
) -> bool:
    """Синхронизирует и сохраняет кэш. Возвращает True, если сработал предохранитель сбоя сети."""
    if not ctx.cache:
        return False
    for s in servers:
        ctx.cache.enrich_from_server(s)

    outage_detected = _is_mass_network_outage(to_probe)
    if outage_detected:
        console.print(
            "[bold yellow]⚠️ Внимание: 100% проверенных серверов вернули DEAD. "
            "Возможен обрыв локальной сети или активный мёртвый прокси — "
            "штрафные баллы для ранее рабочих узлов в кэше не начислены.[/bold yellow]"
        )

    for s in to_probe:
        if not s.result:
            continue
        if outage_detected and s.result == RESULT_DEAD:
            cur = ctx.cache.entries.get(s.cache_key) or ctx.cache.entries.get(s.host_port)
            if cur and (
                cur.get("state") in (STATE_ACTIVE, STATE_DEGRADED)
                or cur.get("result") == RESULT_OK
            ):
                continue
        ctx.cache.update_from_server(s)

    ctx.cache.save()
    suffix = f" ({label})" if label else ""
    console.print(f"[dim]Кэш сохранён{suffix}: {ctx.cache_path} (записей: {len(ctx.cache.entries)})[/dim]")
    return outage_detected


def _finalize_and_report(
    ctx: RuntimeContext,
    servers: list[Server],
    to_probe: list[Server],
    warnings: list[str],
    dt: float,
    cached_counts: dict[str, int],
    interrupted: bool = False,
    circuit_breaker: QuotaCircuitBreaker | None = None,
    cached_unique_hosts: dict[str, set[str]] | None = None,
) -> None:
    if interrupted:
        warnings = list(warnings)
        warnings.append("Проверка была прервана пользователем (Ctrl+C). Часть серверов не проверена.")

    if circuit_breaker and circuit_breaker.is_tripped:
        warnings = list(warnings)
        warnings.append(
            f"Во время проверки была исчерпана индивидуальная квота agy ({circuit_breaker.reason}). "
            f"Последующие проверки agy пропущены, серверы протестированы по preflight/geo."
        )

    outage_detected = _sync_and_save_cache(ctx, servers, to_probe)
    if outage_detected:
        warnings = list(warnings)
        warnings.append(
            "Все проверенные узлы вернули DEAD (возможен сбой локальной сети или родительского прокси). "
            "Деградация ранее рабочих узлов в кэше была заблокирована предохранителем."
        )

    cache_note = ""
    if ctx.cache:
        ttl_txt = ", ".join(f"{k}: {v // 3600} ч" if v > 0 else f"{k}: не устаревает" for k, v in ctx.ttl_map.items())
        cache_note = (
            f"Серверы с кешируемыми результатами (AGY-OK/AGY-BLOCK/DEAD) берутся из кэша ({ctx.cache_path}) "
            f"и не перепроверяются до истечения TTL по типу: {ttl_txt}; "
            f"принудительная перепроверка всех — с --refresh-cache, только упавших (DEAD) — с --refresh-dead."
        )

    stats = compute_summary_stats(servers)
    write_report(
        servers,
        ctx.report_path,
        ctx.ver_sb,
        ctx.ver_xr,
        warnings,
        dt,
        cached_counts=cached_counts,
        cache_note=cache_note,
        cached_unique_hosts=cached_unique_hosts,
        stats=stats,
    )
    nb, nx = write_import_file(
        ctx.cache,
        ctx.import_path,
        fallback_servers=servers,
        relay_port=ctx.antidpi_port,
    )

    gist_res = None
    if ctx.gist_id:
        gist_res = sync_file_to_gist(ctx.import_path, ctx.gist_id)

    print_results_table(servers, mode=ctx.table_mode, limit=ctx.table_limit)
    print_summary_panel(
        servers,
        cached_counts,
        ctx.report_path,
        ctx.import_path,
        nb,
        nx,
        dt,
        cached_unique_hosts=cached_unique_hosts,
        stats=stats,
        gist_res=gist_res,
    )


def _run_clear_dead(args: argparse.Namespace) -> None:
    cache_path = Path(args.cache) if getattr(args, "cache", None) else default_cache_path()
    if not cache_path.is_file():
        console.print(f"[yellow]Файл кэша {cache_path} не найден.[/yellow]")
        return
    cache = ResultCache(path=cache_path)
    removed = cache.clear_dead()
    console.print(
        f"[green]✓ Из кэша {cache_path.name} удалено {removed} записей со статусом DEAD. "
        f"Осталось записей: {len(cache.entries)}.[/green]"
    )


def _run_probe_pipeline(args: argparse.Namespace, *, interactive_loop: bool = False) -> None:
    if args.throne_dir:
        set_throne_dir(args.throne_dir)

    ctx = _setup_environment(args)

    groups = read_groups()
    if not groups:
        raise SystemExit("В БД Throne нет активных групп")

    selection = _collect_and_select_servers(args, groups, ctx.cache, ctx.ttl_map)
    if selection is None:
        console.print("Ничего не выбрано.")
        if not interactive_loop:
            pause_on_exit(args.no_pause)
        return

    servers = selection.servers
    to_probe = selection.to_probe
    cached_counts = selection.cached_counts
    cached_unique_hosts = selection.cached_unique_hosts
    warnings = selection.warnings
    timeouts = {
        "start": min(args.timeout, 12.0),
        "preflight": args.preflight_timeout,
        "geo_precheck": args.geo_precheck_timeout,
        "probe": args.timeout,
        "geo": min(args.timeout, 10.0),
        "web_check": 3.5,
    }
    print_timeout = args.print_timeout
    if print_timeout == AGY_PRINT_TIMEOUT_DEFAULT and args.timeout != 35.0:
        print_timeout = f"{int(args.timeout)}s"
    t0 = time.time()

    circuit_breaker = ctx.initial_circuit_breaker or QuotaCircuitBreaker()
    _completed_count, interrupted = _execute_probe_pool(
        to_probe=to_probe,
        jobs=args.jobs,
        timeouts=timeouts,
        ctx=ctx,
        print_timeout=print_timeout,
        cached_counts=cached_counts,
        circuit_breaker=circuit_breaker,
        cached_unique_hosts=cached_unique_hosts,
    )

    pre_sync_entries = copy.deepcopy(ctx.cache.entries) if ctx.cache is not None else None

    _sync_and_save_cache(ctx, servers, to_probe, label="Stage 1")
    if ctx.import_path and ctx.cache:
        with contextlib.suppress(Exception):
            write_import_file(
                ctx.cache,
                ctx.import_path,
                fallback_servers=servers,
                relay_port=ctx.antidpi_port,
            )

    if not interrupted and ctx.antidpi:
        execute_antidpi_stage(
            servers=servers,
            to_probe=to_probe,
            ctx=ctx,
            timeouts=timeouts,
            print_timeout=print_timeout,
            circuit_breaker=circuit_breaker,
        )

    dt = time.time() - t0

    if ctx.cache is not None and pre_sync_entries is not None:
        ctx.cache.entries = pre_sync_entries

    _finalize_and_report(
        ctx=ctx,
        servers=servers,
        to_probe=to_probe,
        warnings=warnings,
        dt=dt,
        cached_counts=cached_counts,
        interrupted=interrupted,
        circuit_breaker=circuit_breaker,
        cached_unique_hosts=cached_unique_hosts,
    )

    if interrupted:
        if not interactive_loop:
            sys.exit(130)
        return

    if not interactive_loop:
        pause_on_exit(args.no_pause)


def _has_direct_cli_mode(args: argparse.Namespace, raw_argv: list[str]) -> bool:
    """Определяет, передан ли явный режим запуска через аргументы CLI."""
    if (
        getattr(args, "clear_dead", False)
        or getattr(args, "update_catalogue", False)
        or getattr(args, "serve", False)
        or getattr(args, "stop_relay", False)
        or getattr(args, "status_relay", False)
        or getattr(args, "calibrate", None) is not None
        or getattr(args, "group", None)
        or getattr(args, "subset", 0) > 0
        or getattr(args, "refresh_cache", False)
        or getattr(args, "refresh_dead", False)
    ):
        return True
    return bool(raw_argv)


def main(argv: list[str] | None = None) -> int:
    disable_quick_edit_mode()
    load_dotenv()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = build_arg_parser().parse_args(raw_argv)

    for stream in (sys.stdout, sys.stderr):
        recfg = getattr(stream, "reconfigure", None)
        if recfg is not None:
            with contextlib.suppress(ValueError):
                recfg(encoding="utf-8", errors="replace")

    if getattr(args, "stage2_worker", None):
        rc = run_stage2_worker(
            task_file=Path(args.stage2_worker),
            log_file=Path(args.log_output) if getattr(args, "log_output", None) else None,
        )
        sys.exit(rc)

    if getattr(args, "clear_dead", False):
        _run_clear_dead(args)
        return 0

    if getattr(args, "status_relay", False):
        return print_relay_status(args)

    if getattr(args, "stop_relay", False):
        return stop_relay_service(args)

    if getattr(args, "update_catalogue", False):
        rc = run_catalogue_update()
        if rc != 0:
            sys.exit(rc)
        return rc

    if getattr(args, "calibrate", None) is not None:
        return run_calibration(args)

    if getattr(args, "serve", False):
        return run_relay_service(args)

    if _has_direct_cli_mode(args, raw_argv) or not (sys.stdin and sys.stdin.isatty()):
        _run_probe_pipeline(args, interactive_loop=False)
        return 0

    # Интерактивный цикл главного меню TUI (при запуске run.cmd / pxp без аргументов)
    while True:
        try:
            action = select_main_action_interactive(relay_port=args.antidpi_port)
        except TypeError:
            action = select_main_action_interactive()
        if action == "exit":
            break
        if action == "probe":
            _run_probe_pipeline(args, interactive_loop=True)
        elif action == "serve":
            args.detach = True
            run_relay_service(args)
            args.detach = False
        elif action == "stop_relay":
            stop_relay_service(args)
        elif action == "calibrate":
            lvl = select_calibration_level_interactive()
            if lvl is not None:
                args.calibrate = lvl
                run_calibration(args)
                args.calibrate = None
        elif action == "update_catalogue":
            run_catalogue_update()
        elif action == "clear_dead":
            _run_clear_dead(args)
    return 0


def cli_entrypoint() -> None:
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit as exc:
        if exc.code not in (0, 130, None):
            if isinstance(exc.code, str):
                print(f"\nОшибка: {exc.code}", file=sys.stderr)
            if "--no-pause" not in sys.argv:
                pause_on_exit()
        raise
    except Exception:
        import traceback

        traceback.print_exc()
        if "--no-pause" not in sys.argv:
            pause_on_exit()
        sys.exit(1)


if __name__ == "__main__":
    cli_entrypoint()
