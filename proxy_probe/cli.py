#!/usr/bin/env python3
"""Интерфейс командной строки proxy-probe (pxp).

Проверка серверов подписок на пригодность к работе с целевыми утилитами (agy / Gemini API).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from .cache import ResultCache, default_cache_path
from .engines import alloc_port, ensure_binaries
from .models import DEFAULT_TTLS, Server
from .orchestrator import (
    dedupe_servers,
    fetch_subscription,
    gather_sources,
    interactive_select,
    pause_on_exit,
    run_dir,
)
from .parsers import parse_subscription
from .prober import AGY_PRINT_TIMEOUT_DEFAULT, get_default_agy_bin, run_probe
from .reporter import write_import_file, write_report
from .throne import (
    default_throne_dir,
    detect_throne_versions,
    read_groups,
    read_profiles_for_group,
    set_throne_dir,
)
from .ui import (
    console,
    print_progress_row,
    print_results_table,
    print_summary_panel,
)

__all__ = ["main"]


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="pxp",
        description="proxy-probe (pxp): проверка серверов подписок на работу с целевыми утилитами (agy/Gemini)",
    )
    default_jobs = max(1, os.cpu_count() or 1)
    ap.add_argument(
        "--jobs",
        type=int,
        default=default_jobs,
        help=f"число параллельных проверок (по умолчанию CPU = {default_jobs})",
    )
    ap.add_argument("--subset", type=int, default=0, help="проверить только первые N серверов (0 = все)")
    ap.add_argument(
        "--group", type=int, action="append", default=[], help="id группы (можно несколько; иначе — выбор)"
    )
    ap.add_argument("--no-fetch", action="store_true", help="не обновлять подписки, использовать данные из БД Throne")
    ap.add_argument("--timeout", type=float, default=50.0, help="секунд таймаут на одну проверку")
    ap.add_argument(
        "--agy-bin",
        type=str,
        default=None,
        help="путь к agy.exe (CLI Antigravity, по умолчанию поиск в PATH и AppData)",
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
    ap.add_argument("--no-pause", action="store_true", help="не ждать нажатия Enter перед выходом")
    args = ap.parse_args()

    if args.throne_dir:
        set_throne_dir(args.throne_dir)

    for stream in (sys.stdout, sys.stderr):
        recfg = getattr(stream, "reconfigure", None)
        if recfg is not None:
            with contextlib.suppress(ValueError):
                recfg(encoding="utf-8", errors="replace")

    agy_raw = args.agy_bin or os.environ.get("AGY_BIN") or get_default_agy_bin()
    agy_candidate = Path(agy_raw)
    if agy_candidate.is_file():
        agy_bin = str(agy_candidate.resolve())
    else:
        which_path = shutil.which(agy_raw)
        if which_path and Path(which_path).is_file():
            agy_bin = str(Path(which_path).resolve())
        else:
            raise SystemExit(f"agy.exe не найден: {agy_raw} (задайте --agy-bin или AGY_BIN)")
    print(f"Пробер agy: {agy_bin}")

    cache_path = Path(args.cache) if args.cache else default_cache_path()
    ttl_map = {"AGY-OK": args.ttl_ok, "AGY-BLOCK": args.ttl_blocked, "DEAD": args.ttl_dead}
    cache = ResultCache(path=cache_path, ttl_map=ttl_map) if not args.no_cache else None

    if cache:
        ttl_txt = ", ".join(f"{k}={v // 3600}ч" if v > 0 else f"{k}=∞" for k, v in ttl_map.items())
        print(f"Кэш: {cache_path} (записей: {len(cache.entries)}, TTL: {ttl_txt})")

    out_dir = args.out or Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.md"
    import_path = out_dir / "proxy-ok.txt"

    ver_sb, ver_xr = detect_throne_versions(default_throne_dir())
    print(f"Версии движков Throne: sing-box v{ver_sb}, Xray v{ver_xr}")

    sb_exe, xr_exe = ensure_binaries(ver_sb, ver_xr, force=False)
    print(f"Движки: {sb_exe}, {xr_exe}")

    groups = read_groups()
    if not groups:
        raise SystemExit("В БД Throne нет активных групп")

    prefetched_subs: dict[str, bytes] = {}
    selected = set(int(x) for x in args.group)
    if not selected:
        counts: dict[int, int] = {}
        for g in groups:
            url = g.get("url")
            if url and not args.no_fetch:
                data = fetch_subscription(url, timeout=15.0)
                if data is not None:
                    prefetched_subs[url] = data
                    n = len(parse_subscription(data))
                else:
                    n = len(read_profiles_for_group(g["id"]))
                counts[g["id"]] = n
                tag_name = g["name"]
                if data is not None and n:
                    print(f"  подписка «{tag_name}» — {n} серверов (свежая)")
                else:
                    print(f"  подписка «{tag_name}» — недоступна/не распознана, будет из БД")
            else:
                n = len(read_profiles_for_group(g["id"]))
                counts[g["id"]] = n
        selected = interactive_select(groups, counts)

    if not selected:
        print("Ничего не выбрано — выход.")
        pause_on_exit(args.no_pause)
        return

    timeouts = {"start": args.timeout, "probe": args.timeout, "geo": min(args.timeout, 10.0)}
    t0 = time.time()
    servers, warnings = gather_sources(groups, selected, args.no_fetch, prefetched=prefetched_subs)
    servers = dedupe_servers(servers)
    if args.subset > 0:
        servers = servers[: args.subset]

    to_probe: list[Server] = []
    cached_counts = {res: 0 for res in ttl_map}
    for s in servers:
        rec = cache.get_valid(s.host_port) if (cache and not args.refresh_cache) else None
        if rec:
            cached_res = str(rec["result"])
            s.result = cached_res
            s.country = str(rec.get("country", ""))
            s.ip_out = str(rec.get("ip_out", ""))
            cached_note = str(rec.get("note", "")).strip()
            checked_at = str(rec.get("checked", ""))
            if cached_note and not cached_note.startswith("кэш"):
                s.note = f"{cached_note} [кэш {checked_at}]"
            else:
                s.note = f"[кэш {checked_at}]"
            if cached_res in cached_counts:
                cached_counts[cached_res] += 1
            continue
        to_probe.append(s)

    for i, s in enumerate(servers, 1):
        s.index = i

    cache_summary = ", ".join(f"{k}={v}" for k, v in cached_counts.items())
    print(
        f"\nВсего серверов: {len(servers)} (к проверке: {len(to_probe)}, из кэша: {cache_summary}, "
        f"jobs={args.jobs}, таймаут={args.timeout:.0f}с)"
    )

    run_root = run_dir()
    futures: dict[concurrent.futures.Future[Any], Server] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for s in to_probe:
            bin_path = str(xr_exe if s.engine == "xray" else sb_exe)
            port = alloc_port()
            fut = ex.submit(
                run_probe,
                bin_path,
                s.engine == "xray",
                s.import_obj,
                port,
                run_root,
                timeouts,
                agy_bin=agy_bin,
                print_timeout=args.print_timeout,
            )
            futures[fut] = s

        total = len(to_probe)
        try:
            for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                s = futures[fut]
                probe_res: dict[str, Any] = fut.result()
                s.result = probe_res["result"]
                s.country = probe_res.get("country", "")
                s.ip_out = probe_res.get("ip_out", "")
                s.latency_ms = probe_res.get("latency_ms", 0)
                s.note = probe_res.get("note", "")
                print_progress_row(s, i, total)
        except KeyboardInterrupt:
            print("\nПрерывание пользователем (Ctrl+C). Остановка задач...")
            ex.shutdown(wait=False, cancel_futures=True)
            raise

    dt = time.time() - t0

    if cache:
        for s in servers:
            cache.enrich_from_server(s)
        for s in to_probe:
            cache.update_from_server(s)
        cache.save()
        console.print(f"[dim]Кэш обновлён: {cache_path} (записей: {len(cache.entries)})[/dim]")

    cache_note = ""
    if cache:
        ttl_txt = ", ".join(f"{k}: {v // 3600} ч" if v > 0 else f"{k}: не устаревает" for k, v in ttl_map.items())
        cache_note = (
            f"Серверы с кешируемыми результатами (AGY-OK/AGY-BLOCK/DEAD) берутся из кэша ({cache_path}) "
            f"и не перепроверяются до истечения TTL по типу: {ttl_txt}; "
            f"принудительная перепроверка — запуск с --refresh-cache."
        )

    write_report(
        servers,
        report_path,
        ver_sb,
        ver_xr,
        warnings,
        dt,
        cached_counts=cached_counts,
        cache_note=cache_note,
    )
    nb, nx = write_import_file(cache, import_path, fallback_servers=servers)

    print_results_table(servers)
    print_summary_panel(servers, cached_counts, report_path, import_path, nb, nx, dt)

    pause_on_exit(args.no_pause)


def cli_entrypoint() -> None:
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit as exc:
        if exc.code not in (0, None):
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
