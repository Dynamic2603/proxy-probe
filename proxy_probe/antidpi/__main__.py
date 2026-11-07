from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import cProfile
import datetime as _dt
import logging
import pstats
import subprocess
import sys
import time
from pathlib import Path

from ..cache import ResultCache, default_cache_path
from ..engines import project_root
from ..models import Server
from ..parsers import extract_host_port
from .benchmark import (
    calculate_strategy_score,
    default_ratings_path,
    format_benchmark_table,
    load_ratings,
    prepare_strategies_for_level,
    probe_proxy_tunnel,
    save_ratings,
    select_dead_servers,
)
from .catalogue import fetch_catalogue, get_strategy_by_number, load_catalogue
from .elevation import TeeOutput, is_admin, run_elevated_and_wait
from .engine import WinwsRunner, cleanup_stale_windivert_service, ensure_zapret_binaries
from .isp import IspDetectionError, detect_current_isp
from .models import CALIBRATION_LEVELS, AntidpiBenchmarkResult, StrategyRating
from .relay import DEFAULT_RELAY_HOST, DEFAULT_RELAY_PORT, ZapretRelay

logger = logging.getLogger("proxy_probe.antidpi")


def cmd_update(args: argparse.Namespace) -> int:
    print("Обновление каталога Anti-DPI стратегий из upstream...")
    try:
        profiles = fetch_catalogue()
        total = len(profiles)
        fams = len({p.technical_family for p in profiles})
        print(f"Успешно обновлено: {total} стратегий ({fams} уникальных технических семейств).")
        return 0
    except Exception as e:
        print(f"Ошибка обновления каталога: {e}", file=sys.stderr)
        return 1


def collect_dead_candidates(cache: ResultCache) -> list[Server]:
    """Собирает список серверов-кандидатов для Anti-DPI бенчмарка (SSOT).

    Приоритетно считывает актуальные профили из базы Throne,
    сопоставляя их с результатами проверок в кэше.
    При недоступности Throne использует сохраненные в кэше результаты.
    """
    candidates: list[Server] = []
    seen_identities: set[str] = set()

    # 1. Попытка загрузить актуальные серверы из локальной базы Throne
    try:
        from ..throne import read_groups, read_profiles_for_group

        groups = read_groups()
        for g in groups:
            for s in read_profiles_for_group(g["id"], g["name"]):
                cid = s.config_identity
                if cid in seen_identities:
                    continue
                seen_identities.add(cid)

                entry = cache.entries.get(cid) or cache.entries.get(s.cache_key) or {}
                if entry:
                    s.result = str(entry.get("result", ""))
                    s.state = str(entry.get("state", ""))
                    s.note = str(entry.get("note", ""))
                candidates.append(s)
    except Exception as exc:
        logger.debug("Сбор кандидатов из Throne пропущен: %s", exc)

    # 2. Если Throne пуст или недоступен, фоллбэк на базу кэша
    if not candidates:
        for _k, entry in cache.entries.items():
            res = str(entry.get("result", ""))
            state = str(entry.get("state", ""))
            raw_obj = entry.get("import_obj")
            if not isinstance(raw_obj, dict):
                continue
            host, port = extract_host_port(raw_obj)
            if not host or not port:
                continue
            engine = str(entry.get("engine") or ("xray" if "protocol" in raw_obj else "sing-box"))
            s = Server(
                group_id=0,
                group_name="",
                name=str(raw_obj.get("tag", "")),
                engine=engine,
                server=host,
                server_port=port,
                import_obj=raw_obj,
                source="cache",
                result=res,
                state=state,
                note=str(entry.get("note") or ""),
            )
            cid = s.config_identity
            if cid in seen_identities:
                continue
            seen_identities.add(cid)
            candidates.append(s)

    return candidates


def cmd_benchmark(args: argparse.Namespace) -> int:
    if not is_admin() and not getattr(args, "no_elevate", False):
        log_path = default_ratings_path().parent / "benchmark_run.log"
        if log_path.is_file():
            with contextlib.suppress(Exception):
                log_path.unlink()

        print("=" * 70)
        print("  proxy-probe: Запрос прав Администратора для WinDivert (Zapret2)")
        print("  Пожалуйста, подтвердите UAC (нажмите 'Да') в системном окне на экране...")
        print("=" * 70)

        raw_argv = getattr(args, "_raw_argv", sys.argv[1:])
        extra_args = [arg for arg in raw_argv if arg != "--no-elevate"]
        if not extra_args or extra_args[0] != "benchmark":
            extra_args = ["benchmark", *extra_args]
        if "--log-output" not in extra_args:
            extra_args.extend(["--log-output", str(log_path)])

        elev_params = subprocess.list2cmdline(["-m", "proxy_probe.antidpi", *extra_args])

        try:
            rc = run_elevated_and_wait(executable=sys.executable, params=elev_params, cwd=project_root())
            if log_path.is_file():
                with contextlib.suppress(Exception):
                    content = log_path.read_text(encoding="utf-8", errors="replace")
                    if content.strip():
                        print(content)
            return rc
        except PermissionError as exc:
            print(f"\n[!] {exc}", file=sys.stderr)
            return 1223
        except Exception as exc:
            print(f"\n[!] Ошибка вызова UAC: {exc}", file=sys.stderr)
            return 1

    log_out = getattr(args, "log_output", None)
    cm = TeeOutput(Path(log_out)) if log_out else contextlib.nullcontext()
    with cm:
        return _run_benchmark(args)


def _run_benchmark(args: argparse.Namespace) -> int:
    level = int(getattr(args, "level", 2) or 2)
    cfg = CALIBRATION_LEVELS.get(level, CALIBRATION_LEVELS[2])

    print("=" * 65)
    print(f"  proxy-probe: {cfg.title}")
    print("=" * 65)

    # Определение входящего интернет-провайдера (Ingress ISP / ASN)
    print("\nОпределение текущего входящего интернет-провайдера (Ingress ISP)...")
    try:
        current_isp = detect_current_isp(explicit_override=getattr(args, "isp", None))
        print(f"[✓] Провайдер: {current_isp.display_name} (IP: {current_isp.ingress_ip or '—'})")
    except IspDetectionError as err:
        print("\n" + "=" * 65, file=sys.stderr)
        print("  [ERROR] Не удалось определить входящего интернет-провайдера!", file=sys.stderr)
        print(f"  {err}", file=sys.stderr)
        print("=" * 65, file=sys.stderr)
        return 1

    cache_path = default_cache_path()
    if not cache_path.is_file():
        print(f"Файл кэша {cache_path} не найден. Сначала выполните прогон proxy-probe (run.cmd).", file=sys.stderr)
        return 1

    cache = ResultCache(path=cache_path)
    dead_candidates = collect_dead_candidates(cache)

    verify_tcp = not getattr(args, "no_tcp_verify", False)
    server_limit = args.limit if getattr(args, "limit", None) is not None else cfg.server_limit
    selected = select_dead_servers(dead_candidates, limit=server_limit, verify_tcp=verify_tcp)
    if not selected:
        print("В базе кэша не найдено серверов с сетевым таймаутом (DEAD). Тестирование не требуется.")
        return 0

    print(f"\nОтобрано {len(selected)} серверов со статусом DEAD для калибровки:")
    for s in selected[:15]:
        print(f"  - {s.server}:{s.server_port} ({s.name[:35]})")
    if len(selected) > 15:
        print(f"  ... и еще {len(selected) - 15} серверов")

    catalogue = load_catalogue()
    living_ratings = load_ratings(isp_identity=current_isp)
    test_strategies = prepare_strategies_for_level(level, catalogue, living_ratings)
    if getattr(args, "top", None) is not None and args.top > 0:
        test_strategies = test_strategies[: args.top]

    print(f"\nЗапуск тестирования {len(test_strategies)} стратегий десинхронизации...")

    # Обеспечиваем наличие бинарников zapret2
    print("Проверка наличия бинарников Zapret2 (winws.exe, WinDivert)...")
    zapret_dir = ensure_zapret_binaries()
    cleanup_stale_windivert_service(zapret_dir)

    target_ips = [s.server for s in selected if s.server]
    ports = sorted({str(s.server_port) for s in selected if s.server_port})
    if len(ports) > 20:
        ports = ports[:20]
    ports_str = ",".join(ports) or "443"
    ratings: list[StrategyRating] = []
    server_rescue_map: dict[str, list[tuple[int, int]]] = {}

    relay_port = args.relay_port
    workers = min(len(selected), getattr(args, "concurrency", 15))
    probe_timeout = float(getattr(args, "timeout", None) or cfg.timeout)
    enable_profile = bool(getattr(args, "profile", False))
    profiler = cProfile.Profile() if enable_profile else None
    if profiler:
        profiler.enable()

    with ZapretRelay(port=relay_port):
        for idx, strat in enumerate(test_strategies, 1):
            print(f"[{idx}/{len(test_strategies)}] Тестирование S{strat.number:02d}: {strat.name[:45]}...")
            try:
                with WinwsRunner(
                    strategy=strat,
                    target_ips=target_ips,
                    zapret_dir=zapret_dir,
                    ports=ports_str,
                ):
                    time.sleep(0.3)
                    rescued = 0
                    latencies: list[int] = []
                    rescued_servers: list[tuple[Server, int]] = []
                    failed_reasons: dict[str, int] = {}
                    server_details: list[tuple[Server, bool, int, str]] = []

                    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                        futs = {
                            ex.submit(probe_proxy_tunnel, srv, relay_port=relay_port, timeout=probe_timeout): srv
                            for srv in selected
                        }
                        for fut in concurrent.futures.as_completed(futs):
                            srv = futs[fut]
                            try:
                                ok, lat_ms, reason = fut.result()
                            except Exception as exc:
                                ok, lat_ms, reason = False, 0, f"исключение: {exc}"

                            server_details.append((srv, ok, lat_ms, reason))
                            if ok:
                                rescued += 1
                                latencies.append(lat_ms)
                                rescued_servers.append((srv, lat_ms))
                                server_rescue_map.setdefault(srv.server, []).append((strat.number, lat_ms))
                            else:
                                failed_reasons[reason] = failed_reasons.get(reason, 0) + 1

                    avg_lat = int(sum(latencies) / len(latencies)) if latencies else 0
                    rate = rescued / len(selected) if selected else 0
                    score = calculate_strategy_score(rescued, len(selected), avg_lat)
                    r = StrategyRating(
                        strategy_number=strat.number,
                        strategy_name=strat.name,
                        family_name=strat.technical_family,
                        rescued_count=rescued,
                        total_tested=len(selected),
                        success_rate=rate,
                        avg_latency_ms=avg_lat,
                        score=score,
                        status="TOP" if score >= 80 else ("ACTIVE" if rescued > 0 else "DEAD"),
                        consecutive_failures=0 if rescued > 0 else 1,
                        last_tested=_dt.datetime.now().isoformat(),
                        last_success=_dt.datetime.now().isoformat() if rescued > 0 else "",
                    )
                    ratings.append(r)
                    pct = int(rate * 100)
                    lat_str = f"{avg_lat} мс" if avg_lat > 0 else "—"
                    print(
                        f"    -> Спасено: {rescued}/{len(selected)} ({pct}%), "
                        f"задержка: {lat_str}, скор: {score}"
                    )

                    # Вывод спасенных узлов
                    if rescued_servers:
                        for srv, lat_val in rescued_servers:
                            print(f"       [+] Спасен: {srv.server}:{srv.server_port} ({lat_val} мс) — {srv.name[:35]}")

                    # Вывод причин сбоев
                    if failed_reasons:
                        reasons_str = ", ".join(
                            f"{reason}: {cnt}" for reason, cnt in sorted(failed_reasons.items(), key=lambda x: -x[1])
                        )
                        print(f"       [-] Причины сбоев: {reasons_str}")

                    # Детализация при --verbose
                    if getattr(args, "verbose", False):
                        for srv, ok, lat_val, reason in server_details:
                            mark = f"[+] {lat_val} мс" if ok else f"[-] {reason}"
                            print(f"           * {srv.server}:{srv.server_port} -> {mark}")
            except Exception as exc:
                print(f"    -> Ошибка запуска стратегии S{strat.number:02d}: {exc}")

    if profiler:
        profiler.disable()
        stats = pstats.Stats(profiler).strip_dirs()
        print("\n" + "=" * 60)
        print("### cProfile: Профилирование производительности бенчмарка")
        print("=" * 60)
        print("\n--- Топ-20 функций по CUMULATIVE TIME (общее время с подвызовами) ---")
        stats.sort_stats(pstats.SortKey.CUMULATIVE).print_stats(20)
        print("\n--- Топ-15 функций по INTERNAL TIME (собственное процессорное время) ---")
        stats.sort_stats(pstats.SortKey.TIME).print_stats(15)

    # Обновляем живой рейтинг строго для текущего провайдера
    living = living_ratings or AntidpiBenchmarkResult(
        tested_at=_dt.datetime.now().isoformat(),
        isp=current_isp.display_name,
        asn=current_isp.asn,
        isp_key=current_isp.key,
        best_strategy_number=None,
        ratings=[],
    )
    living.isp = current_isp.display_name
    living.asn = current_isp.asn
    living.isp_key = current_isp.key
    living.merge_benchmark_results(ratings)
    save_ratings(living, isp_identity=current_isp)

    print("\n" + "=" * 60)
    print(format_benchmark_table(living))
    print("=" * 60)

    if server_rescue_map:
        print("\n### Спасенные серверы и эффективные стратегии:")
        for srv in selected:
            if srv.server in server_rescue_map:
                res_list = server_rescue_map[srv.server]
                res_str = ", ".join(f"S{num:02d} ({lat} мс)" for num, lat in res_list)
                best_s = min(res_list, key=lambda x: x[1])
                print(f"  - {srv.server}:{srv.server_port} ({srv.name[:35]}): {res_str} -> лучшая S{best_s[0]:02d}")

    best_num = living.best_strategy_number
    best_entry = next((r for r in living.ratings if r.strategy_number == best_num), None) if best_num else None

    if best_entry and best_entry.score > 0:
        print(
            f"\n[+] Рекомендуемая лучшая стратегия для вашего провайдера: S{best_num:02d} "
            f"({best_entry.strategy_name})"
        )
        print("    Живой рейтинг сохранен в data/antidpi_ratings.json.")
        print("\n>>> Для применения спасения запустите основной сбор: run.cmd <<<")
    else:
        print(f"\n[-] Ни одна из проверенных стратегий не оживила узлы на данном этапе ({cfg.title}).")
        if cfg.next_cmd_file:
            print("\n" + "!" * 65)
            print("  Рекомендуется запустить следующий уровень калибровки:")
            print(f"  Дважды кликните '{cfg.next_cmd_file}' в папке проекта")
            print("!" * 65)
        else:
            print("\n" + "!" * 65)
            print("  Внимание: Все 484 стратегии каталога дали 0% успеха.")
            print("  Вердикт: ТСПУ вашего интернет-провайдера полностью блокирует Reality/TLS,")
            print("  либо целевые прокси-серверы недоступны со стороны дата-центров.")
            print("!" * 65)

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    if not is_admin() and not getattr(args, "no_elevate", False):
        print("=" * 70)
        print("  proxy-probe: Запрос прав Администратора для WinDivert (Zapret2)")
        print("  Пожалуйста, подтвердите UAC (нажмите 'Да') в системном окне на экране...")
        print("=" * 70)

        raw_argv = getattr(args, "_raw_argv", sys.argv[1:])
        extra_args = [arg for arg in raw_argv if arg != "--no-elevate"]
        if not extra_args or extra_args[0] != "serve":
            extra_args = ["serve", *extra_args]

        elev_params = subprocess.list2cmdline(["-m", "proxy_probe.antidpi", *extra_args])

        try:
            return run_elevated_and_wait(executable=sys.executable, params=elev_params, cwd=project_root())
        except PermissionError as exc:
            print(f"\n[!] {exc}", file=sys.stderr)
            return 1223
        except Exception as exc:
            print(f"\n[!] Ошибка вызова UAC: {exc}", file=sys.stderr)
            return 1

    return _run_serve(args)


def _run_serve(args: argparse.Namespace) -> int:
    current_isp = None
    with contextlib.suppress(Exception):
        current_isp = detect_current_isp(explicit_override=getattr(args, "isp", None))
    ratings = load_ratings(isp_identity=current_isp)
    strat_num = args.strategy or (ratings.best_strategy_number if ratings else 1) or 1
    strat = get_strategy_by_number(strat_num)
    if not strat:
        print(f"Стратегия S{strat_num:02d} не найдена в каталоге.", file=sys.stderr)
        return 1

    cache_path = default_cache_path()
    target_ips: set[str] = set()
    if cache_path.is_file():
        cache = ResultCache(path=cache_path)
        for entry in cache.entries.values():
            if entry.get("antidpi_strategy") is not None:
                raw_obj = entry.get("import_obj")
                if isinstance(raw_obj, dict):
                    h = raw_obj.get("server") or raw_obj.get("settings", {}).get("address")
                    if h:
                        target_ips.add(str(h))

    if not target_ips and cache_path.is_file():
        cache = ResultCache(path=cache_path)
        for entry in cache.entries.values():
            if entry.get("result") == "DEAD":
                raw_obj = entry.get("import_obj")
                if isinstance(raw_obj, dict):
                    h = raw_obj.get("server") or raw_obj.get("settings", {}).get("address")
                    if h:
                        target_ips.add(str(h))

    if not target_ips:
        print("Внимание: список целевых IP серверов пуст. Релей не может быть запущен без целей.", file=sys.stderr)
        return 1

    zapret_dir = ensure_zapret_binaries()
    cleanup_stale_windivert_service(zapret_dir)

    print("Запуск изолированного Zapret2-релея:")
    print(f"  - Порт: {DEFAULT_RELAY_HOST}:{args.port} (SOCKS5)")
    print(f"  - Стратегия: S{strat.number:02d} ({strat.name})")
    print(f"  - Целевых серверов в фильтре WinDivert: {len(target_ips)}")
    print("\nДля остановки нажмите Ctrl+C...")

    try:
        with (
            ZapretRelay(port=args.port),
            WinwsRunner(strategy=strat, target_ips=target_ips, zapret_dir=zapret_dir),
        ):
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nОстановка релея по запросу пользователя. WinDivert выгружен.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="proxy_probe.antidpi", description="Изолированный Anti-DPI релей и бенчмарк")
    sub = parser.add_subparsers(dest="command")

    p_up = sub.add_parser("update", help="Обновить каталог 484 стратегий из репозитория igareck")
    p_up.set_defaults(func=cmd_update)

    p_bench = sub.add_parser("benchmark", help="Калибровка Anti-DPI стратегий на серверах со статусом DEAD")
    p_bench.add_argument(
        "--level",
        type=int,
        choices=[2, 3, 4],
        default=2,
        help="Уровень калибровки: 2 (экспресс ~1.5м), 3 (широкий по пулу ~4-5м), 4 (глубокий 484 стратегии ~20-25м)",
    )
    p_bench.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Максимум тестируемых DEAD-серверов (по умолчанию из уровня)",
    )
    p_bench.add_argument(
        "--top",
        type=int,
        default=None,
        help="Ограничить количество проверяемых стратегий (по умолчанию из уровня)",
    )
    p_bench.add_argument(
        "--relay-port",
        type=int,
        default=DEFAULT_RELAY_PORT,
        help="Порт локального релея (по умолчанию 10850)",
    )
    p_bench.add_argument("--profile", action="store_true", help="Включить детальное профилирование через cProfile")
    p_bench.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Таймаут проверки прокси-туннеля (по умолчанию из уровня)",
    )
    p_bench.add_argument(
        "--concurrency",
        type=int,
        default=15,
        help="Количество параллельных проверок серверов (по умолчанию 15)",
    )
    p_bench.add_argument(
        "--no-tcp-verify",
        action="store_true",
        help="Отключить быструю проверку L4 TCP связности перед запуском бенчмарка",
    )
    p_bench.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Подробная детализация причин сбоев по каждому серверу в консоли",
    )
    p_bench.add_argument(
        "--no-elevate",
        action="store_true",
        help="Не запрашивать повышение прав через UAC автоматически",
    )
    p_bench.add_argument(
        "--isp",
        type=str,
        default=None,
        help="Принудительно указать имя/ASN провайдера (по умолчанию автодетект Ingress сети)",
    )
    p_bench.add_argument(
        "--log-output",
        type=str,
        default=None,
        help=argparse.SUPPRESS,
    )
    p_bench.set_defaults(func=cmd_benchmark)

    p_serve = sub.add_parser("serve", help="Запустить постоянный изолированный локальный SOCKS5-релей")
    p_serve.add_argument("--port", type=int, default=DEFAULT_RELAY_PORT, help="Порт SOCKS5 (по умолчанию 10850)")
    p_serve.add_argument("--strategy", type=int, default=None, help="Номер стратегии (по умолчанию лучшая из рейтинга)")
    p_serve.add_argument(
        "--isp",
        type=str,
        default=None,
        help="Принудительно указать имя/ASN провайдера для выбора лучшей стратегии",
    )
    p_serve.add_argument(
        "--no-elevate",
        action="store_true",
        help="Не запрашивать повышение прав через UAC автоматически",
    )
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    args._raw_argv = list(argv) if argv is not None else sys.argv[1:]
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
