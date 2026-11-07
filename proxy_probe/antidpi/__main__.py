from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import logging
import sys
import time

from ..cache import ResultCache, default_cache_path
from ..parsers import extract_host_port
from .benchmark import (
    calculate_strategy_score,
    default_ratings_path,
    format_benchmark_table,
    load_ratings,
    probe_proxy_tunnel,
    save_ratings,
    select_dead_servers,
)
from .catalogue import fetch_catalogue, get_golden_strategies, get_strategy_by_number
from .engine import WinwsRunner, ensure_zapret_binaries
from .models import AntidpiBenchmarkResult, StrategyRating
from .relay import DEFAULT_RELAY_HOST, DEFAULT_RELAY_PORT, ZapretRelay

logger = logging.getLogger("proxy_probe.antidpi")


def cmd_update(args: argparse.Namespace) -> int:
    print("Обновление каталога Anti-DPI стратегий из upstream...")
    try:
        profiles = fetch_catalogue()
        golden = [p for p in profiles if p.is_golden]
        total = len(profiles)
        g_len = len(golden)
        s_len = total - g_len
        print(f"Успешно обновлено: {total} стратегий ({g_len} Golden, {s_len} Silver).")
        return 0
    except Exception as e:
        print(f"Ошибка обновления каталога: {e}", file=sys.stderr)
        return 1


def cmd_benchmark(args: argparse.Namespace) -> int:
    cache_path = default_cache_path()
    if not cache_path.is_file():
        print(f"Файл кэша {cache_path} не найден. Сначала выполните прогон proxy-probe.", file=sys.stderr)
        return 1

    cache = ResultCache(path=cache_path)
    from ..models import Server

    dead_candidates: list[Server] = []
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
        dead_candidates.append(s)

    selected = select_dead_servers(dead_candidates, limit=args.limit)
    if not selected:
        print("В базе кэша не найдено серверов с сетевым таймаутом (DEAD). Тестирование не требуется.")
        return 0

    print(f"Отобрано {len(selected)} уникальных серверов со статусом DEAD для бенчмарка стратегий:")
    for s in selected:
        print(f"  - {s.server}:{s.server_port} ({s.name})")

    golden = get_golden_strategies()
    test_strategies = golden[: args.top]
    print(f"\nЗапуск бенчмарка по ТОП-{len(test_strategies)} Golden-стратегиям...")

    # Обеспечиваем наличие бинарников zapret2
    print("Проверка наличия бинарников Zapret2 (winws.exe, WinDivert)...")
    zapret_dir = ensure_zapret_binaries()

    target_ips = [s.server for s in selected if s.server]
    ports_str = ",".join(sorted({str(s.server_port) for s in selected if s.server_port})) or "443"
    ratings: list[StrategyRating] = []

    # Запускаем локальный релей
    relay_port = args.relay_port
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
                    workers = min(len(selected), 5)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                        futs = {
                            ex.submit(probe_proxy_tunnel, srv, relay_port=relay_port, timeout=2.5): srv
                            for srv in selected
                        }
                        for fut in concurrent.futures.as_completed(futs):
                            try:
                                ok, lat_ms = fut.result()
                                if ok:
                                    rescued += 1
                                    latencies.append(lat_ms)
                            except Exception:
                                pass

                    avg_lat = int(sum(latencies) / len(latencies)) if latencies else 0
                    rate = rescued / len(selected) if selected else 0
                    score = calculate_strategy_score(rescued, len(selected), avg_lat)
                    r = StrategyRating(
                        strategy_number=strat.number,
                        strategy_name=strat.name,
                        family_name=strat.family_name,
                        rescued_count=rescued,
                        total_tested=len(selected),
                        success_rate=rate,
                        avg_latency_ms=avg_lat,
                        score=score,
                    )
                    ratings.append(r)
                    pct = int(rate * 100)
                    print(
                        f"    -> Спасено: {rescued}/{len(selected)} ({pct}%), "
                        f"задержка: {avg_lat} мс, скор: {score}"
                    )
            except Exception as exc:
                print(f"    -> Ошибка запуска стратегии S{strat.number:02d}: {exc}")

    # Сортируем рейтинг
    ratings.sort(key=lambda r: (-r.rescued_count, -r.score, r.avg_latency_ms if r.avg_latency_ms > 0 else 99999))
    best_num = ratings[0].strategy_number if ratings and ratings[0].rescued_count > 0 else None

    bench_res = AntidpiBenchmarkResult(
        tested_at=_dt.datetime.now().isoformat(),
        isp="AutoDetected",
        best_strategy_number=best_num,
        ratings=ratings,
    )
    save_ratings(bench_res)

    print("\n" + "=" * 60)
    print(format_benchmark_table(bench_res))
    print("=" * 60)
    if best_num:
        print(f"\nРекомендуемая лучшая стратегия для вашего провайдера: S{best_num:02d}")
    else:
        print("\nНи одна из стратегий не смогла оживить выбранные серверы на данном этапе.")

    print(f"Рейтинг сохранен в {default_ratings_path()}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    ratings = load_ratings()
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
        # Фоллбэк: если конкретных IP с меткой antidpi еще нет, берем все DEAD из кэша
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

    print("Запуск изолированного Zapret2-релея:")
    print(f"  - Порт релея: {DEFAULT_RELAY_HOST}:{args.port} (SOCKS5)")
    print(f"  - Стратегия: S{strat.number:02d} ({strat.name})")
    print(f"  - Защищенный белый список WinDivert: {len(target_ips)} целевых IP серверов")
    print("  - Системный трафик (игры, браузеры, банки): 100% МИМО WinDivert")
    print("\nНажмите Ctrl+C для остановки релея...")

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

    p_bench = sub.add_parser("benchmark", help="Прогнать бенчмарк ТОП-стратегий на серверах со статусом DEAD")
    p_bench.add_argument("--limit", type=int, default=15, help="Максимум тестируемых DEAD-серверов (по умолчанию 15)")
    p_bench.add_argument(
        "--top", type=int, default=10, help="Количество проверяемых Golden-стратегий (по умолчанию 10)"
    )
    p_bench.add_argument(
        "--relay-port",
        type=int,
        default=DEFAULT_RELAY_PORT,
        help="Порт локального релея (по умолчанию 10850)",
    )
    p_bench.set_defaults(func=cmd_benchmark)

    p_serve = sub.add_parser("serve", help="Запустить постоянный изолированный локальный SOCKS5-релей")
    p_serve.add_argument("--port", type=int, default=DEFAULT_RELAY_PORT, help="Порт SOCKS5 (по умолчанию 10850)")
    p_serve.add_argument("--strategy", type=int, default=None, help="Номер стратегии (по умолчанию лучшая из рейтинга)")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
