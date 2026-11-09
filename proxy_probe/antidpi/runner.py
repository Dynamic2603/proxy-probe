from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import cProfile
import dataclasses
import datetime as _dt
import json
import logging
import os
import pstats
import re
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from rich.panel import Panel
from tqdm import tqdm

from ..cache import ResultCache, default_cache_path, server_from_cache_entry
from ..engines import clean_proxy_env, project_root
from ..models import RESULT_DEAD, Server
from ..parsers import extract_host_port
from ..ui import console, print_benchmark_results_panel
from .benchmark import (
    calculate_strategy_score,
    default_ratings_path,
    load_ratings,
    prepare_strategies_for_level,
    probe_proxy_tunnel,
    save_ratings,
    select_dead_servers,
)
from .catalogue import fetch_catalogue, get_strategy_by_number, load_catalogue
from .elevation import (
    TeeOutput,
    is_admin,
    is_process_alive,
    run_elevated_and_wait,
    run_elevated_detached,
)
from .engine import (
    WinwsRunner,
    cleanup_stale_windivert_service,
    default_zapret_dir,
    ensure_zapret_binaries,
)
from .isp import IspDetectionError, detect_current_isp
from .models import (
    CALIBRATION_LEVELS,
    AntidpiBenchmarkResult,
    StrategyRating,
)
from .relay import DEFAULT_RELAY_HOST, DEFAULT_RELAY_PORT, ZapretRelay, is_port_in_use

logger = logging.getLogger("proxy_probe.antidpi")

DEFAULT_RELAY_STATE_FILENAME = "relay_state.json"
CREATE_NO_WINDOW = 0x08000000


@dataclasses.dataclass(frozen=True, slots=True)
class RelayState:
    pid: int
    singbox_pid: int | None
    winws_pid: int | None
    port: int
    host: str
    strategy_number: int
    strategy_name: str
    isp: str
    target_ips_count: int
    started_at: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RelayState:
        return cls(
            pid=int(data.get("pid", 0)),
            singbox_pid=int(data["singbox_pid"]) if data.get("singbox_pid") is not None else None,
            winws_pid=int(data["winws_pid"]) if data.get("winws_pid") is not None else None,
            port=int(data.get("port", DEFAULT_RELAY_PORT)),
            host=str(data.get("host", DEFAULT_RELAY_HOST)),
            strategy_number=int(data.get("strategy_number", 1)),
            strategy_name=str(data.get("strategy_name", "")),
            isp=str(data.get("isp", "")),
            target_ips_count=int(data.get("target_ips_count", 0)),
            started_at=str(data.get("started_at", "")),
        )


def default_relay_state_path() -> Path:
    """Возвращает путь к файлу состояния фонового релея (data/relay_state.json)."""
    return project_root() / "data" / DEFAULT_RELAY_STATE_FILENAME


def load_relay_state(path: Path | None = None) -> RelayState | None:
    """Читает сохранённое состояние фонового релея."""
    p = path or default_relay_state_path()
    if not p.is_file():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return RelayState.from_dict(raw)
    except Exception as exc:
        logger.debug("Не удалось прочитать relay_state.json: %s", exc)
    return None


def save_relay_state(state: RelayState, path: Path | None = None) -> None:
    """Атомарно сохраняет состояние запущенного фонового релея."""
    p = path or default_relay_state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def clear_relay_state(path: Path | None = None) -> None:
    """Удаляет файл состояния фонового релея."""
    p = path or default_relay_state_path()
    with contextlib.suppress(OSError):
        p.unlink(missing_ok=True)


def is_relay_running(
    port: int = DEFAULT_RELAY_PORT,
    host: str = DEFAULT_RELAY_HOST,
    state_path: Path | None = None,
) -> bool:
    """Проверяет, активен ли фоновый релей (слушается ли порт и жив ли процесс winws2)."""
    if not is_port_in_use(port, host):
        clear_relay_state(state_path)
        return False
    state = load_relay_state(state_path)
    return not (state is not None and state.winws_pid is not None and not is_process_alive(state.winws_pid))


@contextlib.contextmanager
def suspend_background_relay(
    relay_port: int = DEFAULT_RELAY_PORT,
    isp: str | None = None,
    strategy: int | None = None,
) -> Iterator[bool]:
    """Временно приостанавливает фоновый релей на время прогона Stage 2 или калибровки и перезапускает его после."""
    was_running = is_relay_running(port=relay_port)
    prev_state = load_relay_state() if was_running else None
    if was_running:
        console.print("[dim]Приостановка фонового релея Zapret2 на время проверки...[/dim]")
        stop_args = argparse.Namespace(
            antidpi_port=relay_port,
            no_elevate=False,
            quiet=True,
        )
        stop_relay_service(stop_args)
    try:
        yield was_running
    finally:
        if was_running:
            console.print("[dim]Перезапуск фонового релея Zapret2 с обновлённым пулом...[/dim]")
            restart_args = argparse.Namespace(
                antidpi_port=relay_port,
                antidpi_strategy=strategy or (prev_state.strategy_number if prev_state else None),
                isp=isp or (prev_state.isp if prev_state else None),
                detach=True,
                no_elevate=False,
                cache=None,
            )
            run_relay_service(restart_args)


@dataclasses.dataclass(frozen=True, slots=True)
class StrategyProbeSummary:
    rescued: int
    latencies: list[int]
    rescued_servers: list[tuple[Server, int]]
    failed_reasons: dict[str, int]
    server_details: list[tuple[Server, bool, int, str]]


def _probe_strategy_servers(
    selected: list[Server],
    relay_port: int,
    probe_timeout: float,
    workers: int,
) -> StrategyProbeSummary:
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
            else:
                failed_reasons[reason] = failed_reasons.get(reason, 0) + 1

    return StrategyProbeSummary(
        rescued=rescued,
        latencies=latencies,
        rescued_servers=rescued_servers,
        failed_reasons=failed_reasons,
        server_details=server_details,
    )


def _log_strategy_summary(
    total_selected: int,
    rating: StrategyRating,
    summary: StrategyProbeSummary,
    verbose: bool,
) -> None:
    pct = int(rating.success_rate * 100)
    lat_str = f"{rating.avg_latency_ms} мс" if rating.avg_latency_ms > 0 else "—"
    color = "green" if summary.rescued > 0 else "dim"
    console.print(
        f"  [{color}]-> S{rating.strategy_number:02d}: спасено {summary.rescued}/{total_selected} ({pct}%), "
        f"задержка: {lat_str}, скор: {rating.score}[/{color}]"
    )
    for srv, lat_val in summary.rescued_servers:
        console.print(f"     [green][+] Спасен:[/green] {srv.host_port} ({lat_val} мс) — {srv.name[:35]}")

    if summary.failed_reasons and verbose:
        sorted_reasons = sorted(summary.failed_reasons.items(), key=lambda x: -x[1])
        reasons_str = ", ".join(f"{reason}: {cnt}" for reason, cnt in sorted_reasons)
        console.print(f"     [dim][-] Причины сбоев: {reasons_str}[/dim]")
        for srv, ok, lat_val, reason in summary.server_details:
            mark = f"[green][+] {lat_val} мс[/green]" if ok else f"[red][-] {reason}[/red]"
            console.print(f"         * {srv.host_port} -> {mark}")


def collect_dead_candidates(cache: ResultCache) -> list[Server]:
    """Собирает список серверов-кандидатов для Anti-DPI бенчмарка (SSOT)."""
    candidates: list[Server] = []
    seen_identities: set[str] = set()

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

    if not candidates:
        for entry in cache.entries.values():
            srv = server_from_cache_entry(entry, require_endpoint=True)
            if srv is None:
                continue
            cid = srv.config_identity
            if cid in seen_identities:
                continue
            seen_identities.add(cid)
            candidates.append(srv)

    return candidates


def run_catalogue_update() -> int:
    """Обновляет каталог 484 стратегий Anti-DPI из upstream."""
    console.print("[bold cyan]Обновление каталога Anti-DPI стратегий из upstream...[/bold cyan]")
    try:
        profiles = fetch_catalogue()
        total = len(profiles)
        fams = len({p.technical_family for p in profiles})
        console.print(
            f"[bold green]✓ Каталог успешно обновлён:[/bold green] {total} стратегий "
            f"({fams} уникальных технических семейств)."
        )
        return 0
    except Exception as exc:
        console.print(f"[bold red]Ошибка обновления каталога:[/bold red] {exc}")
        return 1


def run_calibration(args: argparse.Namespace) -> int:
    """Запускает калибровку стратегий Anti-DPI (с автоматическим повышением прав UAC при необходимости)."""
    level = int(getattr(args, "calibrate", None) or getattr(args, "level", 2) or 2)
    relay_port = int(getattr(args, "antidpi_port", DEFAULT_RELAY_PORT) or DEFAULT_RELAY_PORT)

    with suspend_background_relay(relay_port=relay_port, isp=getattr(args, "isp", None)):
        if not is_admin() and not getattr(args, "no_elevate", False):
            log_path = default_ratings_path().parent / "benchmark_run.log"
            if log_path.is_file():
                with contextlib.suppress(Exception):
                    log_path.unlink()

            console.print(
                Panel(
                    "Запрос прав Администратора для драйвера WinDivert (Zapret2).\n"
                    "Пожалуйста, подтвердите UAC (нажмите «Да») в системном окне...",
                    title="[bold cyan]proxy-probe: Калибровка Anti-DPI[/bold cyan]",
                    border_style="cyan",
                )
            )

            elev_args = ["-m", "proxy_probe", "--calibrate", str(level), "--no-pause"]
            if getattr(args, "antidpi_limit", 0):
                elev_args.extend(["--antidpi-limit", str(args.antidpi_limit)])
            if getattr(args, "antidpi_top", None):
                elev_args.extend(["--antidpi-top", str(args.antidpi_top)])
            if relay_port != DEFAULT_RELAY_PORT:
                elev_args.extend(["--antidpi-port", str(relay_port)])
            if getattr(args, "isp", None):
                elev_args.extend(["--isp", str(args.isp)])
            if getattr(args, "verbose", False):
                elev_args.append("--verbose")
            elev_args.extend(["--log-output", str(log_path)])

            elev_params = subprocess.list2cmdline(elev_args)
            try:
                rc = run_elevated_and_wait(executable=sys.executable, params=elev_params, cwd=project_root())
                if log_path.is_file():
                    with contextlib.suppress(Exception):
                        content = log_path.read_text(encoding="utf-8", errors="replace")
                        if content.strip():
                            print(content)
                return rc
            except PermissionError as exc:
                console.print(f"\n[yellow]⚠ {exc}[/yellow]")
                return 1223
            except Exception as exc:
                console.print(f"\n[bold red]Ошибка вызова UAC:[/bold red] {exc}")
                return 1

        log_out = getattr(args, "log_output", None)
        cm = TeeOutput(Path(log_out)) if log_out else contextlib.nullcontext()
        with cm:
            return _execute_calibration(args, level=level)


def _execute_calibration(args: argparse.Namespace, level: int) -> int:
    cfg = CALIBRATION_LEVELS.get(level, CALIBRATION_LEVELS[2])
    console.print(Panel(f"[bold]{cfg.title}[/bold]", border_style="cyan"))

    try:
        current_isp = detect_current_isp(explicit_override=getattr(args, "isp", None))
        console.print(
            f"[green]✓ Провайдер:[/green] [bold]{current_isp.display_name}[/bold] "
            f"(IP: {current_isp.ingress_ip or '—'})"
        )
    except IspDetectionError as err:
        console.print(f"[bold red]Ошибка определения входящего интернет-провайдера:[/bold red]\n{err}")
        return 1

    cache_path = Path(args.cache) if getattr(args, "cache", None) else default_cache_path()
    if not cache_path.is_file():
        console.print(
            f"[yellow]Файл кэша {cache_path} не найден. "
            "Сначала выполните проверку прокси-пула (пункт 1 главного меню).[/yellow]"
        )
        return 1

    cache = ResultCache(path=cache_path)
    dead_candidates = collect_dead_candidates(cache)

    verify_tcp = not getattr(args, "no_tcp_prefilter", False)
    raw_limit = getattr(args, "antidpi_limit", 0)
    server_limit = raw_limit if raw_limit and raw_limit > 0 else cfg.server_limit
    selected = select_dead_servers(dead_candidates, limit=server_limit, verify_tcp=verify_tcp)
    if not selected:
        console.print("[yellow]В базе кэша не найдено серверов со статусом DEAD и открытым TCP-портом.[/yellow]")
        return 0

    console.print(f"Отобрано [bold]{len(selected)}[/bold] серверов со статусом DEAD для калибровки.")

    catalogue = load_catalogue()
    living_ratings = load_ratings(isp_identity=current_isp)
    test_strategies = prepare_strategies_for_level(level, catalogue, living_ratings)
    top_limit = getattr(args, "antidpi_top", None)
    if top_limit is not None and top_limit > 0:
        test_strategies = test_strategies[:top_limit]

    zapret_dir = ensure_zapret_binaries()
    cleanup_stale_windivert_service(zapret_dir)

    target_ips = [s.server for s in selected if s.server]
    ports = sorted({str(s.server_port) for s in selected if s.server_port})[:20]
    ports_str = ",".join(ports) or "443"
    ratings: list[StrategyRating] = []
    server_rescue_map: dict[str, list[tuple[int, int]]] = {}

    relay_port = int(getattr(args, "antidpi_port", DEFAULT_RELAY_PORT) or DEFAULT_RELAY_PORT)
    workers = min(len(selected), int(getattr(args, "jobs", 15) or 15))
    probe_timeout = float(cfg.timeout)
    enable_profile = bool(getattr(args, "profile", False))
    profiler = cProfile.Profile() if enable_profile else None
    if profiler:
        profiler.enable()

    pbar = tqdm(total=len(test_strategies), desc="Калибровка стратегий", unit="strat", dynamic_ncols=True)
    try:
        with ZapretRelay(port=relay_port):
            for strat in test_strategies:
                pbar.set_postfix_str(f"S{strat.number:02d} {strat.name[:28]}", refresh=True)
                try:
                    with WinwsRunner(
                        strategy=strat,
                        target_ips=target_ips,
                        zapret_dir=zapret_dir,
                        ports=ports_str,
                    ):
                        summary = _probe_strategy_servers(selected, relay_port, probe_timeout, workers)
                        for srv, lat_ms in summary.rescued_servers:
                            server_rescue_map.setdefault(srv.server, []).append((strat.number, lat_ms))

                        avg_lat = int(sum(summary.latencies) / len(summary.latencies)) if summary.latencies else 0
                        rate = summary.rescued / len(selected) if selected else 0.0
                        score = calculate_strategy_score(summary.rescued, len(selected), avg_lat)
                        now_iso = _dt.datetime.now().isoformat()
                        r = StrategyRating(
                            strategy_number=strat.number,
                            strategy_name=strat.name,
                            family_name=strat.technical_family,
                            rescued_count=summary.rescued,
                            total_tested=len(selected),
                            success_rate=rate,
                            avg_latency_ms=avg_lat,
                            score=score,
                            status="TOP" if score >= 80 else ("ACTIVE" if summary.rescued > 0 else "DEAD"),
                            consecutive_failures=0 if summary.rescued > 0 else 1,
                            last_tested=now_iso,
                            last_success=now_iso if summary.rescued > 0 else "",
                        )
                        ratings.append(r)
                        if summary.rescued > 0 or getattr(args, "verbose", False):
                            _log_strategy_summary(
                                total_selected=len(selected),
                                rating=r,
                                summary=summary,
                                verbose=bool(getattr(args, "verbose", False)),
                            )
                except Exception as exc:
                    console.print(f"  [yellow]Ошибка запуска S{strat.number:02d}: {exc}[/yellow]")
                pbar.update(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Калибровка прервана пользователем (Ctrl+C). Сохранение результатов...[/yellow]")
    finally:
        pbar.close()

    if profiler:
        profiler.disable()
        stats = pstats.Stats(profiler).strip_dirs()
        stats.sort_stats(pstats.SortKey.CUMULATIVE).print_stats(20)

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

    print_benchmark_results_panel(living, selected, server_rescue_map, cfg)
    return 0


def _collect_relay_target_ips(cache_path: Path) -> set[str]:
    target_ips: set[str] = set()
    if not cache_path.is_file():
        return target_ips
    cache = ResultCache(path=cache_path)
    for entry in cache.entries.values():
        if entry.get("antidpi_strategy") is not None:
            raw_obj = entry.get("import_obj")
            if isinstance(raw_obj, dict):
                h, _ = extract_host_port(raw_obj)
                if h:
                    target_ips.add(h)

    if not target_ips:
        for entry in cache.entries.values():
            if entry.get("result") == RESULT_DEAD:
                raw_obj = entry.get("import_obj")
                if isinstance(raw_obj, dict):
                    h, _ = extract_host_port(raw_obj)
                    if h:
                        target_ips.add(h)
    return target_ips


def _wait_for_detached_relay(relay_port: int, spawned_pid: int, timeout: float = 10.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if is_relay_running(port=relay_port):
            return True
        if spawned_pid > 0 and not is_process_alive(spawned_pid):
            return False
        time.sleep(0.1)
    return is_relay_running(port=relay_port)


def run_relay_service(args: argparse.Namespace) -> int:
    """Запускает постоянный изолированный локальный SOCKS5-релей Zapret2
    (в фоне при --detach или в текущем процессе).
    """
    relay_port = int(getattr(args, "antidpi_port", DEFAULT_RELAY_PORT) or DEFAULT_RELAY_PORT)
    if is_relay_running(port=relay_port):
        state = load_relay_state()
        strat_txt = f" (стратегия S{state.strategy_number:02d})" if state else ""
        console.print(
            f"[bold yellow]Фоновый релей Zapret2 уже работает на "
            f"{DEFAULT_RELAY_HOST}:{relay_port}{strat_txt}.[/bold yellow]"
        )
        return 0

    detach = bool(getattr(args, "detach", False))

    if not is_admin() and not getattr(args, "no_elevate", False):
        console.print(
            Panel(
                "Запрос прав Администратора для запуска релея WinDivert (Zapret2).\n"
                "Пожалуйста, подтвердите UAC (нажмите «Да») в системном окне...",
                title="[bold cyan]proxy-probe: Запуск релея Zapret2[/bold cyan]",
                border_style="cyan",
            )
        )
        elev_args = ["-m", "proxy_probe", "--serve", "--antidpi-port", str(relay_port), "--no-pause"]
        if getattr(args, "antidpi_strategy", None):
            elev_args.extend(["--antidpi-strategy", str(args.antidpi_strategy)])
        if getattr(args, "isp", None):
            elev_args.extend(["--isp", str(args.isp)])

        elev_params = subprocess.list2cmdline(elev_args)
        try:
            if detach:
                pid = run_elevated_detached(
                    executable=sys.executable,
                    params=elev_params,
                    cwd=project_root(),
                    show_window=False,
                )
                if _wait_for_detached_relay(relay_port, pid, timeout=10.0):
                    st = load_relay_state()
                    s_info = f"S{st.strategy_number:02d} ({st.strategy_name})" if st else "активна"
                    console.print(
                        Panel(
                            f"• [bold cyan]Порт SOCKS5:[/bold cyan] {DEFAULT_RELAY_HOST}:{relay_port}\n"
                            f"• [bold cyan]Стратегия:[/bold cyan] {s_info}\n"
                            f"• [bold cyan]PID процесса:[/bold cyan] {st.pid if st else pid}",
                            title="[bold green]✓ Фоновый релей Zapret2 запущен[/bold green]",
                            border_style="green",
                        )
                    )
                    return 0
                console.print("[bold red]Не удалось дождаться открытия порта фонового релея.[/bold red]")
                return 1
            return run_elevated_and_wait(executable=sys.executable, params=elev_params, cwd=project_root())
        except PermissionError as exc:
            console.print(f"\n[yellow]⚠ {exc}[/yellow]")
            return 1223
        except Exception as exc:
            console.print(f"\n[bold red]Ошибка вызова UAC:[/bold red] {exc}")
            return 1

    if detach:
        bg_args = [
            sys.executable,
            "-m",
            "proxy_probe",
            "--serve",
            "--antidpi-port",
            str(relay_port),
            "--no-elevate",
            "--no-pause",
        ]
        if getattr(args, "antidpi_strategy", None):
            bg_args.extend(["--antidpi-strategy", str(args.antidpi_strategy)])
        if getattr(args, "isp", None):
            bg_args.extend(["--isp", str(args.isp)])
        flags = CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(
            bg_args,
            cwd=str(project_root()),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
            env=clean_proxy_env(),
        )
        if _wait_for_detached_relay(relay_port, proc.pid, timeout=10.0):
            st = load_relay_state()
            s_info = f"S{st.strategy_number:02d} ({st.strategy_name})" if st else "активна"
            console.print(
                Panel(
                    f"• [bold cyan]Порт SOCKS5:[/bold cyan] {DEFAULT_RELAY_HOST}:{relay_port}\n"
                    f"• [bold cyan]Стратегия:[/bold cyan] {s_info}\n"
                    f"• [bold cyan]PID процесса:[/bold cyan] {proc.pid}",
                    title="[bold green]✓ Фоновый релей Zapret2 запущен[/bold green]",
                    border_style="green",
                )
            )
            return 0
        console.print("[bold red]Не удалось запустить фоновый релей Zapret2.[/bold red]")
        return 1

    try:
        current_isp = detect_current_isp(explicit_override=getattr(args, "isp", None))
    except IspDetectionError as err:
        print(f"Ошибка определения провайдера: {err}", file=sys.stderr)
        return 1

    ratings = load_ratings(isp_identity=current_isp)
    strat_num = getattr(args, "antidpi_strategy", None) or (ratings.best_strategy_number if ratings else 1) or 1
    strat = get_strategy_by_number(strat_num)
    if not strat:
        print(f"Стратегия S{strat_num:02d} не найдена в каталоге.", file=sys.stderr)
        return 1

    cache_path = Path(args.cache) if getattr(args, "cache", None) else default_cache_path()
    target_ips = _collect_relay_target_ips(cache_path)
    if not target_ips:
        print("Внимание: список целевых IP серверов пуст. Релей не может быть запущен без целей.", file=sys.stderr)
        return 1

    zapret_dir = ensure_zapret_binaries()
    cleanup_stale_windivert_service(zapret_dir)

    console.print(
        Panel(
            f"• [bold cyan]Порт SOCKS5:[/bold cyan] {DEFAULT_RELAY_HOST}:{relay_port}\n"
            f"• [bold cyan]Провайдер:[/bold cyan] {current_isp.display_name}\n"
            f"• [bold cyan]Стратегия:[/bold cyan] S{strat.number:02d} ({strat.name})\n"
            f"• [bold cyan]Целевых IP в фильтре WinDivert:[/bold cyan] {len(target_ips)}\n\n"
            "[dim]Для остановки релея нажмите Ctrl+C или используйте: uv run pxp --stop-relay[/dim]",
            title="[bold green]Изолированный Zapret2-релей запущен[/bold green]",
            border_style="green",
        )
    )

    relay = ZapretRelay(port=relay_port)
    runner = WinwsRunner(strategy=strat, target_ips=target_ips, zapret_dir=zapret_dir)
    try:
        with relay, runner:
            state = RelayState(
                pid=os.getpid(),
                singbox_pid=relay.process.pid if relay.process else None,
                winws_pid=runner.process.pid if runner.process else None,
                port=relay_port,
                host=DEFAULT_RELAY_HOST,
                strategy_number=strat.number,
                strategy_name=strat.name,
                isp=current_isp.display_name,
                target_ips_count=len(target_ips),
                started_at=_dt.datetime.now().isoformat(timespec="seconds"),
            )
            save_relay_state(state)
            while True:
                if (relay.process and relay.process.poll() is not None) or (
                    runner.process and runner.process.poll() is not None
                ):
                    break
                time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[yellow]Остановка релея по запросу пользователя. Драйвер WinDivert выгружен.[/yellow]")
    finally:
        clear_relay_state()
    return 0


def _kill_pid_tree(pid: int | None) -> None:
    if not pid or pid <= 0 or pid == os.getpid():
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            check=False,
        )


def _stop_own_windivert_service(zapret_dir: Path | None = None) -> None:
    if os.name != "nt":
        return
    zdir = zapret_dir or default_zapret_dir()
    expected_sys = (zdir / "WinDivert64.sys").resolve()
    res = subprocess.run(["sc.exe", "qc", "WinDivert"], capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return
    match = re.search(r"BINARY_PATH_NAME\s*:\s*(.+)", res.stdout)
    if match:
        curr_raw = match.group(1).strip().strip('"')
        with contextlib.suppress(OSError):
            if Path(curr_raw).resolve() == expected_sys:
                subprocess.run(["sc.exe", "stop", "WinDivert"], capture_output=True, text=True, check=False)


def stop_relay_service(args: argparse.Namespace) -> int:
    """Штатно останавливает фоновый релей Zapret2, освобождает порт и выгружает драйвер WinDivert."""
    relay_port = int(getattr(args, "antidpi_port", DEFAULT_RELAY_PORT) or DEFAULT_RELAY_PORT)
    quiet = bool(getattr(args, "quiet", False))
    state = load_relay_state()
    port_busy = is_port_in_use(relay_port)

    if not port_busy and state is None:
        if not quiet:
            console.print("[dim]Фоновый релей Zapret2 не запущен.[/dim]")
        return 0

    if not is_admin() and not getattr(args, "no_elevate", False):
        if not quiet:
            console.print(
                Panel(
                    "Запрос прав Администратора для остановки релея и выгрузки драйвера WinDivert.\n"
                    "Пожалуйста, подтвердите UAC (нажмите «Да») в системном окне...",
                    title="[bold cyan]proxy-probe: Остановка релея Zapret2[/bold cyan]",
                    border_style="cyan",
                )
            )
        elev_params = subprocess.list2cmdline(
            ["-m", "proxy_probe", "--stop-relay", "--antidpi-port", str(relay_port), "--no-pause"]
        )
        try:
            rc = run_elevated_and_wait(executable=sys.executable, params=elev_params, cwd=project_root())
            if rc == 0 and not is_port_in_use(relay_port) and not quiet:
                console.print(
                    Panel(
                        f"Порт [bold]{DEFAULT_RELAY_HOST}:{relay_port}[/bold] освобождён, "
                        "процессы релея завершены, служба WinDivert остановлена.",
                        title="[bold green]✓ Фоновый релей Zapret2 остановлен[/bold green]",
                        border_style="green",
                    )
                )
            return rc
        except PermissionError as exc:
            console.print(f"\n[yellow]⚠ {exc}[/yellow]")
            return 1223
        except Exception as exc:
            console.print(f"\n[bold red]Ошибка вызова UAC при остановке релея:[/bold red] {exc}")
            return 1

    if state is not None:
        _kill_pid_tree(state.winws_pid)
        _kill_pid_tree(state.singbox_pid)
        _kill_pid_tree(state.pid)

    _stop_own_windivert_service()
    clear_relay_state()

    t0 = time.time()
    while time.time() - t0 < 2.5:
        if not is_port_in_use(relay_port):
            break
        time.sleep(0.1)

    if not quiet:
        console.print(
            Panel(
                f"Порт [bold]{DEFAULT_RELAY_HOST}:{relay_port}[/bold] освобождён, "
                "процессы релея завершены, служба WinDivert остановлена.",
                title="[bold green]✓ Фоновый релей Zapret2 остановлен[/bold green]",
                border_style="green",
            )
        )
    return 0


def print_relay_status(args: argparse.Namespace) -> int:
    """Выводит текущий статус фонового релея Zapret2 в консоль."""
    relay_port = int(getattr(args, "antidpi_port", DEFAULT_RELAY_PORT) or DEFAULT_RELAY_PORT)
    running = is_relay_running(port=relay_port)
    state = load_relay_state()

    if running:
        lines = [
            "• [bold cyan]Состояние:[/bold cyan] [bold green]● РАБОТАЕТ[/bold green]",
            f"• [bold cyan]Сокет SOCKS5:[/bold cyan] {DEFAULT_RELAY_HOST}:{relay_port}",
        ]
        if state:
            lines.extend(
                [
                    f"• [bold cyan]Провайдер:[/bold cyan] {state.isp or '—'}",
                    f"• [bold cyan]Стратегия:[/bold cyan] S{state.strategy_number:02d} ({state.strategy_name})",
                    f"• [bold cyan]Целевых IP в фильтре:[/bold cyan] {state.target_ips_count}",
                    f"• [bold cyan]PID (супервизор / sing-box / winws2):[/bold cyan] "
                    f"{state.pid} / {state.singbox_pid or '—'} / {state.winws_pid or '—'}",
                    f"• [bold cyan]Запущен:[/bold cyan] {state.started_at}",
                ]
            )
        border = "green"
    else:
        lines = [
            "• [bold cyan]Состояние:[/bold cyan] [dim]○ ОСТАНОВЛЕН[/dim]",
            f"• [bold cyan]Сокет SOCKS5:[/bold cyan] {DEFAULT_RELAY_HOST}:{relay_port} (свободен)",
        ]
        border = "dim"

    console.print(Panel("\n".join(lines), title="[bold]Статус фонового релея Zapret2[/bold]", border_style=border))
    return 0
