from __future__ import annotations

import concurrent.futures
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tqdm import tqdm

from ..cache import ResultCache, default_cache_path
from ..engines import alloc_port, project_root
from ..models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, STATE_ACTIVE, STATE_DEAD, Server
from ..prober import AGY_PRINT_TIMEOUT_DEFAULT, ProcessRegistry, QuotaCircuitBreaker, run_probe
from ..ui import console
from . import benchmark as _benchmark
from . import catalogue as _catalogue
from . import elevation as _elevation
from . import engine as _engine
from . import isp as _isp
from . import relay as _relay

if TYPE_CHECKING:
    from ..cli import RuntimeContext

ANTIDPI_BATCH_SIZE: int = 150
ANTIDPI_MAX_PORTS_PER_BATCH: int = 16


def chunk_candidates_by_limits(
    candidates: list[Server],
    max_ips: int = ANTIDPI_BATCH_SIZE,
    max_ports: int = ANTIDPI_MAX_PORTS_PER_BATCH,
) -> list[list[Server]]:
    """Формирует пачки кандидатов так, чтобы в каждой пачке было <= max_ips IP и <= max_ports уникальных портов."""
    batches: list[list[Server]] = []
    current_batch: list[Server] = []
    current_ips: set[str] = set()
    current_ports: set[int] = set()

    for srv in candidates:
        ip = srv.server
        port = srv.server_port or 443
        new_ips_len = len(current_ips) + (0 if ip in current_ips else 1)
        new_ports_len = len(current_ports) + (0 if port in current_ports else 1)

        if current_batch and (new_ips_len > max_ips or new_ports_len > max_ports):
            batches.append(current_batch)
            current_batch = []
            current_ips = set()
            current_ports = set()

        current_batch.append(srv)
        if ip:
            current_ips.add(ip)
        current_ports.add(port)

    if current_batch:
        batches.append(current_batch)
    return batches


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


def execute_antidpi_stage(
    servers: list[Server],
    to_probe: list[Server],
    ctx: RuntimeContext,
    timeouts: dict[str, float],
    print_timeout: str,
    circuit_breaker: QuotaCircuitBreaker | None = None,
) -> int:
    """Stage 2: Оживление DEAD серверов через изолированный Zapret2 SOCKS5-релей (SSOT)."""
    if not ctx.antidpi:
        return 0

    raw_candidates = [
        s
        for s in servers
        if s.result == RESULT_DEAD
        and s.server
        and not (s.note and (s.note.startswith("tcp:") or "L4 TCP" in s.note))
    ]
    if not raw_candidates:
        console.print(
            "[dim]Anti-DPI: серверов с открытым TCP сокетом для спасения нет, запуск релея не требуется.[/dim]"
        )
        return 0

    seen_endpoints: set[tuple[str, int]] = set()
    dead_candidates: list[Server] = []
    for s in raw_candidates:
        ep = (s.server, s.server_port)
        if ep not in seen_endpoints:
            seen_endpoints.add(ep)
            dead_candidates.append(s)

    limit = getattr(ctx, "antidpi_limit", 0)
    if limit > 0 and len(dead_candidates) > limit:
        dead_candidates = dead_candidates[:limit]

    if not dead_candidates:
        return 0

    from .runner import suspend_background_relay

    if not _elevation.is_admin() and getattr(ctx, "no_elevate", False):
        console.print(
            "[yellow]⚠ Stage 2 Anti-DPI пропущен: запуск без прав Администратора (--no-elevate).[/yellow]"
        )
        return 0

    with suspend_background_relay(
        relay_port=ctx.antidpi_port,
        isp=ctx.isp,
        strategy=ctx.antidpi_strategy,
    ):
        if not _elevation.is_admin():
            return delegate_stage2_elevated(
                dead_candidates=dead_candidates,
                servers=servers,
                to_probe=to_probe,
                ctx=ctx,
                timeouts=timeouts,
                print_timeout=print_timeout,
            )

        rescued_count = execute_antidpi_stage_core(
            dead_candidates=dead_candidates,
            to_probe=to_probe,
            ctx=ctx,
            timeouts=timeouts,
            print_timeout=print_timeout,
            circuit_breaker=circuit_breaker,
        )
    if rescued_count > 0:
        rescued_by_cid = {s.config_identity: s for s in dead_candidates if s.result == RESULT_OK}
        for s in servers:
            if s.result != RESULT_OK and s.config_identity in rescued_by_cid:
                src = rescued_by_cid[s.config_identity]
                s.result = src.result
                s.country = src.country
                s.ip_out = src.ip_out
                s.country_code = src.country_code
                s.city = src.city
                s.org = src.org
                s.latency_ms = src.latency_ms
                s.note = src.note
                s.web_status = src.web_status
                s.ingress_country_code = src.ingress_country_code
                s.ingress_ip = src.ingress_ip
                s.antidpi_strategy = src.antidpi_strategy
                s.state = src.state
                if s not in to_probe:
                    to_probe.append(s)
    return rescued_count


def delegate_stage2_elevated(
    dead_candidates: list[Server],
    servers: list[Server],
    to_probe: list[Server],
    ctx: RuntimeContext,
    timeouts: dict[str, float],
    print_timeout: str,
) -> int:
    stage_dir = Path(tempfile.gettempdir()) / "proxy-probe"
    stage_dir.mkdir(parents=True, exist_ok=True)
    pid = os.getpid()
    task_path = stage_dir / f"stage2_task_{pid}.json"
    result_path = stage_dir / f"stage2_result_{pid}.json"
    log_path = stage_dir / f"stage2_log_{pid}.log"

    task_data = {
        "cache_path": str(ctx.cache_path) if ctx.cache_path else "",
        "sb_exe": str(ctx.sb_exe) if ctx.sb_exe else "",
        "xr_exe": str(ctx.xr_exe) if ctx.xr_exe else "",
        "dead_candidates": [
            {
                "cache_key": s.cache_key,
                "config_identity": s.config_identity,
                "server": s.server,
                "server_port": s.server_port,
                "engine": s.engine,
                "import_obj": s.import_obj,
                "group_id": s.group_id,
                "group_name": s.group_name,
                "name": s.name,
                "source": s.source,
            }
            for s in dead_candidates
        ],
        "antidpi_strategy": ctx.antidpi_strategy,
        "antidpi_port": ctx.antidpi_port,
        "antidpi_limit": getattr(ctx, "antidpi_limit", 0),
        "isp": ctx.isp,
        "agy_bin": ctx.agy_bin,
        "agy_model": getattr(ctx, "agy_model", None),
        "agy_concurrency": getattr(ctx, "agy_concurrency", 2),
        "jobs": getattr(ctx, "jobs", 16),
        "timeouts": timeouts,
        "print_timeout": print_timeout,
        "use_geo_precheck": ctx.use_geo_precheck,
        "check_web": ctx.check_web,
        "result_path": str(result_path),
    }
    task_path.write_text(json.dumps(task_data, ensure_ascii=False), encoding="utf-8")

    console.print("\n" + "=" * 70)
    console.print("  proxy-probe: Запрос прав Администратора для проверки Anti-DPI (Stage 2)")
    console.print("  Пожалуйста, подтвердите UAC (нажмите 'Да') в системном окне на экране...")
    console.print("=" * 70 + "\n")

    elev_params = subprocess.list2cmdline(
        [
            "-m",
            "proxy_probe",
            "--stage2-worker",
            str(task_path),
            "--log-output",
            str(log_path),
        ]
    )

    try:
        rc = _elevation.run_elevated_and_wait(
            executable=sys.executable,
            params=elev_params,
            cwd=project_root(),
        )
        if rc != 0 and rc != 1223:
            console.print(f"[yellow]Stage 2 воркер завершился с кодом {rc}[/yellow]")
    except PermissionError:
        console.print(
            "[yellow]⚠ Stage 2 Anti-DPI пропущен: запрос прав Администратора (UAC) отклонён пользователем.[/yellow]"
        )
        with contextlib.suppress(Exception):
            task_path.unlink(missing_ok=True)
        return 0
    except Exception as exc:
        console.print(f"[yellow]⚠ Ошибка вызова UAC для Stage 2: {exc}[/yellow]")
        with contextlib.suppress(Exception):
            task_path.unlink(missing_ok=True)
        return 0

    if (rc != 0 or not result_path.is_file()) and log_path.is_file():
        with contextlib.suppress(Exception):
            log_text = log_path.read_text(encoding="utf-8", errors="replace").strip()
            if log_text:
                console.print(f"[dim]{log_text[-800:]}[/dim]")

    with contextlib.suppress(Exception):
        task_path.unlink(missing_ok=True)
        log_path.unlink(missing_ok=True)

    if not result_path.is_file():
        return 0

    rescued_count = 0
    try:
        result_data = json.loads(result_path.read_text(encoding="utf-8"))
        rescued_map = {item["config_identity"]: item for item in result_data.get("rescued", [])}

        for s in servers:
            if s.config_identity in rescued_map:
                info = rescued_map[s.config_identity]
                s.result = info.get("result", RESULT_OK)
                s.country = info.get("country", "")
                s.ip_out = info.get("ip_out", "")
                s.country_code = info.get("country_code", "")
                s.city = info.get("city", "")
                s.org = info.get("org", "")
                s.latency_ms = info.get("latency_ms", 0)
                s.note = info.get("note", "")
                s.web_status = info.get("web_status", "")
                s.ingress_country_code = info.get("ingress_country_code", "")
                s.ingress_ip = info.get("ingress_ip", "")
                s.antidpi_strategy = info.get("antidpi_strategy")
                s.state = info.get("state", STATE_ACTIVE)
                rescued_count += 1
                if s not in to_probe:
                    to_probe.append(s)

        if rescued_count > 0:
            total_dead = len(dead_candidates)
            console.print(
                f"[bold green]✓ Anti-DPI релей успешно оживил {rescued_count} из {total_dead} серверов![/bold green]"
            )
        else:
            console.print("\n[yellow]⚠ Anti-DPI: стратегия не смогла оживить упавшие узлы (0 спасено).[/yellow]")
            console.print(
                "[bold cyan]Рекомендуется выполнить экспресс-калибровку (Уровень 2):[/bold cyan]\n"
                "[bold white]  Выберите «Калибровать стратегии обхода DPI» в меню run.cmd "
                "(или: uv run pxp --calibrate 2)[/bold white]\n"
            )
    except Exception as exc:
        console.print(f"[yellow]Ошибка обработки результатов Stage 2: {exc}[/yellow]")
    finally:
        with contextlib.suppress(Exception):
            result_path.unlink(missing_ok=True)

    return rescued_count


def run_stage2_worker(task_file: Path, log_file: Path | None = None) -> int:
    from ..cli import RuntimeContext

    cm = _elevation.TeeOutput(log_file) if log_file else contextlib.nullcontext()
    with cm:
        if not task_file.is_file():
            print(f"Task file not found: {task_file}", file=sys.stderr)
            return 1
        try:
            data = json.loads(task_file.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"Failed to read task file {task_file}: {exc}", file=sys.stderr)
            return 1

        cache_path = Path(data["cache_path"]) if data.get("cache_path") else default_cache_path()
        cache = ResultCache(path=cache_path) if cache_path.is_file() else None

        sb_exe = Path(data.get("sb_exe", ""))
        xr_exe = Path(data.get("xr_exe", ""))

        ctx = RuntimeContext(
            agy_bin=data.get("agy_bin", ""),
            agy_model=data.get("agy_model"),
            agy_concurrency=int(data.get("agy_concurrency", 2)),
            initial_circuit_breaker=None,
            cache=cache,
            cache_path=cache_path,
            ttl_map={},
            report_path=Path("dummy"),
            import_path=Path("dummy"),
            ver_sb="",
            ver_xr="",
            sb_exe=sb_exe,
            xr_exe=xr_exe,
            antidpi=True,
            antidpi_strategy=data.get("antidpi_strategy"),
            antidpi_port=int(data.get("antidpi_port", 10850)),
            antidpi_limit=int(data.get("antidpi_limit", 0)),
            isp=data.get("isp"),
            use_geo_precheck=bool(data.get("use_geo_precheck", True)),
            check_web=bool(data.get("check_web", False)),
            jobs=int(data.get("jobs", 16)),
        )

        dead_candidates: list[Server] = []
        for d in data.get("dead_candidates", []):
            s = Server(
                group_id=d.get("group_id", 0),
                group_name=d.get("group_name", ""),
                name=d.get("name", ""),
                engine=d.get("engine", "sing-box"),
                server=d.get("server", ""),
                server_port=d.get("server_port", 443),
                import_obj=d.get("import_obj", {}),
                source=d.get("source", "db"),
                result=RESULT_DEAD,
            )
            dead_candidates.append(s)

        to_probe: list[Server] = []
        execute_antidpi_stage_core(
            dead_candidates=dead_candidates,
            to_probe=to_probe,
            ctx=ctx,
            timeouts=data.get("timeouts", {}),
            print_timeout=data.get("print_timeout", AGY_PRINT_TIMEOUT_DEFAULT),
            circuit_breaker=None,
        )

        result_path = Path(data["result_path"])
        rescued_items = []
        for s in dead_candidates:
            if s.result in (RESULT_OK, RESULT_BLOCK):
                rescued_items.append(
                    {
                        "config_identity": s.config_identity,
                        "cache_key": s.cache_key,
                        "result": s.result,
                        "country": s.country,
                        "ip_out": s.ip_out,
                        "country_code": s.country_code,
                        "city": s.city,
                        "org": s.org,
                        "latency_ms": s.latency_ms,
                        "note": s.note,
                        "web_status": s.web_status,
                        "ingress_country_code": s.ingress_country_code,
                        "ingress_ip": s.ingress_ip,
                        "antidpi_strategy": s.antidpi_strategy,
                        "state": s.state,
                    }
                )

        result_path.write_text(
            json.dumps({"rescued": rescued_items}, ensure_ascii=False),
            encoding="utf-8",
        )
        return 0


def execute_antidpi_stage_core(
    dead_candidates: list[Server],
    to_probe: list[Server],
    ctx: RuntimeContext,
    timeouts: dict[str, float],
    print_timeout: str,
    circuit_breaker: QuotaCircuitBreaker | None = None,
) -> int:
    if not dead_candidates:
        return 0

    try:
        current_isp = _isp.detect_current_isp(explicit_override=ctx.isp)
        ratings = _benchmark.load_ratings(isp_identity=current_isp)
        isp_label = f"[{current_isp.display_name}]"
    except _isp.IspDetectionError as err:
        console.print(
            f"[yellow]⚠ Stage 2 Anti-DPI пропущен: невозможно определить провайдера сети ({err}).[/yellow]"
        )
        return 0

    strat_num = ctx.antidpi_strategy
    if strat_num is None:
        strat_num = ratings.best_strategy_number if (ratings and ratings.best_strategy_number) else 10

    strat = _catalogue.get_strategy_by_number(strat_num)
    if not strat:
        console.print(f"[yellow]Anti-DPI: стратегия S{strat_num:02d} не найдена в каталоге.[/yellow]")
        return 0

    try:
        zapret_dir = _engine.ensure_zapret_binaries()
    except Exception as exc:
        console.print(f"[yellow]Anti-DPI: не удалось загрузить бинарники Zapret2 ({exc}). Пропуск Stage 2.[/yellow]")
        return 0

    batch_size = ANTIDPI_BATCH_SIZE
    total_candidates = len(dead_candidates)
    batches = chunk_candidates_by_limits(
        dead_candidates,
        max_ips=batch_size,
        max_ports=ANTIDPI_MAX_PORTS_PER_BATCH,
    )
    num_batches = len(batches)

    console.print(
        f"\n[bold cyan]Stage 2: Anti-DPI Релей {isp_label}[/bold cyan] "
        f"(стратегия S{strat.number:02d} {strat.name[:35]}, "
        f"узлов: {total_candidates}, "
        f"пачек: {num_batches} по <={batch_size} IP и <={ANTIDPI_MAX_PORTS_PER_BATCH} портов, "
        f"порт {ctx.antidpi_port})..."
    )

    relay_port = ctx.antidpi_port
    rescued_count = 0
    init_desc = f"Anti-DPI спасение [пачка 1/{num_batches}]" if num_batches > 1 else "Anti-DPI попытка спасения"
    pbar = tqdm(
        total=total_candidates,
        desc=init_desc,
        unit="srv",
        dynamic_ncols=True,
    )

    concurrency = getattr(ctx, "agy_concurrency", 2)
    agy_semaphore = threading.Semaphore(concurrency)
    model = getattr(ctx, "agy_model", None)
    registry = ProcessRegistry()
    stop_event = threading.Event()

    stage2_timeouts = {
        "start": min(timeouts.get("start", 6.0), 4.0),
        "preflight": min(timeouts.get("preflight", 2.5), 2.5),
        "geo": min(timeouts.get("geo", 6.0), 4.0),
        "geo_precheck": min(timeouts.get("geo_precheck", 3.0), 3.0),
        "probe": max(min(timeouts.get("probe", 35.0), 25.0), 15.0),
        "web_check": timeouts.get("web_check", 3.5),
    }
    stage2_print_timeout = "25s" if print_timeout == AGY_PRINT_TIMEOUT_DEFAULT else print_timeout

    try:
        with _relay.ZapretRelay(port=relay_port):
            for b_idx, batch in enumerate(batches, start=1):
                if stop_event.is_set():
                    break
                if num_batches > 1:
                    pbar.set_description(f"Anti-DPI спасение [пачка {b_idx}/{num_batches}]")

                batch_ips = {s.server for s in batch if s.server}
                if not batch_ips:
                    pbar.update(len(batch))
                    continue

                batch_ports_set = sorted({str(s.server_port) for s in batch if s.server_port})
                batch_ports_str = ",".join(batch_ports_set[:16]) or "443"

                with _engine.WinwsRunner(
                    strategy=strat,
                    target_ips=batch_ips,
                    zapret_dir=zapret_dir,
                    ports=batch_ports_str,
                ):
                    workers = min(len(batch), getattr(ctx, "jobs", 16), 16)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                        futures = {}
                        for s in batch:
                            patched_obj = _benchmark.apply_relay_detour(s.import_obj, is_xray=(s.engine == "xray"))
                            _, relay_outbound = _benchmark.build_relay_detour(
                                is_xray=(s.engine == "xray"),
                                relay_port=relay_port,
                            )
                            bin_path = str(ctx.xr_exe if s.engine == "xray" else ctx.sb_exe)
                            fut = ex.submit(
                                _probe_worker,
                                bin_path,
                                s.engine == "xray",
                                patched_obj,
                                stage2_timeouts,
                                ctx.agy_bin,
                                stage2_print_timeout,
                                agy_model=model,
                                agy_semaphore=agy_semaphore,
                                circuit_breaker=circuit_breaker,
                                stop_event=stop_event,
                                registry=registry,
                                use_geo_precheck=ctx.use_geo_precheck,
                                check_web=ctx.check_web,
                                extra_outbounds=[relay_outbound],
                            )
                            futures[fut] = s

                        for fut in concurrent.futures.as_completed(futures):
                            srv = futures[fut]
                            if stop_event.is_set():
                                break
                            try:
                                res = fut.result()
                            except Exception as exc:
                                res = {"result": RESULT_DEAD, "note": str(exc)}

                            res_status = res.get("result")
                            if res_status == RESULT_OK:
                                srv.result = RESULT_OK
                                srv.country = res.get("country", "")
                                srv.ip_out = res.get("ip_out", "")
                                srv.country_code = res.get("country_code", "")
                                srv.city = res.get("city", "")
                                srv.org = res.get("org", "")
                                srv.latency_ms = res.get("latency_ms", 0)
                                srv.note = f"оживлен через Zapret S{strat.number:02d}"
                                srv.web_status = res.get("web_status", "")
                                srv.ingress_country_code = res.get("ingress_country_code", "")
                                srv.ingress_ip = res.get("ingress_ip", "")
                                srv.antidpi_strategy = strat.number
                                srv.state = STATE_ACTIVE
                                rescued_count += 1
                                if srv not in to_probe:
                                    to_probe.append(srv)
                            elif res_status == RESULT_BLOCK:
                                srv.result = RESULT_BLOCK
                                srv.country = res.get("country", "")
                                srv.ip_out = res.get("ip_out", "")
                                srv.country_code = res.get("country_code", "")
                                srv.city = res.get("city", "")
                                srv.org = res.get("org", "")
                                srv.latency_ms = res.get("latency_ms", 0)
                                srv.note = res.get("note", "геоблок через Zapret")
                                srv.state = STATE_DEAD
                                if srv not in to_probe:
                                    to_probe.append(srv)
                            pbar.update(1)

                if b_idx < num_batches and not stop_event.is_set():
                    time.sleep(0.1)

    except KeyboardInterrupt:
        stop_event.set()
        registry.kill_all()
        console.print("\n[yellow]Stage 2 прерван пользователем.[/yellow]")
    except Exception as exc:
        console.print(f"[yellow]Ошибка работы Stage 2 Anti-DPI: {exc}[/yellow]")
    finally:
        pbar.close()

    if ratings is not None and current_isp is not None:
        ratings.record_live_feedback(strat.number, rescued_count, total_candidates)
        _benchmark.save_ratings(ratings, isp_identity=current_isp)

    if rescued_count > 0:
        console.print(
            f"[bold green]✓ Anti-DPI релей успешно оживил {rescued_count} из {total_candidates} серверов![/bold green]"
        )
    else:
        console.print(
            f"\n[yellow]⚠ Anti-DPI: текущая стратегия S{strat.number:02d} "
            "не смогла оживить упавшие узлы (0 спасено).[/yellow]"
        )
        console.print(
            "[bold cyan]Рекомендуется выполнить экспресс-калибровку (Уровень 2):[/bold cyan]\n"
            "[bold white]  Выберите «Калибровать стратегии обхода DPI» в меню run.cmd "
            "(или: uv run pxp --calibrate 2)[/bold white]\n"
        )

    return rescued_count
