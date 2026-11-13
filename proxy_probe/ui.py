from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .antidpi.models import AntidpiBenchmarkResult, CalibrationLevelConfig
    from .gist import GistSyncResult

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, RESULT_UNKNOWN, STATE_DEGRADED, Server
from .stats import SummaryStats, compute_summary_stats

console = Console()


def format_result(res: str) -> str:
    if res == RESULT_OK:
        return "[bold green]AGY-OK[/bold green]"
    if res == RESULT_BLOCK:
        return "[bold red]AGY-BLOCK[/bold red]"
    if res == RESULT_DEAD:
        return "[dim red]DEAD[/dim red]"
    if res == RESULT_UNKNOWN:
        return "[bold yellow]UNKNOWN[/bold yellow]"
    if not res:
        return "[dim]—[/dim]"
    return res


def format_latency(ms: int) -> str:
    if ms <= 0:
        return "-"
    if ms < 600:
        return f"[green]{ms} мс[/green]"
    if ms < 1500:
        return f"[yellow]{ms} мс[/yellow]"
    return f"[red]{ms} мс[/red]"


def format_cached_counters(
    cached_counts: dict[str, int],
    cached_unique_hosts: dict[str, set[str]] | None = None,
) -> str:
    order = [RESULT_OK, RESULT_BLOCK, RESULT_DEAD, RESULT_UNKNOWN]
    parts: list[str] = []
    for k in order:
        v = cached_counts.get(k, 0)
        if v > 0:
            u_cnt = len(cached_unique_hosts.get(k, set())) if cached_unique_hosts else 0
            if u_cnt > 0 and u_cnt < v:
                parts.append(f"{k}: {v} ({u_cnt} уникальных)")
            else:
                parts.append(f"{k}: {v}")
    for k, v in cached_counts.items():
        if k not in order and v > 0:
            u_cnt = len(cached_unique_hosts.get(k, set())) if cached_unique_hosts else 0
            if u_cnt > 0 and u_cnt < v:
                parts.append(f"{k}: {v} ({u_cnt} уникальных)")
            else:
                parts.append(f"{k}: {v}")
    return f"Из кэша: {', '.join(parts)}" if parts else ""


def format_live_counters(counts: dict[str, int]) -> str:
    order = [RESULT_OK, RESULT_BLOCK, RESULT_DEAD, RESULT_UNKNOWN]
    return " | ".join(f"{k}: {counts.get(k, 0)}" for k in order)


def select_main_action_interactive(relay_port: int | None = None) -> str:
    """Отображает главное интерактивное меню TUI proxy-probe с адаптивным статусом релея (SSOT)."""
    if not sys.stdin or not sys.stdin.isatty():
        return "probe"

    from InquirerPy import inquirer
    from InquirerPy.base.control import Choice

    from .antidpi.relay import DEFAULT_RELAY_PORT
    from .antidpi.runner import resolve_active_relay_port

    effective_port = DEFAULT_RELAY_PORT if relay_port is None else relay_port
    relay_active, active_port, st = resolve_active_relay_port(effective_port)
    if relay_active:
        strat_hint = f", S{st.strategy_number:02d}" if st else ""
        relay_choice = Choice(
            value="stop_relay",
            name=f"2. Остановить фоновый релей Zapret2 [● Работает на 127.0.0.1:{active_port}{strat_hint}]",
        )
    else:
        relay_choice = Choice(
            value="serve",
            name=f"2. Запустить фоновый релей Zapret2 (SOCKS5 127.0.0.1:{active_port}) [○ Остановлен]",
        )

    choices = [
        Choice(
            value="probe",
            name="1. Проверить и обновить пул прокси (Stage 0 TCP -> Stage 1 Direct -> Stage 2 Anti-DPI)",
        ),
        relay_choice,
        Choice(
            value="calibrate",
            name="3. Калибровать стратегии обхода DPI под текущего провайдера",
        ),
        Choice(
            value="update_catalogue",
            name="4. Обновить каталог стратегий Anti-DPI из upstream (484 профиля)",
        ),
        Choice(
            value="clear_dead",
            name="5. Очистить кэш results.json от нерабочих записей (DEAD)",
        ),
        Choice(
            value="exit",
            name="0. Выход",
        ),
    ]
    try:
        console.print()
        selected = inquirer.select(
            message="Выберите действие proxy-probe (pxp):",
            choices=choices,
            cycle=True,
        ).execute()
        return str(selected) if selected else "exit"
    except (EOFError, KeyboardInterrupt):
        return "exit"


def select_calibration_level_interactive() -> int | None:
    """Отображает интерактивное подменю выбора уровня калибровки Anti-DPI."""
    if not sys.stdin or not sys.stdin.isatty():
        return 2

    from InquirerPy import inquirer
    from InquirerPy.base.control import Choice

    choices = [
        Choice(
            value=2,
            name="Уровень 2: Экспресс-калибровка разнообразия механик (~20–25 стратегий, ~1.5 мин)",
        ),
        Choice(
            value=3,
            name="Уровень 3: Расширенная калибровка лидеров на пуле живых серверов (~4–5 мин)",
        ),
        Choice(
            value=4,
            name="Уровень 4: Глубокий перебор всех 484 стратегий каталога (~20–25 мин)",
        ),
        Choice(
            value=0,
            name="← Назад в главное меню",
        ),
    ]
    try:
        selected = inquirer.select(
            message="Выберите уровень калибровки Anti-DPI:",
            choices=choices,
            cycle=True,
        ).execute()
        return int(selected) if selected and int(selected) in (2, 3, 4) else None
    except (EOFError, KeyboardInterrupt):
        return None


def print_benchmark_results_panel(
    living: AntidpiBenchmarkResult,
    selected: list[Server],
    server_rescue_map: dict[str, list[tuple[int, int]]],
    cfg: CalibrationLevelConfig,
) -> None:
    """Выводит сводную таблицу и панель вердикта калибровки Anti-DPI в едином стиле Rich."""
    table = Table(
        title=f"Живой рейтинг Anti-DPI стратегий ({living.isp or 'Default'}, {living.tested_at[:19]})",
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("№", width=8)
    table.add_column("Стратегия", style="bold white", ratio=1, overflow="ellipsis", no_wrap=True)
    table.add_column("Механика", style="cyan", width=24, overflow="ellipsis", no_wrap=True)
    table.add_column("Статус", justify="center", width=12)
    table.add_column("Спасено", justify="right", width=10)
    table.add_column("Успех", justify="right", width=8)
    table.add_column("Задержка", justify="right", width=10)
    table.add_column("Скор", justify="right", width=6)

    for r in living.ratings[:25]:
        is_best = r.strategy_number == living.best_strategy_number
        mark = "⭐ " if is_best else ""
        pct = f"{int(r.success_rate * 100)}%"
        lat = format_latency(r.avg_latency_ms)
        table.add_row(
            f"{mark}S{r.strategy_number:02d}",
            r.strategy_name[:40],
            r.technical_family[:24],
            r.status_badge,
            f"{r.rescued_count}/{r.total_tested}",
            pct,
            lat,
            str(r.score),
        )
    console.print()
    console.print(table)

    summary_lines: list[str] = []
    if server_rescue_map:
        summary_lines.append("[bold cyan]Спасённые серверы и эффективные стратегии:[/bold cyan]")
        for srv in selected:
            if srv.server in server_rescue_map:
                res_list = server_rescue_map[srv.server]
                res_str = ", ".join(f"S{num:02d} ({lat} мс)" for num, lat in res_list[:6])
                best_s = min(res_list, key=lambda x: x[1])
                summary_lines.append(
                    f"  • [bold white]{srv.host_port}[/bold white] ({srv.name[:30]}): "
                    f"{res_str} -> лучшая [green]S{best_s[0]:02d}[/green]"
                )
        summary_lines.append("")

    best_num = living.best_strategy_number
    best_entry = next((r for r in living.ratings if r.strategy_number == best_num), None) if best_num else None

    if best_entry and best_entry.score > 0:
        summary_lines.append(
            f"[bold green]✓ Рекомендуемая стратегия для провайдера {living.isp}: "
            f"S{best_num:02d} ({best_entry.strategy_name})[/bold green]"
        )
        summary_lines.append("[dim]Живой рейтинг сохранён в data/antidpi_ratings.json.[/dim]")
    else:
        summary_lines.append(
            f"[bold yellow]⚠ Ни одна из проверенных стратегий не оживила узлы ({cfg.title}).[/bold yellow]"
        )
        if cfg.next_level:
            summary_lines.append(
                f"Рекомендуется запустить следующий уровень калибровки: "
                f"[bold cyan]Уровень {cfg.next_level}[/bold cyan] "
                f"(или: [bold white]uv run pxp --calibrate {cfg.next_level}[/bold white])"
            )
        else:
            summary_lines.append(
                "[red]Все 484 стратегии каталога дали 0% успеха. "
                "ТСПУ провайдера полностью блокирует протокол либо целевые серверы недоступны.[/red]"
            )

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold]Вердикт калибровки Anti-DPI[/bold]",
            border_style="cyan",
        )
    )


def select_groups_interactive(groups: list[dict[str, Any]], counts: dict[int, int]) -> set[int]:
    if not sys.stdin or not sys.stdin.isatty():
        return {g["id"] for g in groups}

    from InquirerPy import inquirer
    from InquirerPy.base.control import Choice

    choices: list[Choice] = []
    for g in groups:
        gid = g["id"]
        cnt = counts.get(gid, 0)
        label = f"[{gid:>2}] {g['name']} (серверов: {cnt})"
        choices.append(Choice(value=gid, name=label, enabled=True))

    try:
        selected = inquirer.checkbox(
            message="Выберите подписки (Пробел — выбор/снятие, Enter — подтвердить):",
            choices=choices,
            cycle=True,
            transformer=lambda result: f"выбрано {len(result)} из {len(choices)}",
        ).execute()
        return set(selected) if selected else set()
    except (EOFError, KeyboardInterrupt):
        return set()


def print_results_table(
    servers: list[Server],
    mode: str = "ok",
    limit: int = 20,
) -> None:
    """Выводит итоговую таблицу результатов в консоль.

    Параметры:
        mode: "ok" (только рабочие узлы AGY-OK и DEGRADED),
              "all" (все проверенные узлы),
              "none" (не выводить таблицу).
        limit: максимальное количество строк (0 - без лимита).
    """
    if mode == "none":
        return

    if mode == "ok":
        candidates = [s for s in servers if s.result == RESULT_OK or s.state == STATE_DEGRADED]
        title = "Рабочие серверы (AGY-OK)"
    else:
        candidates = [s for s in servers if s.result]
        title = "Результаты проверки серверов"

    if not candidates:
        if mode == "ok":
            console.print("\n[dim]Рабочих серверов (AGY-OK) не найдено (см. полный отчёт в report.md)[/dim]")
        return

    total_candidates = len(candidates)
    if limit > 0 and total_candidates > limit:
        displayed = candidates[:limit]
        caption = (
            f"[dim]Показано первых {limit} из {total_candidates} серверов "
            f"(полный список — в report.md и proxy-ok.txt)[/dim]"
        )
    else:
        displayed = candidates
        caption = None

    table = Table(
        title=title,
        header_style="bold magenta",
        expand=True,
        caption=caption,
    )
    table.add_column("№", style="dim", width=4, justify="right")
    table.add_column("Статус", justify="center", width=12)
    table.add_column("Группа", style="cyan", width=14)
    table.add_column("Движок", style="blue", width=10)
    table.add_column("Сервер", style="bold white", width=22)
    table.add_column("Страна", width=16)
    table.add_column("Egress IP", width=16)
    table.add_column("Задержка", justify="right", width=10)
    table.add_column("Имя", style="dim", max_width=30, overflow="ellipsis", no_wrap=True)
    table.add_column("Ответ / Примечание", style="dim", ratio=1, overflow="ellipsis", no_wrap=True)

    for s in displayed:
        table.add_row(
            str(s.index),
            format_result(s.result),
            s.group_name[:14],
            s.engine,
            s.host_port,
            s.country or "-",
            s.ip_out or "-",
            format_latency(s.latency_ms),
            (s.formatted_tag or s.name or "")[:30],
            s.note or "-",
        )
    console.print(table)


def print_summary_panel(
    servers: list[Server],
    cached_counts: dict[str, int],
    report_path: Path,
    import_path: Path,
    nb: int,
    nx: int,
    elapsed_s: float,
    cached_unique_hosts: dict[str, set[str]] | None = None,
    stats: SummaryStats | None = None,
    gist_res: GistSyncResult | None = None,
) -> None:
    if stats is None:
        stats = compute_summary_stats(servers)

    tested_count = stats.tested
    total_count = stats.total
    cached_total = sum(1 for s in servers if getattr(s, "from_cache", False))
    fresh_tested = sum(1 for s in servers if not getattr(s, "from_cache", False) and s.result)

    if tested_count < total_count:
        stat = f"{tested_count} из {total_count} (прервано)"
        header = f"[bold]Проверено серверов:[/] {stat} за [cyan]{elapsed_s:.1f} с[/cyan]"
    elif cached_total > 0:
        header = (
            f"[bold]Всего в пуле:[/] {total_count} серверов "
            f"([green]проверено:[/] {fresh_tested} за [cyan]{elapsed_s:.1f} с[/cyan], "
            f"[dim]из кэша:[/] {cached_total})"
        )
    else:
        header = f"[bold]Всего проверено:[/] {total_count} серверов за [cyan]{elapsed_s:.1f} с[/cyan]"
    lines: list[str] = [header]

    breakdown = []
    if stats.counts.get(RESULT_OK):
        breakdown.append(f"[bold green]AGY-OK:[/] {stats.counts[RESULT_OK]}")
    if stats.counts.get(RESULT_BLOCK):
        breakdown.append(f"[bold red]AGY-BLOCK:[/] {stats.counts[RESULT_BLOCK]}")
    if stats.counts.get(RESULT_DEAD):
        breakdown.append(f"[dim red]DEAD:[/] {stats.counts[RESULT_DEAD]}")
    if stats.counts.get(RESULT_UNKNOWN):
        breakdown.append(f"[bold yellow]UNKNOWN:[/] {stats.counts[RESULT_UNKNOWN]}")

    if breakdown:
        lines.append(" | ".join(breakdown))

    # 1. География рабочих узлов (текстовый формат без emoji-флагов: DE (Германия): N)
    if stats.geo_stats:
        lines.append("")
        lines.append("[bold cyan]География (AGY-OK):[/]")
        geo_parts = []
        for g in stats.geo_stats[:6]:
            label = f"{g.code} ({g.name})" if g.name and g.name != g.code else g.code
            ms_txt = f" (ср. {g.avg_latency_ms} мс)" if g.avg_latency_ms > 0 else ""
            geo_parts.append(f"{label}: [bold]{g.count}[/]{ms_txt}")
        lines.append("  " + " | ".join(geo_parts))

    # 2. Задержка рабочих серверов
    if stats.latency_avg > 0:
        lines.append("")
        lines.append(
            f"[bold cyan]Задержка (AGY-OK):[/] "
            f"мин [green]{stats.latency_min}[/] мс | "
            f"медиана [yellow]{stats.latency_median}[/] мс | "
            f"средняя [yellow]{stats.latency_avg}[/] мс"
        )

    # 3. Эффективность подписок
    if stats.group_stats:
        lines.append("")
        lines.append("[bold cyan]Подписки (эффективность):[/]")
        for grp in stats.group_stats[:6]:
            rate_color = "green" if grp.success_rate >= 30 else ("yellow" if grp.success_rate > 0 else "dim red")
            lines.append(
                f"  • [{grp.group_id}] {grp.group_name[:25]}: "
                f"[{rate_color}]{grp.ok_count}/{grp.total_count} OK ({grp.success_rate:.1f}%)[/{rate_color}]"
            )

    # 4. Причины сбоев
    if stats.failure_reasons:
        lines.append("")
        lines.append("[bold cyan]Причины сбоев (DEAD / BLOCK):[/]")
        for reason, count in stats.failure_reasons:
            lines.append(f"  • {reason}: [red]{count}[/]")

    # 5. Хостинг-провайдеры (дата-центры / ISP)
    ok_orgs = [o for o in stats.org_stats if o.ok_count > 0]
    if ok_orgs:
        lines.append("")
        lines.append("[bold cyan]Хостинг-провайдеры (AGY-OK):[/]")
        for org in ok_orgs[:5]:
            c_str = f" | {', '.join(org.countries)}" if org.countries else ""
            ms_str = f"ср. {org.avg_latency_ms} мс" if org.avg_latency_ms > 0 else "-"
            score_str = (
                f", ⭐{org.avg_score}"
                if org.avg_score >= 90
                else (f", скор {org.avg_score}" if org.avg_score > 0 else "")
            )
            lines.append(f"  • {org.org_name[:32]}: [bold]{org.ok_count}[/] серверов ({ms_str}{score_str}{c_str})")

    cached_total = sum(cached_counts.values())
    if cached_total > 0:
        c_parts = []
        for k, v in cached_counts.items():
            if not v:
                continue
            u_cnt = len(cached_unique_hosts.get(k, set())) if cached_unique_hosts else 0
            if u_cnt > 0 and u_cnt < v:
                c_parts.append(f"{k}: {v} ({u_cnt} уникальных)")
            else:
                c_parts.append(f"{k}: {v}")
        lines.append("")
        lines.append(f"[dim]Из кэша (без повторной проверки): {', '.join(c_parts)}[/dim]")

    lines.append("")
    lines.append(f"[bold cyan]Отчёт:[/] {report_path}")
    lines.append(
        f"[bold green]Импорт в Throne:[/] {import_path} (рабочих в кэше: {nb + nx} — sing-box: {nb}, xray: {nx})"
    )
    if gist_res:
        if gist_res.success:
            lines.append(
                f"[bold cyan]GitHub Gist:[/] {gist_res.raw_url} [bold green](обновлён)[/]"
            )
        else:
            lines.append(
                f"[bold cyan]GitHub Gist:[/] [bold yellow]Не удалось обновить[/] ({gist_res.error_message})"
            )

    console.print(Panel("\n".join(lines), title="[bold]Итоги проверки proxy-probe[/bold]", border_style="cyan"))
