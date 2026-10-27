from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

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


def print_progress_row(server: Server, idx: int, total: int, write_fn: Callable[[str], None] | None = None) -> None:
    res_badge = format_result(server.result)
    ms_txt = format_latency(server.latency_ms)
    country = server.country or "-"
    note_hint = f" ({server.note[:35]})" if server.note and server.result != RESULT_OK else ""
    line = (
        f"  [cyan][{idx:>2}/{total}][/cyan] {res_badge:20s} "
        f"[bold white]{server.host_port:<24}[/bold white] "
        f"{country:<16} {ms_txt:<12} [dim]{server.name[:30]}{note_hint}[/dim]"
    )
    if write_fn is not None:
        with console.capture() as cap:
            console.print(line)
        write_fn(cap.get().rstrip("\r\n"))
    else:
        console.print(line)


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
) -> None:
    if stats is None:
        stats = compute_summary_stats(servers)

    tested_count = stats.tested
    total_count = stats.total
    if tested_count < total_count:
        stat = f"{tested_count} из {total_count} (прервано)"
        header = f"[bold]Проверено серверов:[/] {stat} за [cyan]{elapsed_s:.1f} с[/cyan]"
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

    console.print(Panel("\n".join(lines), title="[bold]Итоги проверки proxy-probe[/bold]", border_style="cyan"))
