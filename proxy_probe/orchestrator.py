from __future__ import annotations

import contextlib
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from .models import Server
from .parsers import USER_AGENT, extract_host_port, extract_tag, parse_subscription
from .security import is_insecure_server
from .throne import read_profiles_for_group
from .ui import select_groups_interactive

__all__ = [
    "dedupe_servers",
    "fetch_subscription",
    "filter_insecure_servers",
    "gather_sources",
    "interactive_select",
    "pause_on_exit",
    "run_dir",
]


def pause_on_exit(no_pause: bool = False) -> None:
    if not no_pause and sys.stdin and sys.stdin.isatty():
        with contextlib.suppress(EOFError, KeyboardInterrupt):
            input("\nНажмите Enter для выхода...")


def run_dir() -> Path:
    base = Path(tempfile.gettempdir()) / "proxy-probe" / "run"
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, exist_ok=True)
    return base


def fetch_subscription(url: str, timeout: float = 25.0) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None


def _canonical_structure(val: Any) -> Any:
    if isinstance(val, dict):
        return {
            k: _canonical_structure(v)
            for k, v in sorted(val.items())
            if k not in ("tag", "remarks", "packet_encoding")
        }
    if isinstance(val, list):
        items = [_canonical_structure(x) for x in val]
        if all(isinstance(x, (str, int, float, bool)) for x in items):
            try:
                return sorted(items)
            except TypeError:
                return sorted(items, key=repr)
        return items
    return val


def dedupe_servers(items: list[Server]) -> list[Server]:
    """Дедуплицирует серверы по их канонической конфигурации (SSOT).

    Свежие записи из онлайн-подписок (source: fresh) замещают
    устаревшие копии из локальной БД (source: db).
    """
    seen: dict[str, Server] = {}
    for it in items:
        key = it.config_identity
        if key in seen:
            cur = seen[key]
            if (cur.source == "db" and it.source == "fresh") or (cur.name == cur.host_port and it.name != it.host_port):
                seen[key] = it
            continue
        seen[key] = it
    return list(seen.values())


def filter_insecure_servers(servers: list[Server]) -> tuple[list[Server], list[Server]]:
    """Разделяет список серверов на безопасные и небезопасные."""
    safe: list[Server] = []
    insecure: list[Server] = []
    for s in servers:
        if is_insecure_server(s):
            insecure.append(s)
        else:
            safe.append(s)
    return safe, insecure


def gather_sources(
    groups: list[dict],
    selected: set[int],
    no_fetch: bool,
    prefetched: dict[str, bytes] | None = None,
    filter_insecure: bool | None = None,
) -> tuple[list[Server], list[str]]:
    warnings: list[str] = []
    all_items: list[Server] = []
    for g in groups:
        gid = g.get("id")
        if gid not in selected:
            continue
        gname = g.get("name", f"Group {gid}")
        remove_insecure = bool(g.get("remove_insecure", False))

        # 1. Загрузка из локальной БД Throne
        try:
            db_items = read_profiles_for_group(gid, gname)
        except Exception:
            db_items = []

        # 2. Загрузка онлайн-подписки
        online_items: list[Server] = []
        url = g.get("url")
        if not no_fetch and url:
            data = prefetched[url] if (prefetched and url in prefetched) else fetch_subscription(url)
            if data is None:
                if db_items:
                    warnings.append(f"Подписка «{gname}» (id {gid}) недоступна онлайн — взято только из БД Throne")
                else:
                    warnings.append(f"Подписка «{gname}» (id {gid}) недоступна онлайн и отсутствует в БД")
            else:
                pairs = parse_subscription(data)
                for eng, obj in pairs:
                    srv, prt = extract_host_port(obj)
                    if not srv:
                        continue
                    online_items.append(
                        Server(
                            group_id=gid,
                            group_name=gname,
                            name=extract_tag(obj) or f"{srv}:{prt}",
                            engine=eng,
                            server=srv,
                            server_port=prt,
                            import_obj=obj,
                            source="fresh",
                        )
                    )
                if not online_items and not db_items:
                    warnings.append(f"Подписка «{gname}» (id {gid}) не содержит распознанных серверов")

        # 3. Объединение и дедупликация (онлайн замещает дубликаты из БД)
        items = dedupe_servers(db_items + online_items)

        # 4. Решение о фильтрации небезопасных серверов
        should_filter = (filter_insecure is True) or (filter_insecure is None and remove_insecure)
        if should_filter and items:
            safe, insecure = filter_insecure_servers(items)
            if insecure:
                warnings.append(
                    f"Отфильтровано {len(insecure)} небезопасных серверов в группе «{gname}» "
                    "(Insecure TLS / открытый трафик / устаревшие шифры)"
                )
            items = safe

        all_items.extend(dedupe_servers(items))
    return all_items, warnings


def interactive_select(groups: list[dict[str, Any]], counts: dict[int, int]) -> set[int]:
    return select_groups_interactive(groups, counts)
