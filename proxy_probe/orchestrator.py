from __future__ import annotations

import contextlib
import json
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from .models import Server
from .parsers import USER_AGENT, extract_host_port, extract_tag, parse_subscription
from .throne import read_profiles_for_group
from .ui import select_groups_interactive

__all__ = [
    "dedupe_servers",
    "fetch_subscription",
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
        return {k: _canonical_structure(v) for k, v in sorted(val.items()) if k not in ("tag", "remarks")}
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
    seen: dict[str, Server] = {}
    for it in items:
        clean = _canonical_structure(it.import_obj) if isinstance(it.import_obj, dict) else it.import_obj
        key = f"{it.engine}:{json.dumps(clean, sort_keys=True, ensure_ascii=False)}"
        if key in seen:
            cur = seen[key]
            if (cur.source == "db" and it.source == "fresh") or (cur.name == cur.host_port and it.name != it.host_port):
                seen[key] = it
            continue
        seen[key] = it
    return list(seen.values())


def gather_sources(
    groups: list[dict],
    selected: set[int],
    no_fetch: bool,
    prefetched: dict[str, bytes] | None = None,
) -> tuple[list[Server], list[str]]:
    warnings: list[str] = []
    all_items: list[Server] = []
    group_names = {g["id"]: g["name"] for g in groups}
    for g in groups:
        gid = g["id"]
        if gid not in selected:
            continue
        gname = group_names[gid]
        items: list[Server] = []
        src = "fresh"
        url = g.get("url")
        if not no_fetch and url:
            data = prefetched[url] if (prefetched and url in prefetched) else fetch_subscription(url)
            if data is None:
                src = "db"
                warnings.append(f"Подписка «{gname}» (id {gid}) недоступна — взято из БД Throne (возможно устарело)")
            else:
                pairs = parse_subscription(data)
                for eng, obj in pairs:
                    srv, prt = extract_host_port(obj)
                    if not srv:
                        continue
                    items.append(
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
        if not items:
            items = read_profiles_for_group(gid, gname)
            if src == "fresh" and items:
                warnings.append(f"Подписка «{gname}» (id {gid}) не распознана — взято из БД Throne")
        all_items.extend(dedupe_servers(items))
    return all_items, warnings


def interactive_select(groups: list[dict[str, Any]], counts: dict[int, int]) -> set[int]:
    return select_groups_interactive(groups, counts)
