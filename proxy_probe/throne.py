from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from .models import Server
from .parsers import extract_host_port, extract_tag

APP_NAME = "proxy-probe"
_snapshot_path: Path | None = None
_snapshot_source_dir: Path | None = None
_custom_throne_dir: Path | None = None


def set_throne_dir(path: Path | str | None) -> None:
    global _custom_throne_dir, _snapshot_path, _snapshot_source_dir
    _custom_throne_dir = Path(path).resolve() if path else None
    _snapshot_path = None
    _snapshot_source_dir = None


def reset_throne_state() -> None:
    set_throne_dir(None)


def find_throne_dir(custom_path: Path | str | None = None) -> Path:
    if custom_path:
        p = Path(custom_path).resolve()
        if p.exists():
            return p
    if _custom_throne_dir and _custom_throne_dir.exists():
        return _custom_throne_dir

    env_dir = os.environ.get("THRONE_DIR")
    if env_dir:
        p = Path(env_dir).resolve()
        if p.exists():
            return p

    candidates: list[Path] = []
    for var in ("LOCALAPPDATA", "APPDATA", "ProgramFiles", "ProgramFiles(x86)"):
        val = os.environ.get(var)
        if val:
            candidates.append(Path(val) / "Throne")

    for c in candidates:
        if (c / "ThroneCore.exe").is_file() or (c / "config" / "throne.db").is_file():
            return c.resolve()

    for c in candidates:
        if c.is_dir():
            return c.resolve()

    return candidates[0] if candidates else Path.home() / "AppData" / "Local" / "Throne"


def default_throne_dir() -> Path:
    return find_throne_dir()


def detect_throne_versions(throne_dir: Path) -> tuple[str, str]:
    exe = throne_dir / "ThroneCore.exe"
    if not exe.exists():
        raise SystemExit(
            f"ThroneCore.exe не найден: {exe}\n"
            f"Укажите путь к Throne через --throne-dir <путь> или переменную THRONE_DIR"
        )
    try:
        out = subprocess.run([str(exe)], capture_output=True, timeout=10, cwd=str(throne_dir))
        txt = (out.stdout or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        raise SystemExit("ThroneCore.exe не вышел за 10 секунд — не могу узнать версии") from e
    m_sb = re.search(r"sing-box:\s*v?([\d.]+)", txt)
    m_xr = re.search(r"Xray-core:\s*v?([\d.]+)", txt)
    if not m_sb or not m_xr:
        raise SystemExit("Не удалось распознать версии из баннера ThroneCore.exe")
    return m_sb.group(1), m_xr.group(1)


def get_db_snapshot(throne_dir: Path | None = None, force_refresh: bool = False) -> Path:
    global _snapshot_path, _snapshot_source_dir
    base_dir = throne_dir or default_throne_dir()
    if (
        _snapshot_path is not None
        and not force_refresh
        and _snapshot_source_dir == base_dir
        and _snapshot_path.exists()
    ):
        return _snapshot_path

    src = base_dir / "config" / "throne.db"
    if not src.exists():
        raise SystemExit(
            f"throne.db не найден: {src}\n"
            f"Укажите путь к Throne через --throne-dir <путь> или переменную THRONE_DIR"
        )
    dst = Path(tempfile.gettempdir()) / APP_NAME / "snapshot" / "throne.db"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    for ext in ("-wal", "-shm"):
        s = src.with_name(src.name + ext)
        if s.exists():
            shutil.copy2(s, dst.with_name(dst.name + ext))
    _snapshot_path = dst
    _snapshot_source_dir = base_dir
    return dst


def read_groups() -> list[dict]:
    db = get_db_snapshot()
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT id, name, url FROM groups WHERE archive=0 ORDER BY id").fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def read_profiles_for_group(gid: int, group_name: str = "") -> list[Server]:
    db = get_db_snapshot()
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT type, name, outbound_json FROM profiles WHERE gid=? ORDER BY id", (gid,)
        ).fetchall()
    finally:
        con.close()
    out: list[Server] = []
    for r in rows:
        try:
            obj = json.loads(r["outbound_json"])
        except Exception:
            continue
        engine = "xray" if r["type"] == "xrayvless" else "sing-box"
        srv, prt = extract_host_port(obj)
        if not srv:
            continue
        out.append(
            Server(
                group_id=gid,
                group_name=group_name,
                name=r["name"] or extract_tag(obj) or f"{srv}:{prt}",
                engine=engine,
                server=srv,
                server_port=prt,
                import_obj=obj,
                source="db",
            )
        )
    return out
