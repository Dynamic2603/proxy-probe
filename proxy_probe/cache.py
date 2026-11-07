from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from .models import DEFAULT_TTLS, RESULT_OK, RESULT_PRIORITIES, Server

CACHE_VERSION = 1
DEFAULT_CACHE_NAME = "results.json"


def default_cache_path() -> Path:
    from .engines import project_root

    return project_root() / DEFAULT_CACHE_NAME


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC).replace(tzinfo=None)


class ResultCache:
    def __init__(self, path: Path | None = None, ttl_map: dict[str, int] | None = None):
        self.path = Path(path) if path else default_cache_path()
        self.ttl_map = ttl_map or dict(DEFAULT_TTLS)
        self.entries: dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.entries = {}
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            servers = data.get("servers") if isinstance(data, dict) else None
            if isinstance(servers, dict):
                self.entries = {k: v for k, v in servers.items() if isinstance(k, str) and isinstance(v, dict)}
            else:
                self.entries = {}
        except Exception:
            self.entries = {}

    def get_valid(self, server_key: str, now: _dt.datetime | None = None) -> dict | None:
        rec = self.entries.get(server_key)
        if not rec:
            return None
        res = rec.get("result")
        if not isinstance(res, str) or res not in self.ttl_map:
            return None
        ttl = self.ttl_map[res]
        checked_s = rec.get("checked")
        if not isinstance(checked_s, str):
            return None
        try:
            checked = _dt.datetime.fromisoformat(checked_s)
        except Exception:
            return None
        now_dt = now or utcnow()
        if ttl <= 0 or (now_dt - checked).total_seconds() <= ttl:
            return rec
        return None

    def is_valid(self, server_key: str, now: _dt.datetime | None = None) -> bool:
        return self.get_valid(server_key, now=now) is not None

    def get_valid_server(self, server: Server, now: _dt.datetime | None = None) -> dict | None:
        rec = self.get_valid(server.cache_key, now=now)
        if rec:
            return rec
        return self.get_valid(server.host_port, now=now)

    def put(self, server_key: str, record: dict, force: bool = False, now: _dt.datetime | None = None) -> None:
        if not force:
            cur = self.get_valid(server_key, now=now)
            if cur:
                cur_prio = RESULT_PRIORITIES.get(str(cur.get("result", "")), 0)
                new_prio = RESULT_PRIORITIES.get(str(record.get("result", "")), 0)
                if cur_prio >= new_prio:
                    return
        self.entries[server_key] = record

    def update_from_server(self, server: Server, now: _dt.datetime | None = None) -> None:
        if server.result not in self.ttl_map:
            return
        now_s = (now or utcnow()).isoformat(timespec="seconds")
        rec: dict = {
            "checked": now_s,
            "result": server.result,
            "country": server.country,
            "ip_out": server.ip_out,
            "latency_ms": server.latency_ms,
            "note": server.note,
        }
        if server.result == RESULT_OK:
            rec["engine"] = server.engine
            cur = self.entries.get(server.cache_key) or self.entries.get(server.host_port) or {}
            rec["import_obj"] = server.import_obj or cur.get("import_obj")
        self.put(server.cache_key, rec, force=True)

    def enrich_from_server(self, server: Server) -> bool:
        rec = self.entries.get(server.cache_key) or self.entries.get(server.host_port)
        if not rec or rec.get("result") != RESULT_OK:
            return False
        if server.import_obj and not rec.get("import_obj"):
            rec["engine"] = server.engine
            rec["import_obj"] = server.import_obj
            return True
        return False

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        payload = {"version": CACHE_VERSION, "servers": self.entries}
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(self.path)
