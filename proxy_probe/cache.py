from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import (
    DEFAULT_TTLS,
    MAX_CONSECUTIVE_FAILS,
    RESULT_DEAD,
    RESULT_OK,
    RESULT_PRIORITIES,
    STATE_ACTIVE,
    STATE_DEAD,
    STATE_DEGRADED,
    TERMINAL_FAILURES,
    Server,
)
from .parsers import extract_host_port

CACHE_VERSION = 1
DEFAULT_CACHE_NAME = "results.json"


def calculate_score(
    ok_count: int,
    consecutive_fails: int,
    latency_ms: int,
) -> int:
    """Вычисляет рейтинг надежности сервера (0..100)."""
    if ok_count <= 0 or consecutive_fails >= MAX_CONSECUTIVE_FAILS:
        return 0
    base = 70
    bonus_history = min(20, max(0, ok_count - 1) * 3)
    penalty_latency = min(15, max(0, (latency_ms - 150) // 20)) if latency_ms > 0 else 0
    penalty_fails = consecutive_fails * 30
    score = base + bonus_history - penalty_latency - penalty_fails
    return max(1, min(100, score))


@dataclass(frozen=True, slots=True)
class LifecycleDecision:
    state: str
    consecutive_fails: int
    ok_count: int


def resolve_lifecycle(
    ok_count: int,
    consecutive_fails: int,
    probe_result: str,
) -> LifecycleDecision:
    """Определяет решение жизненного цикла (state, consecutive_fails, ok_count).

    OCP: Терминальные сбои (AGY-BLOCK / геоблок Google) мгновенно переводят узел
    в STATE_DEAD без испытательного срока.
    Транзиентные сбои (DEAD / таймаут сети) сохраняют Grace Period (DEGRADED).
    """
    if probe_result == RESULT_OK:
        return LifecycleDecision(state=STATE_ACTIVE, consecutive_fails=0, ok_count=ok_count + 1)

    # Терминальный сбой: геоблок — это свойство IP/подсети в Google, не деградирует
    if probe_result in TERMINAL_FAILURES:
        return LifecycleDecision(state=STATE_DEAD, consecutive_fails=MAX_CONSECUTIVE_FAILS, ok_count=0)

    # Сетевой транзиентный сбой (DEAD / таймаут / connection reset)
    new_fails = consecutive_fails + 1
    if ok_count >= 1 and new_fails < MAX_CONSECUTIVE_FAILS:
        return LifecycleDecision(state=STATE_DEGRADED, consecutive_fails=new_fails, ok_count=ok_count)

    return LifecycleDecision(state=STATE_DEAD, consecutive_fails=new_fails, ok_count=ok_count)


def _normalize_entry(rec: dict) -> dict:
    """Обеспечивает обратную совместимость для старых записей кэша results.json."""
    res = rec.get("result", "")
    is_ok = res == RESULT_OK
    rec.setdefault("state", STATE_ACTIVE if is_ok else STATE_DEAD)
    rec.setdefault("score", 70 if is_ok else 0)
    rec.setdefault("consecutive_fails", 0)
    rec.setdefault("ok_count", 1 if is_ok else 0)
    rec.setdefault("check_count", 1)
    rec.setdefault("first_seen", rec.get("checked", ""))
    rec.setdefault("last_ok", rec.get("checked", "") if is_ok else "")
    rec.setdefault("web_status", "")
    rec.setdefault("ingress_country_code", "")
    rec.setdefault("ingress_ip", "")
    rec.setdefault("antidpi_strategy", None)

    # Ретроактивная нормализация: геоблоки никогда не могут быть в DEGRADED
    if res in TERMINAL_FAILURES and rec.get("state") == STATE_DEGRADED:
        rec["state"] = STATE_DEAD
        rec["score"] = 0
        rec["consecutive_fails"] = MAX_CONSECUTIVE_FAILS

    return rec


def server_from_cache_entry(
    entry: dict[str, Any],
    *,
    require_endpoint: bool = False,
) -> Server | None:
    """Восстанавливает объект Server из записи кэша results.json (SSOT)."""
    raw_obj = entry.get("import_obj")
    if not isinstance(raw_obj, dict):
        return None
    host, port = extract_host_port(raw_obj)
    if require_endpoint and (not host or not port):
        return None
    eng = str(entry.get("engine") or "")
    if not eng:
        eng = "xray" if raw_obj.get("protocol") else "sing-box"
    res = str(entry.get("result", ""))
    state = str(entry.get("state", STATE_ACTIVE if res == RESULT_OK else STATE_DEGRADED))
    strat = entry.get("antidpi_strategy")
    strat_val: int | None = int(strat) if strat and int(strat) > 0 else None
    return Server(
        group_id=0,
        group_name="",
        name=str(raw_obj.get("tag", "")),
        engine=eng,
        server=host,
        server_port=port,
        import_obj=raw_obj,
        source="cache",
        result=res,
        country=str(entry.get("country", "")),
        ip_out=str(entry.get("ip_out", "")),
        country_code=str(entry.get("country_code", "")),
        city=str(entry.get("city", "")),
        org=str(entry.get("org", "")),
        ingress_country_code=str(entry.get("ingress_country_code", "")),
        ingress_ip=str(entry.get("ingress_ip", "")),
        antidpi_strategy=strat_val,
        score=int(entry.get("score", 70 if res == RESULT_OK else 0)),
        state=state,
        consecutive_fails=int(entry.get("consecutive_fails", 0)),
        note=str(entry.get("note") or ""),
    )


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
        self.meta: dict[str, Any] = {}
        self.load()

    def get_meta(self, key: str, default: Any = None) -> Any:
        return self.meta.get(key, default)

    def set_meta(self, key: str, value: Any) -> None:
        self.meta[key] = value

    def load(self) -> None:
        if not self.path.exists():
            self.entries = {}
            self.meta = {}
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                raw_meta = data.get("meta")
                self.meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
                servers = data.get("servers")
                if isinstance(servers, dict):
                    self.entries = {
                        k: _normalize_entry(v)
                        for k, v in servers.items()
                        if isinstance(k, str) and isinstance(v, dict)
                    }
                else:
                    self.entries = {}
            else:
                self.entries = {}
                self.meta = {}
        except Exception:
            self.entries = {}
            self.meta = {}

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
        now_dt = now or utcnow()
        now_s = now_dt.isoformat(timespec="seconds")
        cur_raw = self.entries.get(server.cache_key) or self.entries.get(server.host_port) or {}
        cur = _normalize_entry(dict(cur_raw)) if cur_raw else {}

        cur_ok_count = int(cur.get("ok_count", 1 if cur.get("result") == RESULT_OK else 0))
        cur_check_count = int(cur.get("check_count", 0)) + 1
        cur_fails = int(cur.get("consecutive_fails", 0))

        decision = resolve_lifecycle(
            ok_count=cur_ok_count,
            consecutive_fails=cur_fails,
            probe_result=server.result,
        )
        new_state = decision.state
        new_fails = decision.consecutive_fails
        new_ok_count = decision.ok_count
        new_score = calculate_score(
            ok_count=new_ok_count,
            consecutive_fails=new_fails,
            latency_ms=server.latency_ms,
        )

        first_seen = cur.get("first_seen") or now_s
        last_ok = now_s if server.result == RESULT_OK else (cur.get("last_ok") or "")

        server.state = new_state
        server.score = new_score
        server.consecutive_fails = new_fails

        if server.result == RESULT_OK:
            effective_strategy = server.antidpi_strategy
        elif new_state == STATE_DEGRADED:
            effective_strategy = (
                server.antidpi_strategy if server.antidpi_strategy is not None else cur.get("antidpi_strategy")
            )
        else:
            effective_strategy = None

        rec: dict = {
            "checked": now_s,
            "result": server.result,
            "country": server.country or cur.get("country", ""),
            "ip_out": server.ip_out or cur.get("ip_out", ""),
            "country_code": server.country_code or cur.get("country_code", ""),
            "city": server.city or cur.get("city", ""),
            "org": server.org or cur.get("org", ""),
            "latency_ms": server.latency_ms,
            "note": server.note,
            "web_status": server.web_status or cur.get("web_status", ""),
            "ingress_country_code": server.ingress_country_code or cur.get("ingress_country_code", ""),
            "ingress_ip": server.ingress_ip or cur.get("ingress_ip", ""),
            "antidpi_strategy": effective_strategy,
            "state": new_state,
            "score": new_score,
            "consecutive_fails": new_fails,
            "ok_count": new_ok_count,
            "check_count": cur_check_count,
            "first_seen": first_seen,
            "last_ok": last_ok,
        }
        if server.result == RESULT_OK or new_state == STATE_DEGRADED:
            rec["engine"] = server.engine or cur.get("engine", "")
            rec["import_obj"] = server.import_obj or cur.get("import_obj")
        self.put(server.cache_key, rec, force=True, now=now_dt)

    def enrich_from_server(self, server: Server) -> bool:
        rec = self.entries.get(server.cache_key) or self.entries.get(server.host_port)
        if not rec or rec.get("result") != RESULT_OK:
            return False
        changed = False
        if server.import_obj and not rec.get("import_obj"):
            rec["engine"] = server.engine
            rec["import_obj"] = server.import_obj
            changed = True
        if server.country_code and not rec.get("country_code"):
            rec["country_code"] = server.country_code
            rec["city"] = server.city
            rec["org"] = server.org
            changed = True
        if server.ingress_country_code and not rec.get("ingress_country_code"):
            rec["ingress_country_code"] = server.ingress_country_code
            rec["ingress_ip"] = server.ingress_ip
            changed = True
        return changed

    def enrich_geo_from_ips(self, ip_map: dict[str, tuple[str, str, str, str, str]]) -> int:
        """Обогащает записи кэша AGY-OK гео-метаданными из словаря {ip: (country, ip_out, code, city, org)}."""
        changed_count = 0
        for rec in self.entries.values():
            if rec.get("result") != RESULT_OK:
                continue
            ip = str(rec.get("ip_out") or "").strip()
            if not ip or ip not in ip_map:
                continue
            country, _, code, city, org = ip_map[ip]
            if not code and not country:
                continue
            rec_changed = False
            if not rec.get("country_code") and code:
                rec["country_code"] = code
                rec_changed = True
            if not rec.get("city") and city:
                rec["city"] = city
                rec_changed = True
            if not rec.get("org") and org:
                rec["org"] = org
                rec_changed = True
            if not rec.get("country") and country:
                rec["country"] = country
                rec_changed = True
            if rec_changed:
                changed_count += 1
        return changed_count

    def clear_dead(self) -> int:
        """Удаляет из кэша все записи со статусом DEAD и сохраняет файл."""
        before = len(self.entries)
        self.entries = {k: v for k, v in self.entries.items() if v.get("result") != RESULT_DEAD}
        removed = before - len(self.entries)
        if removed:
            self.save()
        return removed

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        payload = {"version": CACHE_VERSION, "meta": self.meta, "servers": self.entries}
        tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        tmp.replace(self.path)
