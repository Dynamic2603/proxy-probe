from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from functools import cache
from pathlib import Path
from typing import Any

from .engines import build_singbox_config, build_xray_config, wait_port, xray_shorthand_to_v2ray
from .models import (
    BLOCK_MARKERS,
    DEAD_PATTERNS,
    RESULT_BLOCK,
    RESULT_DEAD,
    RESULT_OK,
    RESULT_UNKNOWN,
    UNKNOWN_PATTERNS,
)
from .parsers import USER_AGENT


def find_agy_bin() -> str:
    env_bin = os.environ.get("AGY_BIN")
    if env_bin and Path(env_bin).is_file():
        return str(Path(env_bin).resolve())
    for name in ("agy", "agy.exe"):
        w = shutil.which(name)
        if w:
            return str(Path(w).resolve())
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        candidate = Path(local_app) / "agy" / "bin" / "agy.exe"
        if candidate.is_file():
            return str(candidate.resolve())
    home_candidate = Path.home() / "AppData" / "Local" / "agy" / "bin" / "agy.exe"
    if home_candidate.is_file():
        return str(home_candidate.resolve())
    return "agy"


@cache
def get_default_agy_bin() -> str:
    return find_agy_bin()


AGY_PROMPT = "Reply with only the word OK"
AGY_PRINT_TIMEOUT_DEFAULT = "45s"
GEO_URL = "http://ipwho.is/"


def classify_agy(out: str, rc: int) -> str:
    out_lower = out.lower()
    if any(m.lower() in out_lower for m in BLOCK_MARKERS):
        return RESULT_BLOCK
    for p in UNKNOWN_PATTERNS:
        if p.lower() in out_lower:
            return RESULT_UNKNOWN
    for p in DEAD_PATTERNS:
        p_lower = p.lower()
        if p_lower == "eof":
            if re.search(r"\beof\b", out_lower):
                return RESULT_DEAD
        elif p_lower in out_lower:
            return RESULT_DEAD
    if rc < 0:
        return RESULT_DEAD
    if rc != 0 or not out.strip():
        return RESULT_UNKNOWN
    return RESULT_OK


def agy_probe(port: int, agy_bin: str, print_timeout: str, total_timeout: float) -> tuple[str, int]:
    env = dict(os.environ)
    proxy_url = f"http://127.0.0.1:{port}"
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env[key] = proxy_url
    for key in ("NO_PROXY", "no_proxy"):
        env[key] = ""
    cmd = [
        agy_bin,
        "-p",
        AGY_PROMPT,
        "--print-timeout",
        print_timeout,
        "--disable-slash-commands",
        "--output-format",
        "text",
    ]
    with tempfile.TemporaryDirectory(prefix="pxp_probe_", ignore_cleanup_errors=True) as cwd:
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                cwd=cwd,
                env=env,
                timeout=total_timeout,
            )
            out_txt = res.stdout.decode("utf-8", errors="replace").strip() if res.stdout else ""
            err_txt = res.stderr.decode("utf-8", errors="replace").strip() if res.stderr else ""
            combined = f"{out_txt}\n{err_txt}" if out_txt and err_txt else (out_txt or err_txt)
            return combined, res.returncode
        except subprocess.TimeoutExpired:
            return "", -1
        except OSError as e:
            return str(e), -2


PREFLIGHT_URL = "https://www.google.com/generate_204"


def fetch_geo(port: int, timeout: float = 8.0) -> tuple[str, str]:
    proxy_url = f"http://127.0.0.1:{port}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(GEO_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            flag = data.get("flag", "")
            if isinstance(flag, dict):
                flag = flag.get("emoji", "")
            country = f"{flag} {data.get('country', '')}".strip()
            return country, str(data.get("ip", ""))
    except Exception:
        return "", ""


def preflight_check(port: int, timeout: float = 4.0) -> bool:
    """Fast connectivity test through proxy before launching heavy agy binary.

    Returns True if the proxy tunnel is alive (can reach external hosts).
    """
    proxy_url = f"http://127.0.0.1:{port}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(PREFLIGHT_URL, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status in (200, 204)
    except Exception:
        return False


def _tail_file(path: Path, n: int = 6, limit: int = 512) -> str:
    try:
        lines = path.read_text("utf-8", "replace").splitlines()
        return "\n".join(lines[-n:])[:limit]
    except Exception:
        return ""


def run_probe(
    engine_bin: str,
    is_xray: bool,
    import_obj: dict[str, Any],
    port: int,
    run_root: Path,
    timeouts: dict[str, float],
    agy_bin: str | None = None,
    print_timeout: str = AGY_PRINT_TIMEOUT_DEFAULT,
) -> dict[str, Any]:
    resolved_agy_bin = agy_bin or get_default_agy_bin()
    d = run_root / f"p{port}"
    d.mkdir(parents=True, exist_ok=True)
    log_rel = "engine.log"
    if is_xray:
        test_out = xray_shorthand_to_v2ray(import_obj)
        cfg = build_xray_config(test_out, port, log_rel)
    else:
        cfg = build_singbox_config(import_obj, port, log_rel)
    (d / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
    out_path = d / "engine.out"
    log_path = d / log_rel
    t0 = time.time()
    out_f = None
    proc = None
    try:
        out_f = open(out_path, "wb")
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        }
        proc = subprocess.Popen(
            [engine_bin, "run", "-c", "config.json"],
            cwd=str(d),
            stdout=out_f,
            stderr=subprocess.STDOUT,
            env=clean_env,
        )
    except OSError as e:
        if out_f is not None:
            with contextlib.suppress(Exception):
                out_f.close()
        return {
            "result": RESULT_DEAD,
            "country": "",
            "ip_out": "",
            "latency_ms": 0,
            "note": f"движок не запустился: {e}",
        }

    try:
        if not wait_port(port, proc, timeouts.get("start", 12.0)):
            note = (_tail_file(log_path) + "\n" + _tail_file(out_path)).strip()
            return {
                "result": RESULT_DEAD,
                "country": "",
                "ip_out": "",
                "latency_ms": 0,
                "note": f"движок не поднял порт: {note[:200]}",
            }

        # Preflight: быстрая проверка связности туннеля перед запуском тяжёлого agy
        preflight_ok = preflight_check(port, timeout=timeouts.get("preflight", 4.0))
        if not preflight_ok:
            return {
                "result": RESULT_DEAD,
                "country": "",
                "ip_out": "",
                "latency_ms": int((time.time() - t0) * 1000),
                "note": "preflight: туннель не пропускает трафик",
            }

        # Geo-данные уже можно получить — туннель жив
        country, ip_out = fetch_geo(port, timeouts.get("geo", 8.0))

        try:
            atext, arc = agy_probe(port, resolved_agy_bin, print_timeout, timeouts.get("probe", 45.0))
        except Exception as e:
            return {
                "result": RESULT_DEAD,
                "country": country,
                "ip_out": ip_out,
                "latency_ms": int((time.time() - t0) * 1000),
                "note": f"agy: {e}"[:160],
            }

        latency = int((time.time() - t0) * 1000)
        result = classify_agy(atext or "", arc)

        # Если agy таймаутнул (rc == -1), но preflight прошёл — туннель жив,
        # проблема в agy/API, а не в прокси → UNKNOWN, не DEAD
        if arc == -1 and result == RESULT_DEAD:
            result = RESULT_UNKNOWN

        raw_text = " ".join((atext or "").strip().split())
        if arc == -1:
            note = f"таймаут agy ({timeouts.get('probe', 45.0):.0f}с)"
        elif arc == -2:
            note = f"ошибка запуска agy: {raw_text}"
        elif raw_text:
            note = raw_text[:250]
        elif arc != 0:
            note = f"rc={arc} (нет вывода)"
        else:
            note = ""
        return {
            "result": result,
            "country": country,
            "ip_out": ip_out,
            "latency_ms": latency,
            "note": note,
        }
    finally:
        if out_f is not None:
            with contextlib.suppress(Exception):
                out_f.close()
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                with contextlib.suppress(Exception):
                    proc.kill()
                with contextlib.suppress(Exception):
                    proc.wait(timeout=5)
