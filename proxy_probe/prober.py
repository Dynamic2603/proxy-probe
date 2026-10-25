from __future__ import annotations

import concurrent.futures
import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from collections import deque
from collections.abc import Callable
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
    QuotaInfo,
    country_code_to_emoji,
    parse_quota_info,
)
from .parsers import USER_AGENT


class QuotaCircuitBreaker:
    """Потокобезопасный автомат аварийного отключения при исчерпании глобальной квоты."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._reason: str = ""

    def trip(self, reason: str = "") -> None:
        with self._lock:
            if not self._event.is_set():
                self._reason = reason or "квота agy исчерпана"
                self._event.set()

    @property
    def is_tripped(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason


class ProcessRegistry:
    """Потокобезопасный реестр запущенных процессов для немедленной остановки."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._procs: set[subprocess.Popen[Any]] = set()

    def register(self, proc: subprocess.Popen[Any]) -> None:
        with self._lock:
            self._procs.add(proc)

    def unregister(self, proc: subprocess.Popen[Any]) -> None:
        with self._lock:
            self._procs.discard(proc)

    def kill_all(self) -> None:
        with self._lock:
            procs = list(self._procs)
            self._procs.clear()
        for p in procs:
            with contextlib.suppress(Exception):
                p.kill()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._procs)


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


FLASH_PREFERENCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"flash.*low", re.IGNORECASE),
    re.compile(r"flash.*medium", re.IGNORECASE),
    re.compile(r"flash", re.IGNORECASE),
]


def resolve_lightest_flash_model(model_names: list[str]) -> str | None:
    """Выбирает наиболее экономичную Flash-модель из списка доступных.

    Приоритет:
    1. Модели с маркером flash.*low (например, gemini-3.8-flash-low)
    2. Модели с маркером flash.*medium (например, gemini-3.8-flash-medium)
    3. Любая модель с маркером flash
    """
    for pat in FLASH_PREFERENCE_PATTERNS:
        for name in model_names:
            if pat.search(name):
                return name
    return None


@cache
def detect_best_agy_model(agy_bin: str) -> str | None:
    """Определяет наилучшую легковесную модель через 'agy models'."""
    env_model = os.environ.get("AGY_MODEL")
    if env_model:
        return env_model.strip()

    try:
        proc = subprocess.run(
            [agy_bin, "models"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            names: list[str] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line or line.lower().startswith("fetching"):
                    continue
                parts = line.split()
                if parts:
                    names.append(parts[0])
            matched = resolve_lightest_flash_model(names)
            if matched:
                return matched
    except Exception:
        pass
    return None


def check_agy_health(
    agy_bin: str,
    model: str | None = None,
    timeout: float = 15.0,
) -> tuple[bool, QuotaInfo]:
    """Быстрая проверка доступности квоты agy перед запуском пула."""
    cmd = [
        agy_bin,
        "-p",
        AGY_PROMPT,
        "--print-timeout",
        "10s",
        "--disable-slash-commands",
        "--output-format",
        "text",
    ]
    if model:
        cmd.extend(["--model", model])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        combined = f"{proc.stdout or ''}\n{proc.stderr or ''}".strip()
        quota_info = parse_quota_info(combined)
        if quota_info.is_exhausted:
            return False, quota_info
        return True, quota_info
    except Exception:
        return True, QuotaInfo(is_exhausted=False)


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


def agy_probe(
    port: int,
    agy_bin: str,
    print_timeout: str,
    total_timeout: float,
    model: str | None = None,
    stop_event: threading.Event | None = None,
    registry: ProcessRegistry | None = None,
) -> tuple[str, int]:
    if stop_event is not None and stop_event.is_set():
        return "", -1
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
    if model:
        cmd.extend(["--model", model])
    with tempfile.TemporaryDirectory(prefix="pxp_probe_", ignore_cleanup_errors=True) as cwd:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
            if registry is not None:
                registry.register(proc)
            try:
                stdout_data, stderr_data = proc.communicate(timeout=total_timeout)
                if stop_event is not None and stop_event.is_set():
                    return "", -1
                out_txt = stdout_data.decode("utf-8", errors="replace").strip() if stdout_data else ""
                err_txt = stderr_data.decode("utf-8", errors="replace").strip() if stderr_data else ""
                combined = f"{out_txt}\n{err_txt}" if out_txt and err_txt else (out_txt or err_txt)
                return combined, proc.returncode
            except subprocess.TimeoutExpired:
                with contextlib.suppress(Exception):
                    proc.kill()
                with contextlib.suppress(Exception):
                    proc.communicate()
                return "", -1
            finally:
                if registry is not None:
                    registry.unregister(proc)
        except OSError as e:
            return str(e), -2


PREFLIGHT_URL = "https://www.google.com/generate_204"


def probe_tcp_port(host: str, port: int, timeout: float = 1.5) -> tuple[bool, int, str]:
    """Проверяет доступность удалённого хоста по L4 TCP (3-way handshake).

    Возвращает:
        (is_alive, latency_ms, error_note)
    """
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = max(1, int((time.perf_counter() - t0) * 1000))
            return True, latency_ms, ""
    except TimeoutError:
        return False, 0, "tcp: таймаут соединения (хост не отвечает)"
    except ConnectionRefusedError:
        return False, 0, "tcp: соединение сброшено (порт закрыт)"
    except socket.gaierror:
        return False, 0, "tcp: ошибка разрешения доменного имени (DNS)"
    except OSError as e:
        err_msg = str(e.strerror or e).strip()
        return False, 0, f"tcp: ошибка сокета ({err_msg})"


def batch_probe_tcp(
    endpoints: set[tuple[str, int]],
    timeout: float = 1.5,
    max_workers: int = 100,
    stop_event: threading.Event | None = None,
    progress_callback: Callable[[int, int], Any] | None = None,
) -> dict[tuple[str, int], tuple[bool, int, str]]:
    """Параллельно проверяет доступность множества уникальных TCP-эндпоинтов (host, port).

    Возвращает:
        dict[(host, port) -> (is_alive, latency_ms, error_note)]
    """
    results: dict[tuple[str, int], tuple[bool, int, str]] = {}
    if not endpoints:
        return results

    total = len(endpoints)
    completed = 0
    workers = min(max_workers, max(1, total))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ep = {
            executor.submit(probe_tcp_port, host, port, timeout): (host, port)
            for host, port in endpoints
        }
        for future in concurrent.futures.as_completed(future_to_ep):
            if stop_event is not None and stop_event.is_set():
                for f in future_to_ep:
                    f.cancel()
                break
            ep = future_to_ep[future]
            try:
                results[ep] = future.result()
            except Exception as e:
                results[ep] = (False, 0, f"tcp: внутренняя ошибка ({e})")
            completed += 1
            if progress_callback:
                progress_callback(completed, total)

    if stop_event is not None and stop_event.is_set():
        for ep in endpoints:
            if ep not in results:
                results[ep] = (False, 0, "проверка отменена")

    return results


def fetch_geo(port: int, timeout: float = 8.0) -> tuple[str, str, str, str, str]:
    proxy_url = f"http://127.0.0.1:{port}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(GEO_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            country_code = str(data.get("country_code", "")).strip().upper()
            flag = data.get("flag", "")
            if isinstance(flag, dict):
                flag = flag.get("emoji", "")
            if not flag and country_code:
                flag = country_code_to_emoji(country_code)
            country = f"{flag} {data.get('country', '')}".strip()
            ip_out = str(data.get("ip", "")).strip()
            city = str(data.get("city", "")).strip()
            conn = data.get("connection")
            org = ""
            if isinstance(conn, dict):
                org = str(conn.get("org") or conn.get("isp") or "").strip()
            if not org:
                org = str(data.get("org") or "").strip()
            return country, ip_out, country_code, city, org
    except Exception:
        return "", "", "", "", ""


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


def _drain_output(pipe: Any, buf: deque[str]) -> None:
    try:
        for raw_line in iter(pipe.readline, b""):
            line = raw_line.decode("utf-8", errors="replace").strip()
            if line:
                buf.append(line)
    except Exception:
        pass


def run_probe(
    engine_bin: str,
    is_xray: bool,
    import_obj: dict[str, Any],
    port: int,
    run_root: Path | None = None,
    timeouts: dict[str, float] | None = None,
    agy_bin: str | None = None,
    print_timeout: str = AGY_PRINT_TIMEOUT_DEFAULT,
    agy_model: str | None = None,
    agy_semaphore: threading.Semaphore | None = None,
    circuit_breaker: QuotaCircuitBreaker | None = None,
    stop_event: threading.Event | None = None,
    registry: ProcessRegistry | None = None,
) -> dict[str, Any]:
    if stop_event is not None and stop_event.is_set():
        return {
            "result": RESULT_DEAD,
            "country": "",
            "ip_out": "",
            "country_code": "",
            "city": "",
            "org": "",
            "latency_ms": 0,
            "note": "проверка отменена",
        }
    if timeouts is None:
        timeouts = {}
    resolved_agy_bin = agy_bin or get_default_agy_bin()
    if is_xray:
        test_out = xray_shorthand_to_v2ray(import_obj)
        cfg = build_xray_config(test_out, port)
        cmd = [engine_bin, "run", "-c", "stdin:"]
    else:
        cfg = build_singbox_config(import_obj, port)
        cmd = [engine_bin, "run", "-c", "stdin"]

    cfg_bytes = json.dumps(cfg, ensure_ascii=False).encode("utf-8")
    log_buffer: deque[str] = deque(maxlen=30)
    drain_thread: threading.Thread | None = None
    proc: subprocess.Popen[bytes] | None = None
    t0 = time.time()
    try:
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
        }
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=clean_env,
        )
        if proc.stdin is not None:
            proc.stdin.write(cfg_bytes)
            proc.stdin.close()
        if proc.stdout is not None:
            drain_thread = threading.Thread(target=_drain_output, args=(proc.stdout, log_buffer), daemon=True)
            drain_thread.start()
        if registry is not None:
            registry.register(proc)
    except OSError as e:
        return {
            "result": RESULT_DEAD,
            "country": "",
            "ip_out": "",
            "country_code": "",
            "city": "",
            "org": "",
            "latency_ms": 0,
            "note": f"движок не запустился: {e}",
        }

    try:
        if stop_event is not None and stop_event.is_set():
            return {
                "result": RESULT_DEAD,
                "country": "",
                "ip_out": "",
                "country_code": "",
                "city": "",
                "org": "",
                "latency_ms": 0,
                "note": "проверка отменена",
            }

        if not wait_port(port, proc, timeouts.get("start", 12.0), stop_event=stop_event):
            if stop_event is not None and stop_event.is_set():
                return {
                    "result": RESULT_DEAD,
                    "country": "",
                    "ip_out": "",
                    "country_code": "",
                    "city": "",
                    "org": "",
                    "latency_ms": 0,
                    "note": "проверка отменена",
                }
            note = "\n".join(log_buffer).strip()
            return {
                "result": RESULT_DEAD,
                "country": "",
                "ip_out": "",
                "country_code": "",
                "city": "",
                "org": "",
                "latency_ms": 0,
                "note": f"движок не поднял порт: {note[:200]}",
            }

        if stop_event is not None and stop_event.is_set():
            return {
                "result": RESULT_DEAD,
                "country": "",
                "ip_out": "",
                "country_code": "",
                "city": "",
                "org": "",
                "latency_ms": 0,
                "note": "проверка отменена",
            }

        # Preflight: быстрая проверка связности туннеля перед запуском тяжёлого agy
        preflight_ok = preflight_check(port, timeout=timeouts.get("preflight", 2.5))
        if not preflight_ok:
            return {
                "result": RESULT_DEAD,
                "country": "",
                "ip_out": "",
                "country_code": "",
                "city": "",
                "org": "",
                "latency_ms": int((time.time() - t0) * 1000),
                "note": "preflight: туннель не пропускает трафик",
            }

        if stop_event is not None and stop_event.is_set():
            return {
                "result": RESULT_DEAD,
                "country": "",
                "ip_out": "",
                "country_code": "",
                "city": "",
                "org": "",
                "latency_ms": 0,
                "note": "проверка отменена",
            }

        # Geo-данные уже можно получить — туннель жив
        geo_res = fetch_geo(port, timeouts.get("geo", 8.0))
        if len(geo_res) == 5:
            country, ip_out, country_code, city, org = geo_res
        elif len(geo_res) == 2:
            country, ip_out = geo_res
            country_code, city, org = "", "", ""
        else:
            country, ip_out, country_code, city, org = "", "", "", "", ""

        if circuit_breaker is not None and circuit_breaker.is_tripped:
            return {
                "result": RESULT_UNKNOWN,
                "country": country,
                "ip_out": ip_out,
                "country_code": country_code,
                "city": city,
                "org": org,
                "latency_ms": int((time.time() - t0) * 1000),
                "note": "пропущено (квота agy исчерпана)",
            }

        try:
            if agy_semaphore is not None:
                with agy_semaphore:
                    atext, arc = agy_probe(
                        port,
                        resolved_agy_bin,
                        print_timeout,
                        timeouts.get("probe", 45.0),
                        model=agy_model,
                        stop_event=stop_event,
                        registry=registry,
                    )
            else:
                atext, arc = agy_probe(
                    port,
                    resolved_agy_bin,
                    print_timeout,
                    timeouts.get("probe", 45.0),
                    model=agy_model,
                    stop_event=stop_event,
                    registry=registry,
                )
        except Exception as e:
            return {
                "result": RESULT_DEAD,
                "country": country,
                "ip_out": ip_out,
                "country_code": country_code,
                "city": city,
                "org": org,
                "latency_ms": int((time.time() - t0) * 1000),
                "note": f"agy: {e}"[:160],
            }

        if stop_event is not None and stop_event.is_set():
            return {
                "result": RESULT_DEAD,
                "country": "",
                "ip_out": "",
                "country_code": "",
                "city": "",
                "org": "",
                "latency_ms": 0,
                "note": "проверка отменена",
            }

        latency = int((time.time() - t0) * 1000)

        quota_info = parse_quota_info(atext or "")
        if quota_info.is_exhausted:
            if circuit_breaker is not None:
                circuit_breaker.trip(quota_info.clean_note)
            result = RESULT_UNKNOWN
            note = quota_info.clean_note
        else:
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
            "country_code": country_code,
            "city": city,
            "org": org,
            "latency_ms": latency,
            "note": note,
        }
    finally:
        if proc is not None:
            if registry is not None:
                registry.unregister(proc)
            if stop_event is not None and stop_event.is_set():
                with contextlib.suppress(Exception):
                    proc.kill()
            else:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    with contextlib.suppress(Exception):
                        proc.kill()
                    with contextlib.suppress(Exception):
                        proc.wait(timeout=5)
            if proc.stdout is not None:
                with contextlib.suppress(Exception):
                    proc.stdout.close()
            if drain_thread is not None and drain_thread.is_alive():
                drain_thread.join(timeout=0.2)
