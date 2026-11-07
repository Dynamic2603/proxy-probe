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
    GEO_PRECHECK_URL,
    RESULT_BLOCK,
    RESULT_DEAD,
    RESULT_OK,
    RESULT_UNKNOWN,
    UNKNOWN_PATTERNS,
    WEB_CHECK_URL,
    WEB_STATUS_BLOCKED,
    WEB_STATUS_CAPTCHA,
    WEB_STATUS_OK,
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
def detect_best_agy_model(agy_bin: str, cache: Any = None) -> str | None:
    """Определяет наилучшую легковесную модель через 'agy models' с поддержкой кэша метаданных."""
    env_model = os.environ.get("AGY_MODEL")
    if env_model:
        return env_model.strip()

    if cache is not None:
        try:
            cached_model = cache.get_meta("best_model")
            saved_at = float(cache.get_meta("best_model_saved_at", 0))
            if cached_model and isinstance(cached_model, str) and (time.time() - saved_at < 86400):
                return cached_model
        except Exception:
            pass

    matched: str | None = None
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
    except Exception:
        pass

    if matched and cache is not None:
        try:
            cache.set_meta("best_model", matched)
            cache.set_meta("best_model_saved_at", time.time())
            cache.save()
        except Exception:
            pass
    return matched


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


def parse_geo_payload(data: dict) -> tuple[str, str, str, str, str]:
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


def fetch_geo_for_ip(ip: str, timeout: float = 4.0) -> tuple[str, str, str, str, str]:
    """Запрашивает гео-данные для egress IP напрямую с ipwho.is."""
    if not ip or ip.startswith("127.") or ip == "localhost":
        return "", "", "", "", ""
    url = f"http://ipwho.is/{ip}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            return parse_geo_payload(data)
    except Exception:
        return "", "", "", "", ""


_INGRESS_GEO_CACHE: dict[str, tuple[str, str]] = {}
_INGRESS_GEO_LOCK = threading.Lock()


def resolve_host_ip(host: str) -> str:
    """Резолвит доменное имя в IPv4-адрес. Если host уже IP, возвращает его."""
    h = (host or "").strip()
    if not h:
        return ""
    try:
        socket.inet_aton(h)
        return h
    except OSError:
        pass
    try:
        return socket.gethostbyname(h)
    except Exception:
        return ""


def resolve_ingress_country(host: str, timeout: float = 3.0) -> tuple[str, str]:
    """Возвращает (country_code, resolved_ip) для точки входа с потокобезопасной мемоизацией."""
    h = (host or "").strip()
    if not h:
        return "", ""
    with _INGRESS_GEO_LOCK:
        if h in _INGRESS_GEO_CACHE:
            return _INGRESS_GEO_CACHE[h]

    ip = resolve_host_ip(h)
    if not ip or ip.startswith("127.") or ip == "localhost":
        with _INGRESS_GEO_LOCK:
            _INGRESS_GEO_CACHE[h] = ("", ip)
        return "", ip

    with _INGRESS_GEO_LOCK:
        if ip in _INGRESS_GEO_CACHE:
            res = _INGRESS_GEO_CACHE[ip]
            _INGRESS_GEO_CACHE[h] = res
            return res

    _, _, code, _, _ = fetch_geo_for_ip(ip, timeout=timeout)
    code = (code or "").strip().upper()
    with _INGRESS_GEO_LOCK:
        _INGRESS_GEO_CACHE[h] = (code, ip)
        _INGRESS_GEO_CACHE[ip] = (code, ip)
    return code, ip


def fetch_geo(port: int, timeout: float = 8.0) -> tuple[str, str, str, str, str]:
    proxy_url = f"http://127.0.0.1:{port}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(GEO_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            return parse_geo_payload(data)
    except Exception:
        return "", "", "", "", ""


def enrich_cached_ok_geo(cache: Any, max_workers: int = 10) -> int:
    """Обогащает записи кэша AGY-OK недостающими полями (country_code, city, org) по ip_out."""
    if not cache or not getattr(cache, "entries", None):
        return 0
    needed_ips: set[str] = set()
    for rec in cache.entries.values():
        if rec.get("result") == RESULT_OK and rec.get("ip_out") and (not rec.get("country_code") or not rec.get("org")):
            ip = str(rec.get("ip_out")).strip()
            if ip and not ip.startswith("127."):
                needed_ips.add(ip)

    if not needed_ips:
        return 0

    ip_results: dict[str, tuple[str, str, str, str, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(needed_ips))) as ex:
        future_to_ip = {ex.submit(fetch_geo_for_ip, ip): ip for ip in needed_ips}
        for fut in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                res = fut.result()
                if res[0] or res[2]:
                    ip_results[ip] = res
            except Exception:
                pass

    if ip_results:
        updated = cache.enrich_geo_from_ips(ip_results)
        if updated > 0:
            cache.save()
        return updated
    return 0


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Предотвращает автоматический переход по редиректам для инспекции заголовков."""

    def redirect_request(self, *args: Any, **_kwargs: Any) -> None:
        return None


def tunnel_http_request(
    port: int,
    url: str,
    timeout: float = 4.0,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
) -> tuple[int, str, dict[str, str]]:
    """Выполняет HTTP(S) запрос через локальный прокси-порт туннеля (SSOT/DRY).

    Возвращает (status_code, body_snippet, response_headers).
    При сбое сети или таймауте возвращает (0, "", {}).
    """
    proxy_url = f"http://127.0.0.1:{port}"
    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    handlers: list[Any] = [proxy_handler]
    if not follow_redirects:
        handlers.append(NoRedirectHandler())
    opener = urllib.request.build_opener(*handlers)

    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)

    try:
        with opener.open(req, timeout=timeout) as resp:
            code = getattr(resp, "status", getattr(resp, "code", 200))
            raw = resp.read(65536)
            body = raw.decode("utf-8", errors="replace")
            resp_headers = {k.lower(): str(v) for k, v in resp.headers.items()}
            return code, body, resp_headers
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            raw = e.read(65536)
            body = raw.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        resp_headers = {k.lower(): str(v) for k, v in e.headers.items()} if hasattr(e, "headers") and e.headers else {}
        return code, body, resp_headers
    except Exception:
        return 0, "", {}


def preflight_check(port: int, timeout: float = 4.0) -> bool:
    """Fast connectivity test through proxy before launching heavy agy binary.

    Returns True if the proxy tunnel is alive (can reach external hosts).
    """
    code, _, _ = tunnel_http_request(port, PREFLIGHT_URL, timeout=timeout)
    return code in (200, 204)


def geo_precheck(port: int, timeout: float = 2.5) -> tuple[bool, str]:
    """Быстрая проверка геоблока Google через легковесный запрос к aistudio.google.com.

    Возвращает (is_blocked, reason):
      (True, reason) -> подтверждённый геоблок (403 Forbidden / явный маркер в ответе).
      (False, "")    -> доступ к Google Edge открыт (200 OK / 302).
    """
    code, body, _headers = tunnel_http_request(
        port,
        GEO_PRECHECK_URL,
        timeout=timeout,
        headers={"Accept-Language": "en-US,en;q=0.9"},
        follow_redirects=True,
    )
    if code == 403:
        return True, "403 Forbidden"
    if code == 0:
        return False, ""
    body_lower = body.lower()
    if "user location is not supported" in body_lower or "unsupported location" in body_lower:
        return True, "unsupported location"
    return False, ""


def web_probe(port: int, timeout: float = 3.5) -> tuple[str, str]:
    """Проверяет веб-доступность gemini.google.com и выявляет капчу Google.

    Возвращает (web_status, detail):
      (WEB_STATUS_OK, "200 OK")
      (WEB_STATUS_CAPTCHA, "google.com/sorry")
      (WEB_STATUS_BLOCKED, "403 Forbidden")
      ("", "failed/timeout")
    """
    code, body, headers = tunnel_http_request(
        port,
        WEB_CHECK_URL,
        timeout=timeout,
        headers={"Accept-Language": "en-US,en;q=0.9"},
        follow_redirects=True,
    )
    if code == 0:
        return "", "connection failed"
    if code == 403:
        return WEB_STATUS_BLOCKED, "403 Forbidden"

    location = headers.get("location", "").lower()
    body_lower = body.lower()
    if "sorry/index" in location or "unusual traffic from your computer network" in body_lower:
        return WEB_STATUS_CAPTCHA, "google.com/sorry"

    if code in (200, 302, 303):
        return WEB_STATUS_OK, f"{code} OK"

    return "", f"http {code}"


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
    use_geo_precheck: bool = True,
    check_web: bool = False,
    extra_outbounds: list[dict[str, Any]] | None = None,
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
        cfg = build_xray_config(test_out, port, extra_outbounds=extra_outbounds)
        cmd = [engine_bin, "run", "-c", "stdin:"]
    else:
        cfg = build_singbox_config(import_obj, port, extra_outbounds=extra_outbounds)
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

        # Zero-Quota Geo Precheck (быстрый отсев геоблока до запуска agy)
        if use_geo_precheck:
            is_blocked, block_reason = geo_precheck(port, timeouts.get("geo_precheck", 2.5))
            if is_blocked:
                return {
                    "result": RESULT_BLOCK,
                    "country": country,
                    "ip_out": ip_out,
                    "country_code": country_code,
                    "city": city,
                    "org": org,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "note": f"геоблок (быстрый precheck: {block_reason})",
                    "web_status": WEB_STATUS_BLOCKED,
                }

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

        web_status = ""
        if check_web and result == RESULT_OK:
            w_status, _ = web_probe(port, timeouts.get("web_check", 3.5))
            web_status = w_status
            if w_status == WEB_STATUS_CAPTCHA:
                note = f"{note} [captcha]".strip() if note else "captcha (google.com/sorry)"

        ingress_country_code = ""
        ingress_ip = ""
        server_host = str(import_obj.get("server") or "").strip()
        if not server_host:
            sett = import_obj.get("settings")
            if isinstance(sett, dict):
                vnext = sett.get("vnext")
                if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
                    server_host = str(vnext[0].get("address") or "").strip()

        if server_host and ip_out and server_host != ip_out:
            ingress_country_code, ingress_ip = resolve_ingress_country(server_host, timeout=3.0)

        return {
            "result": result,
            "country": country,
            "ip_out": ip_out,
            "country_code": country_code,
            "city": city,
            "org": org,
            "latency_ms": latency,
            "note": note,
            "web_status": web_status,
            "ingress_country_code": ingress_country_code,
            "ingress_ip": ingress_ip,
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
