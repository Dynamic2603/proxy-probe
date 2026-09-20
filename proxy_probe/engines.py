from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from .parsers import USER_AGENT

SINGBOX_REPO = "SagerNet/sing-box"
XRAY_REPO = "XTLS/Xray-core"

_port_lock = threading.Lock()
_next_port = [20000]


def _is_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def alloc_port(max_attempts: int = 1000) -> int:
    with _port_lock:
        for _ in range(max_attempts):
            _next_port[0] += 1
            if _next_port[0] > 60000:
                _next_port[0] = 20000
            if _is_port_free(_next_port[0]):
                return _next_port[0]
        raise RuntimeError("Не удалось найти свободный порт")


def project_root() -> Path:
    candidate = Path(__file__).resolve().parent.parent
    if (candidate / "pyproject.toml").is_file():
        return candidate
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "proxy-probe"
    return Path.home() / ".proxy-probe"


def app_bin_dir(custom_dir: Path | str | None = None) -> Path:
    if custom_dir:
        p = Path(custom_dir).resolve()
    else:
        env_dir = os.environ.get("PROXY_PROBE_BIN_DIR")
        p = Path(env_dir).resolve() if env_dir else project_root() / "bin"
    p.mkdir(parents=True, exist_ok=True)
    return p


def download_file(url: str, dest: Path, timeout: float = 120.0) -> None:
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(tmp, "wb") as f:
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            f.write(chunk)
    tmp.replace(dest)


def _resolve_asset_url(repo: str, tag: str, want: str) -> str:
    direct = f"https://github.com/{repo}/releases/download/{tag}/{want}"
    try:
        req = urllib.request.Request(direct, method="HEAD", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.status == 200:
                return direct
    except Exception:
        pass
    api_url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    req = urllib.request.Request(api_url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        rel = json.loads(r.read())
    for a in rel.get("assets", []):
        if a.get("name") == want:
            return str(a.get("browser_download_url"))
    raise SystemExit(f"Не найден ассет {want} в релизе {tag} репозитория {repo}")


def _extract_binary(exe_dst: Path, zip_path: Path) -> None:
    exe_name = exe_dst.name.lower()
    with zipfile.ZipFile(zip_path) as z:
        hits = [n for n in z.namelist() if n.replace("\\", "/").lower().endswith(exe_name)]
        if not hits:
            raise SystemExit(f"В {zip_path.name} нет {exe_name}")
        src = min(hits, key=lambda n: (n.replace("\\", "/").count("/"), len(n)))
        with z.open(src) as f, open(exe_dst, "wb") as o:
            shutil.copyfileobj(f, o)


def ensure_binaries(
    ver_sb: str, ver_xr: str, force: bool = False, bin_dir: Path | None = None
) -> tuple[Path, Path]:
    target_bin_dir = bin_dir or app_bin_dir()
    sb_exe = target_bin_dir / "sing-box.exe"
    xr_exe = target_bin_dir / "xray.exe"
    manifest = target_bin_dir / "current.json"
    want = {"singbox": ver_sb, "xray": ver_xr}
    if not force and sb_exe.exists() and xr_exe.exists() and manifest.exists():
        try:
            if json.loads(manifest.read_text("utf-8")) == want:
                return sb_exe, xr_exe
        except Exception:
            pass

    print(f"Скачиваю движки: sing-box v{ver_sb}, Xray v{ver_xr} ...")
    sb_zip = target_bin_dir / f"sing-box-{ver_sb}-windows-amd64.zip"
    url_sb = _resolve_asset_url(SINGBOX_REPO, f"v{ver_sb}", f"sing-box-{ver_sb}-windows-amd64.zip")
    if not sb_zip.exists():
        download_file(url_sb, sb_zip)
    _extract_binary(sb_exe, sb_zip)

    xr_zip = target_bin_dir / "Xray-windows-64.zip"
    url_xr = _resolve_asset_url(XRAY_REPO, f"v{ver_xr}", "Xray-windows-64.zip")
    if not xr_zip.exists():
        download_file(url_xr, xr_zip)
    _extract_binary(xr_exe, xr_zip)

    manifest.write_text(json.dumps(want), encoding="utf-8")
    return sb_exe, xr_exe


def build_singbox_config(outbound: dict[str, Any], port: int, log_path: str) -> dict[str, Any]:
    ob = dict(outbound)
    ob["tag"] = "probe"
    return {
        "log": {"level": "error", "output": log_path},
        "inbounds": [{"type": "http", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
        "route": {"final": "probe"},
    }


def build_xray_config(outbound: dict[str, Any], port: int, log_path: str) -> dict[str, Any]:
    return {
        "log": {"loglevel": "error", "access": "", "error": log_path},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
        "outbounds": [outbound],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def xray_shorthand_to_v2ray(o: dict[str, Any]) -> dict[str, Any]:
    s = o.get("settings", {})
    ss = o.get("streamSettings", {})
    net = ss.get("network", "tcp")
    sec = ss.get("security") or "none"
    addr = s.get("address") or ""
    port = int(s.get("port") or 0)
    user = {
        "id": s.get("id", ""),
        "encryption": s.get("encryption", "none"),
        "flow": s.get("flow", ""),
    }
    stream: dict[str, Any] = {"network": "tcp" if net == "raw" else net, "security": sec}
    if net == "xhttp":
        xh = dict(ss.get("xhttpSettings") or {})
        xh.setdefault("path", "/")
        stream["xhttpSettings"] = xh
    if sec == "tls":
        ts = dict(ss.get("tlsSettings") or {})
        ts.setdefault("serverName", addr)
        stream["tlsSettings"] = ts
    elif sec == "reality":
        rs = ss.get("realitySettings") or {}
        rs2: dict[str, Any] = {
            "serverName": rs.get("serverName") or addr,
            "fingerprint": rs.get("fingerprint") or "",
            "publicKey": rs.get("password") or "",
            "spiderX": rs.get("spiderX") or "/",
        }
        if sid := rs.get("shortId"):
            rs2["shortId"] = sid
        stream["realitySettings"] = rs2
    return {
        "protocol": "vless",
        "tag": "probe",
        "settings": {"vnext": [{"address": addr, "port": port, "users": [user]}]},
        "streamSettings": stream,
    }


def wait_port(port: int, proc: subprocess.Popen | None, timeout: float = 12.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            pass
        time.sleep(0.2)
    return False
