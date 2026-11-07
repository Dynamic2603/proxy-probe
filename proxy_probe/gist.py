from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://gist.githubusercontent.com"


@dataclass(frozen=True, slots=True)
class GistSyncResult:
    success: bool
    gist_id: str
    raw_url: str = ""
    error_message: str = ""


def resolve_gist_id(cli_arg: str | None = None) -> str | None:
    """Определяет ID гиста из переданного CLI-аргумента или переменных окружения."""
    if cli_arg and cli_arg.strip():
        return cli_arg.strip()
    for var in ("PROXY_PROBE_GIST_ID", "GIST_ID"):
        val = os.environ.get(var)
        if val and val.strip():
            return val.strip()
    return None


def mask_gist_id(gist_id: str | None) -> str:
    """Маскирует ID гиста для безопасного вывода в логах и консоли (SSOT)."""
    if not gist_id:
        return ""
    clean = gist_id.strip()
    if len(clean) <= 8:
        return "***"
    return f"{clean[:4]}...{clean[-4:]}"


def get_github_token() -> str | None:
    """Извлекает GitHub токен из ENV или через утилиту gh (gh auth token)."""
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        tok = os.environ.get(var)
        if tok and tok.strip():
            return tok.strip()

    if shutil.which("gh"):
        try:
            res = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    return None


def sync_file_to_gist(
    file_path: Path | str,
    gist_id: str,
    token: str | None = None,
    filename: str | None = None,
    description: str | None = None,
    timeout: float = 15.0,
) -> GistSyncResult:
    """Отправляет содержимое файла в существующий Secret Gist через GitHub API (PATCH)."""
    path = Path(file_path)
    clean_id = gist_id.strip()
    if not path.is_file():
        return GistSyncResult(
            success=False,
            gist_id=clean_id,
            error_message=f"Файл не найден: {path}",
        )

    auth_token = (token or get_github_token() or "").strip()
    if not auth_token:
        return GistSyncResult(
            success=False,
            gist_id=clean_id,
            error_message="GitHub токен не найден (задайте GITHUB_TOKEN или авторизуйтесь через 'gh auth login')",
        )

    target_filename = filename or path.name
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        return GistSyncResult(
            success=False,
            gist_id=clean_id,
            error_message=f"Ошибка чтения файла: {e}",
        )

    payload: dict[str, Any] = {
        "files": {
            target_filename: {"content": content}
        }
    }
    if description:
        payload["description"] = description

    url = f"{GITHUB_API_BASE}/gists/{clean_id}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {auth_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "proxy-probe",
            "Content-Type": "application/json",
        },
        method="PATCH",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            owner = data.get("owner", {}).get("login", "")
            if not owner:
                owner = "gist"
            raw_url = f"{GITHUB_RAW_BASE}/{owner}/{clean_id}/raw/{target_filename}"
            return GistSyncResult(success=True, gist_id=clean_id, raw_url=raw_url)
    except urllib.error.HTTPError as e:
        body = (e.read() or b"").decode("utf-8", "replace")
        return GistSyncResult(
            success=False,
            gist_id=clean_id,
            error_message=f"HTTP {e.code}: {body[:150].strip()}",
        )
    except Exception as e:
        return GistSyncResult(
            success=False,
            gist_id=clean_id,
            error_message=str(e),
        )
