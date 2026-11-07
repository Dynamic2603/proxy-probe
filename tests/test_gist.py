from __future__ import annotations

import email.message
import io
import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from proxy_probe.gist import (
    GistSyncResult,
    get_github_token,
    mask_gist_id,
    resolve_gist_id,
    sync_file_to_gist,
)
from proxy_probe.models import RESULT_OK, Server
from proxy_probe.ui import console, print_summary_panel


def test_resolve_gist_id(monkeypatch) -> None:
    # 1. CLI arg takes highest precedence
    monkeypatch.setenv("PROXY_PROBE_GIST_ID", "env_id_1")
    monkeypatch.setenv("GIST_ID", "env_id_2")
    assert resolve_gist_id("cli_id") == "cli_id"
    assert resolve_gist_id("  cli_id_trimmed  ") == "cli_id_trimmed"

    # 2. PROXY_PROBE_GIST_ID takes precedence over GIST_ID
    assert resolve_gist_id(None) == "env_id_1"
    assert resolve_gist_id("") == "env_id_1"

    # 3. Fallback to GIST_ID
    monkeypatch.delenv("PROXY_PROBE_GIST_ID")
    assert resolve_gist_id(None) == "env_id_2"

    # 4. Neither set
    monkeypatch.delenv("GIST_ID")
    assert resolve_gist_id(None) is None
    assert resolve_gist_id("   ") is None


def test_mask_gist_id() -> None:
    assert mask_gist_id("ae7c898aae560906ba5ec3a0357fe53f") == "ae7c...e53f"
    assert mask_gist_id("  ae7c898aae560906ba5ec3a0357fe53f  ") == "ae7c...e53f"
    assert mask_gist_id("123456789") == "1234...6789"
    assert mask_gist_id("12345678") == "***"
    assert mask_gist_id("12345") == "***"
    assert mask_gist_id("") == ""
    assert mask_gist_id(None) == ""


def test_get_github_token_from_env(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "token_gh")
    monkeypatch.setenv("GH_TOKEN", "token_gh_alt")
    assert get_github_token() == "token_gh"

    monkeypatch.delenv("GITHUB_TOKEN")
    assert get_github_token() == "token_gh_alt"


def test_get_github_token_from_gh_cli(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    with patch("shutil.which", return_value="C:\\path\\gh.exe"):
        mock_proc = MagicMock(returncode=0, stdout="gho_cli_token_123\n")
        with patch("subprocess.run", return_value=mock_proc):
            assert get_github_token() == "gho_cli_token_123"

        mock_failed_proc = MagicMock(returncode=1, stdout="")
        with patch("subprocess.run", return_value=mock_failed_proc):
            assert get_github_token() is None


def test_sync_file_to_gist_success(tmp_path: Path) -> None:
    test_file = tmp_path / "proxy-ok.txt"
    test_file.write_text("vless://test-node-1\nvless://test-node-2\n", encoding="utf-8")

    fake_response_data = {
        "id": "gist_abc_123",
        "owner": {"login": "testuser"},
        "files": {"proxy-ok.txt": {"filename": "proxy-ok.txt"}},
    }
    fake_body = json.dumps(fake_response_data).encode("utf-8")

    mock_resp = MagicMock()
    mock_resp.read.return_value = fake_body
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res = sync_file_to_gist(
            file_path=test_file,
            gist_id="gist_abc_123",
            token="gho_test_token",
        )

        assert res.success is True
        assert res.gist_id == "gist_abc_123"
        assert res.raw_url == "https://gist.githubusercontent.com/testuser/gist_abc_123/raw/proxy-ok.txt"
        assert res.error_message == ""

        # Verify request details
        req = mock_urlopen.call_args[0][0]
        assert req.get_method() == "PATCH"
        assert req.full_url == "https://api.github.com/gists/gist_abc_123"
        assert req.headers["Authorization"] == "Bearer gho_test_token"
        assert req.headers["Accept"] == "application/vnd.github+json"

        sent_payload = json.loads(req.data.decode("utf-8"))
        assert sent_payload["files"]["proxy-ok.txt"]["content"] == "vless://test-node-1\nvless://test-node-2\n"


def test_sync_file_to_gist_missing_file(tmp_path: Path) -> None:
    non_existent = tmp_path / "missing.txt"
    res = sync_file_to_gist(non_existent, "gist123", token="token")
    assert res.success is False
    assert "Файл не найден" in res.error_message


def test_sync_file_to_gist_no_token(tmp_path: Path, monkeypatch) -> None:
    test_file = tmp_path / "proxy-ok.txt"
    test_file.write_text("vless://node\n", encoding="utf-8")

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with patch("proxy_probe.gist.get_github_token", return_value=None):
        res = sync_file_to_gist(test_file, "gist123")
        assert res.success is False
        assert "GitHub токен не найден" in res.error_message


def test_sync_file_to_gist_http_error(tmp_path: Path) -> None:
    test_file = tmp_path / "proxy-ok.txt"
    test_file.write_text("vless://node\n", encoding="utf-8")

    http_err = urllib.error.HTTPError(
        url="https://api.github.com/gists/gist123",
        code=404,
        msg="Not Found",
        hdrs=email.message.Message(),
        fp=io.BytesIO(b'{"message": "Not Found"}'),
    )

    with patch("urllib.request.urlopen", side_effect=http_err):
        res = sync_file_to_gist(test_file, "gist123", token="dummy_token")
        assert res.success is False
        assert "HTTP 404" in res.error_message
        assert "Not Found" in res.error_message


def test_ui_summary_panel_renders_gist(tmp_path: Path) -> None:
    s = Server(1, "Group 1", "S1", "sing-box", "1.1.1.1", 443, {}, "fresh", 1, result=RESULT_OK, latency_ms=50)

    # 1. Success GistSyncResult
    success_res = GistSyncResult(
        success=True,
        gist_id="gist123",
        raw_url="https://gist.githubusercontent.com/user/gist123/raw/proxy-ok.txt",
    )
    with patch.object(console, "print") as mock_print:
        print_summary_panel(
            servers=[s],
            cached_counts={},
            report_path=tmp_path / "report.md",
            import_path=tmp_path / "proxy-ok.txt",
            nb=1,
            nx=0,
            elapsed_s=1.0,
            gist_res=success_res,
        )
        rendered = str(mock_print.call_args[0][0].renderable)
        assert "GitHub Gist:" in rendered
        assert "https://gist.githubusercontent.com/user/gist123/raw/proxy-ok.txt" in rendered
        assert "(обновлён)" in rendered

    # 2. Failed GistSyncResult
    fail_res = GistSyncResult(
        success=False,
        gist_id="gist123",
        error_message="HTTP 401: Bad credentials",
    )
    with patch.object(console, "print") as mock_print:
        print_summary_panel(
            servers=[s],
            cached_counts={},
            report_path=tmp_path / "report.md",
            import_path=tmp_path / "proxy-ok.txt",
            nb=1,
            nx=0,
            elapsed_s=1.0,
            gist_res=fail_res,
        )
        rendered = str(mock_print.call_args[0][0].renderable)
        assert "GitHub Gist:" in rendered
        assert "Не удалось обновить" in rendered
        assert "HTTP 401" in rendered
