from __future__ import annotations

from pathlib import Path

import pytest

from proxy_probe.engines import (
    alloc_port,
    build_singbox_config,
    build_xray_config,
    xray_shorthand_to_v2ray,
)


def test_alloc_port() -> None:
    p1 = alloc_port()
    p2 = alloc_port()
    assert p2 > p1


def test_build_singbox_config() -> None:
    ob = {"type": "vless", "server": "1.1.1.1", "server_port": 443}
    cfg = build_singbox_config(ob, 20050, "engine.log")
    assert cfg["inbounds"][0]["listen_port"] == 20050
    assert cfg["outbounds"][0]["tag"] == "probe"
    assert cfg["route"]["final"] == "probe"


def test_build_xray_config() -> None:
    ob = {"protocol": "vless", "settings": {}}
    cfg = build_xray_config(ob, 20060, "engine.log")
    assert cfg["inbounds"][0]["port"] == 20060
    assert cfg["outbounds"][0]["protocol"] == "vless"


def test_xray_shorthand_to_v2ray() -> None:
    short = {
        "settings": {"address": "1.2.3.4", "port": 443, "id": "uuid-xyz"},
        "streamSettings": {"network": "tcp", "security": "reality"},
    }
    v2 = xray_shorthand_to_v2ray(short)
    assert v2["protocol"] == "vless"
    assert v2["settings"]["vnext"][0]["address"] == "1.2.3.4"
    assert v2["settings"]["vnext"][0]["users"][0]["id"] == "uuid-xyz"


def test_app_bin_dir(tmp_path: Path) -> None:
    from proxy_probe.engines import app_bin_dir

    custom = tmp_path / "custom_bin"
    b = app_bin_dir(custom_dir=custom)
    assert b.is_dir()
    assert b == custom


def test_extract_binary_least_nested(tmp_path: Path) -> None:
    import zipfile

    from proxy_probe.engines import _extract_binary

    zip_file = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_file, "w") as z:
        z.writestr("deep/nested/folder/sing-box.exe", b"nested")
        z.writestr("sing-box-v1/sing-box.exe", b"root_exe")

    dst = tmp_path / "sing-box.exe"
    _extract_binary(dst, zip_file)
    assert dst.read_bytes() == b"root_exe"


def test_verify_file_hash(tmp_path: Path) -> None:
    from proxy_probe.engines import compute_file_sha256, verify_file_hash

    test_file = tmp_path / "hello.txt"
    test_file.write_bytes(b"hello world")
    expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert compute_file_sha256(test_file) == expected
    assert verify_file_hash(test_file, expected)
    assert verify_file_hash(test_file, expected.upper())
    assert not verify_file_hash(test_file, "wrong_hash")


def test_extract_sha256_from_text() -> None:
    from proxy_probe.engines import extract_sha256_from_text

    h = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    # DGST format
    assert extract_sha256_from_text(f"MD5= 123\nSHA2-256= {h}\nSHA1= abc") == h
    # checksums.txt format with asset name
    assert extract_sha256_from_text(f"{h}  *my-file.zip", "my-file.zip") == h
    # Plain hash
    assert extract_sha256_from_text(h) == h
    # No hash
    assert extract_sha256_from_text("no valid hash here") is None


def test_verify_file_against_upstream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from proxy_probe.engines import verify_file_against_upstream

    test_file = tmp_path / "app.zip"
    test_file.write_bytes(b"hello world")
    good_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    # 1. Upstream has no checksum -> passes gracefully
    monkeypatch.setattr("proxy_probe.engines.fetch_upstream_sha256", lambda *args: None)
    assert verify_file_against_upstream(test_file, "repo", "tag", "app.zip") is True

    # 2. Upstream hash matches -> passes
    monkeypatch.setattr("proxy_probe.engines.fetch_upstream_sha256", lambda *args: good_hash)
    assert verify_file_against_upstream(test_file, "repo", "tag", "app.zip") is True

    # 3. Upstream hash differs -> raises SystemExit
    monkeypatch.setattr("proxy_probe.engines.fetch_upstream_sha256", lambda *args: "0" * 64)
    with pytest.raises(SystemExit):
        verify_file_against_upstream(test_file, "repo", "tag", "app.zip")


def test_extract_sha256_from_text_multiple_hashes() -> None:
    from proxy_probe.engines import extract_sha256_from_text

    h1 = "a" * 64
    h2 = "b" * 64
    text = f"{h1}  sing-box-linux-amd64.tar.gz\n{h2}  sing-box-windows-amd64.zip\n"

    # Should return h2 for windows-amd64.zip and not h1
    assert extract_sha256_from_text(text, "sing-box-windows-amd64.zip") == h2
    # Without asset name, since there are multiple hashes, it must return None
    assert extract_sha256_from_text(text) is None


def test_download_and_verify_archive_cleanup_on_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from proxy_probe.engines import _download_and_verify_archive

    dest = tmp_path / "app.zip"
    monkeypatch.setattr(
        "proxy_probe.engines.download_file",
        lambda url, tmp, timeout=120.0: tmp.write_bytes(b"corrupted content"),
    )

    def mock_verify(path, repo, tag, name):
        raise SystemExit("Checksum mismatch")

    monkeypatch.setattr("proxy_probe.engines.verify_file_against_upstream", mock_verify)

    with pytest.raises(SystemExit):
        _download_and_verify_archive("http://fake.url", dest, "repo", "tag", "app.zip")

    assert not dest.exists()
    assert not dest.with_suffix(".zip.part").exists()




