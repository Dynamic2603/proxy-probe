from __future__ import annotations

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


def test_app_bin_dir() -> None:
    from proxy_probe.engines import app_bin_dir, project_root

    b = app_bin_dir()
    assert b.is_dir()
    assert b == project_root() / "bin"

