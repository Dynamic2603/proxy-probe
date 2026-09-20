from __future__ import annotations

from proxy_probe.parsers import (
    decode_body,
    extract_host_port,
    extract_tag,
    link_to_outbound,
    split_blocks,
)


def test_extract_host_port() -> None:
    obj1 = {"server": "example.com", "server_port": 443}
    assert extract_host_port(obj1) == ("example.com", 443)

    obj2 = {"settings": {"address": "1.2.3.4", "port": 8080}}
    assert extract_host_port(obj2) == ("1.2.3.4", 8080)


def test_extract_tag() -> None:
    obj = {"tag": "test-server"}
    assert extract_tag(obj) == "test-server"


def test_link_to_outbound_vless() -> None:
    link = "vless://uuid-123@example.com:443?security=reality&pbk=key123#MyServer"
    eng, obj = link_to_outbound(link)
    assert eng == "sing-box"
    assert obj["server"] == "example.com"
    assert obj["server_port"] == 443
    assert obj["uuid"] == "uuid-123"
    assert obj["tag"] == "MyServer"
    assert obj["tls"]["reality"]["public_key"] == "key123"


def test_link_to_outbound_hysteria2() -> None:
    link = "hy2://pass123@example.com:8443?sni=sni.com#HyServer"
    eng, obj = link_to_outbound(link)
    assert eng == "sing-box"
    assert obj["type"] == "hysteria2"
    assert obj["server"] == "example.com"
    assert obj["server_port"] == 8443
    assert obj["password"] == "pass123"
    assert obj["tls"]["server_name"] == "sni.com"


def test_split_blocks() -> None:
    text = "vless://a@b:443#s1\n# comment\nvless://c@d:443#s2\n"
    blocks = split_blocks(text)
    assert len(blocks) == 2
    assert "vless://a@b:443#s1" in blocks[0]
    assert "vless://c@d:443#s2" in blocks[1]


def test_decode_body() -> None:
    raw = b"vless://test@host:443#tag\n"
    assert "vless://test@host:443#tag" in decode_body(raw)


def test_link_to_outbound_vmess() -> None:
    import base64
    import json

    payload = {
        "v": "2",
        "ps": "VMessServer",
        "add": "1.2.3.4",
        "port": "443",
        "id": "uuid-vmess",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/ws",
        "tls": "tls",
        "sni": "sni.example.com",
    }
    b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    link = f"vmess://{b64}"
    eng, obj = link_to_outbound(link)
    assert eng == "sing-box"
    assert obj["type"] == "vmess"
    assert obj["server"] == "1.2.3.4"
    assert obj["server_port"] == 443
    assert obj["uuid"] == "uuid-vmess"
    assert obj["tls"]["enabled"] is True
    assert obj["tls"]["server_name"] == "sni.example.com"
    assert obj["transport"]["type"] == "ws"
    assert obj["transport"]["path"] == "/ws"
    assert obj["transport"]["headers"]["Host"] == "cdn.example.com"

