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


def test_parse_shadowsocks_formats() -> None:
    # 1. Base64 с паддингом
    link_b64 = "ss://YWVzLTEyOC1nY206cGFzczEyMw==@1.2.3.4:8388#SS-Padded"
    eng, obj = link_to_outbound(link_b64)
    assert eng == "sing-box"
    assert obj["type"] == "shadowsocks"
    assert obj["method"] == "aes-128-gcm"
    assert obj["password"] == "pass123"
    assert obj["server"] == "1.2.3.4"
    assert obj["server_port"] == 8388

    # 2. Base64 без паддинга
    link_unpadded = "ss://YWVzLTEyOC1nY206cGFzczEyMw@1.2.3.4:8388#SS-Unpadded"
    eng, obj = link_to_outbound(link_unpadded)
    assert eng == "sing-box"
    assert obj["method"] == "aes-128-gcm"
    assert obj["password"] == "pass123"

    # 4. Legacy format: ss://BASE64(method:password@host:port)#tag
    link_legacy = "ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#SS-Legacy"
    eng, obj = link_to_outbound(link_legacy)
    assert eng == "sing-box"
    assert obj["type"] == "shadowsocks"
    assert obj["method"] == "bf-cfb"
    assert obj["password"] == "test"
    assert obj["server"] == "192.168.100.1"
    assert obj["server_port"] == 8888


def test_link_to_outbound_vless_flow_normalization() -> None:
    link = "vless://uuid-1@1.2.3.4:443?security=reality&flow=xtls-rprx-vision-udp443#NormFlow"
    eng, obj = link_to_outbound(link)
    assert eng == "sing-box"
    assert obj["flow"] == "xtls-rprx-vision"


def test_decode_body_urlsafe_base64() -> None:
    import base64

    text = "vless://test@1.2.3.4:443?security=reality#Tag1\nvless://test2@5.6.7.8:443#Tag2\n" * 3
    # Use urlsafe base64 with - and _
    b64_urlsafe = base64.urlsafe_b64encode(text.encode("utf-8"))
    decoded = decode_body(b64_urlsafe)
    assert "vless://test@1.2.3.4:443" in decoded


def test_extract_host_port_wireguard() -> None:
    wg_obj = {
        "type": "wireguard",
        "peers": [{"address": "10.0.0.1", "port": 51820, "public_key": "xyz"}],
    }
    host, port = extract_host_port(wg_obj)
    assert host == "10.0.0.1"
    assert port == 51820
