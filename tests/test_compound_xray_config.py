from __future__ import annotations

import json
import sqlite3
from typing import Any

from proxy_probe.engines import xray_shorthand_to_v2ray
from proxy_probe.parsers import (
    extract_host_port,
    extract_proxy_outbounds_from_config,
    parse_outbound_doc,
    parse_subscription,
)
from proxy_probe.throne import read_profiles_for_group, set_throne_dir


def test_extract_host_port_vnext() -> None:
    obj = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": "node1.example.org",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001"}],
                }
            ]
        },
    }
    srv, prt = extract_host_port(obj)
    assert srv == "node1.example.org"
    assert prt == 443


def test_extract_host_port_servers() -> None:
    obj = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": "ss.example.org",
                    "port": 8388,
                    "password": "test-password",
                }
            ]
        },
    }
    srv, prt = extract_host_port(obj)
    assert srv == "ss.example.org"
    assert prt == 8388


def test_extract_proxy_outbounds_filters_auxiliary() -> None:
    cfg = {
        "outbounds": [
            {
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": "192.0.2.1", "port": 443}]},
            },
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
            {"protocol": "dns", "tag": "dns-out"},
        ]
    }
    proxies = extract_proxy_outbounds_from_config(cfg)
    assert len(proxies) == 1
    assert proxies[0]["protocol"] == "vless"
    assert proxies[0]["tag"] == "proxy"


def test_parse_outbound_doc_full_config() -> None:
    full_cfg = {
        "remarks": "Synthetic Node Alpha",
        "outbounds": [
            {
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": "node1.example.org", "port": 443}]},
            },
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
    }
    doc = json.dumps(full_cfg)
    pairs = parse_outbound_doc(doc)
    assert len(pairs) == 1
    eng, ob = pairs[0]
    assert eng == "xray"
    assert ob["tag"] == "Synthetic Node Alpha"
    assert ob["settings"]["vnext"][0]["address"] == "node1.example.org"


def test_parse_subscription_array_with_balancer_and_standalone() -> None:
    # Имитирует структуру комплексной подписки:
    # 0: Балансировщик (виртуальный контейнер со списком outbounds)
    # 1: Одиночный узел 1
    # 2: Одиночный узел 2
    sub_data = [
        {
            "remarks": "Auto Selector",
            "routing": {"balancers": [{"tag": "balancer", "selector": ["proxy-"]}]},
            "outbounds": [
                {
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {"vnext": [{"address": "node1.example.org", "port": 443}]},
                },
                {
                    "protocol": "vless",
                    "tag": "proxy-2",
                    "settings": {"vnext": [{"address": "node2.example.org", "port": 443}]},
                },
                {"protocol": "freedom", "tag": "direct"},
            ],
        },
        {
            "remarks": "Node Alpha",
            "outbounds": [
                {
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {"vnext": [{"address": "node1.example.org", "port": 443}]},
                },
                {"protocol": "freedom", "tag": "direct"},
            ],
        },
        {
            "remarks": "Node Beta",
            "outbounds": [
                {
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {"vnext": [{"address": "node2.example.org", "port": 443}]},
                },
                {"protocol": "freedom", "tag": "direct"},
            ],
        },
    ]
    raw = json.dumps(sub_data).encode("utf-8")
    pairs = parse_subscription(raw)
    assert len(pairs) == 2
    assert pairs[0][1]["tag"] == "Node Alpha"
    assert pairs[1][1]["tag"] == "Node Beta"


def test_xray_shorthand_to_v2ray_preserves_vnext() -> None:
    native_vless = {
        "protocol": "vless",
        "tag": "custom-tag",
        "settings": {
            "vnext": [
                {
                    "address": "node1.example.org",
                    "port": 443,
                    "users": [{"id": "00000000-0000-0000-0000-000000000001", "flow": "xtls-rprx-vision"}],
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": "node1.example.org",
                "publicKey": "synthetic-public-key",
            },
        },
    }
    converted = xray_shorthand_to_v2ray(native_vless)
    assert converted["tag"] == "probe"
    assert converted["protocol"] == "vless"
    assert converted["settings"]["vnext"][0]["address"] == "node1.example.org"
    assert converted["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert converted["streamSettings"]["realitySettings"]["publicKey"] == "synthetic-public-key"


def test_read_profiles_for_group_custom_wrapper(tmp_path: Any) -> None:
    db_file = tmp_path / "config" / "throne.db"
    db_file.parent.mkdir(parents=True)
    con = sqlite3.connect(db_file)
    con.execute(
        """
        CREATE TABLE groups (
            id INTEGER PRIMARY KEY,
            name TEXT,
            url TEXT,
            archive INTEGER,
            sub_options_json TEXT,
            profiles_json TEXT
        )
        """
    )
    con.execute(
        """
        CREATE TABLE profiles (
            id INTEGER PRIMARY KEY,
            gid INTEGER,
            type TEXT,
            name TEXT,
            outbound_json TEXT
        )
        """
    )
    balancer_cfg = {
        "remarks": "Auto Selector",
        "burstObservatory": {},
        "routing": {"balancers": [{"tag": "b"}]},
        "outbounds": [
            {"protocol": "vless", "settings": {"vnext": [{"address": "node1.example.org", "port": 443}]}},
            {"protocol": "vless", "settings": {"vnext": [{"address": "node2.example.org", "port": 443}]}},
            {"protocol": "freedom", "tag": "direct"},
        ],
    }
    balancer_wrapper = {
        "name": "Auto Selector",
        "type": "custom",
        "subtype": "xrayfullconfig",
        "config": json.dumps(balancer_cfg),
    }

    node_cfg = {
        "remarks": "Node Alpha",
        "outbounds": [
            {
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": "node1.example.org", "port": 443}]},
            },
            {"protocol": "freedom", "tag": "direct"},
        ],
    }
    node_wrapper = {
        "name": "Node Alpha",
        "type": "custom",
        "subtype": "xrayfullconfig",
        "config": json.dumps(node_cfg),
    }

    con.execute("INSERT INTO groups VALUES (1, 'Test Group', 'https://example.org/sub', 0, NULL, '[100, 101]')")
    con.execute(
        "INSERT INTO profiles VALUES (100, 1, 'custom', 'Auto Selector', ?)",
        (json.dumps(balancer_wrapper),),
    )
    con.execute(
        "INSERT INTO profiles VALUES (101, 1, 'custom', 'Node Alpha', ?)",
        (json.dumps(node_wrapper),),
    )
    con.commit()
    con.close()

    set_throne_dir(tmp_path)
    try:
        servers = read_profiles_for_group(1, "Test Group")
        assert len(servers) == 1
        s = servers[0]
        assert s.name == "Node Alpha"
        assert s.engine == "xray"
        assert s.server == "node1.example.org"
        assert s.server_port == 443
    finally:
        set_throne_dir(None)
