from __future__ import annotations

from proxy_probe.models import Server
from proxy_probe.orchestrator import dedupe_servers, gather_sources


def test_dedupe_servers_preserves_fresh() -> None:
    s1 = Server(
        group_id=1,
        group_name="Group1",
        name="server1",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"type": "vless", "server": "1.2.3.4", "server_port": 443, "uuid": "abc", "tag": "old_tag"},
        source="db",
    )
    s2 = Server(
        group_id=1,
        group_name="Group1",
        name="server1-fresh",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"type": "vless", "server": "1.2.3.4", "server_port": 443, "uuid": "abc", "tag": "new_tag"},
        source="fresh",
    )
    deduped = dedupe_servers([s1, s2])
    assert len(deduped) == 1
    assert deduped[0].source == "fresh"
    assert deduped[0].name == "server1-fresh"


def test_dedupe_servers_alpn_order() -> None:
    # Проверка, что разный порядок в списках примитивов (alpn) нормализуется и дедуплицируется
    s1 = Server(
        group_id=1,
        group_name="Group1",
        name="s1",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"type": "vless", "server": "1.2.3.4", "server_port": 443, "tls": {"alpn": ["h2", "http/1.1"]}},
        source="fresh",
    )
    s2 = Server(
        group_id=1,
        group_name="Group1",
        name="s2",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj={"type": "vless", "server": "1.2.3.4", "server_port": 443, "tls": {"alpn": ["http/1.1", "h2"]}},
        source="fresh",
    )
    deduped = dedupe_servers([s1, s2])
    assert len(deduped) == 1


def test_canonical_structure_mixed_types() -> None:
    from proxy_probe.orchestrator import _canonical_structure

    # Смешанный список разных примитивных типов не должен падать с TypeError
    mixed = [1, "b", 2, "a", True]
    canonical = _canonical_structure(mixed)
    assert len(canonical) == 5
    assert set(canonical) == {1, "b", 2, "a"}


def test_gather_sources_with_prefetched(monkeypatch) -> None:
    # Интеграционный тест: проверяет сквозную цепочку gather_sources -> parse_subscription -> parse_vless
    monkeypatch.setattr("proxy_probe.orchestrator.read_profiles_for_group", lambda gid, gname="": [])
    groups = [{"id": 10, "name": "Test Group", "url": "http://example.com/sub"}]
    # Simple vless link payload
    link = "vless://00000000-0000-0000-0000-000000000000@1.1.1.1:443?security=none#Server1"
    prefetched = {"http://example.com/sub": link.encode("utf-8")}

    servers, warnings = gather_sources(groups, selected={10}, no_fetch=False, prefetched=prefetched)
    assert len(servers) == 1
    assert servers[0].server == "1.1.1.1"
    assert servers[0].server_port == 443
    assert servers[0].source == "fresh"
    assert len(warnings) == 0


def test_gather_sources_merges_db_and_online(monkeypatch) -> None:
    db_s1 = Server(
        group_id=1,
        group_name="G1",
        name="DB-Only",
        engine="sing-box",
        server="1.1.1.1",
        server_port=443,
        import_obj={"type": "vless", "server": "1.1.1.1", "server_port": 443, "uuid": "u1", "tag": "DB-Only"},
        source="db",
    )
    db_s2 = Server(
        group_id=1,
        group_name="G1",
        name="Common-Old",
        engine="sing-box",
        server="2.2.2.2",
        server_port=443,
        import_obj={"type": "vless", "server": "2.2.2.2", "server_port": 443, "uuid": "u2", "tag": "Common-Old"},
        source="db",
    )

    monkeypatch.setattr("proxy_probe.orchestrator.read_profiles_for_group", lambda gid, gname: [db_s1, db_s2])

    groups = [{"id": 1, "name": "G1", "url": "http://sub.test"}]
    # Subscription contains common server 2.2.2.2 and new server 3.3.3.3
    sub_links = (
        "vless://u2@2.2.2.2:443?security=none#Common-Fresh\n"
        "vless://u3@3.3.3.3:443?security=none#Online-Only\n"
    )
    prefetched = {"http://sub.test": sub_links.encode("utf-8")}

    servers, warnings = gather_sources(groups, selected={1}, no_fetch=False, prefetched=prefetched)

    assert len(servers) == 3
    by_ip = {s.server: s for s in servers}

    assert "1.1.1.1" in by_ip
    assert by_ip["1.1.1.1"].source == "db"
    assert by_ip["1.1.1.1"].name == "DB-Only"

    assert "2.2.2.2" in by_ip
    assert by_ip["2.2.2.2"].source == "fresh"
    assert by_ip["2.2.2.2"].name == "Common-Fresh"

    assert "3.3.3.3" in by_ip
    assert by_ip["3.3.3.3"].source == "fresh"
    assert by_ip["3.3.3.3"].name == "Online-Only"
    assert len(warnings) == 0


def test_gather_sources_filters_insecure(monkeypatch) -> None:
    monkeypatch.setattr("proxy_probe.orchestrator.read_profiles_for_group", lambda gid, gname: [])

    groups = [{"id": 1, "name": "G1", "url": "http://sub.test", "remove_insecure": True}]
    # Link 1: insecure (plain security=none)
    # Link 2: secure (tls with verified SNI)
    sub_links = (
        "vless://u1@1.1.1.1:443?security=none#Insecure-Plain\n"
        "vless://u2@2.2.2.2:443?security=tls&sni=example.com#Secure-TLS\n"
    )
    prefetched = {"http://sub.test": sub_links.encode("utf-8")}

    # 1. By default, group remove_insecure=True -> insecure filtered
    servers, warnings = gather_sources(groups, selected={1}, no_fetch=False, prefetched=prefetched)
    assert len(servers) == 1
    assert servers[0].server == "2.2.2.2"
    assert any("Отфильтровано 1 небезопасных" in w for w in warnings)

    # 2. Override allow_insecure (filter_insecure=False) -> all kept
    servers, warnings = gather_sources(
        groups, selected={1}, no_fetch=False, prefetched=prefetched, filter_insecure=False
    )
    assert len(servers) == 2
    assert not any("Отфильтровано" in w for w in warnings)

    # 3. Group remove_insecure=False, but CLI filter_insecure=True -> filtered
    groups[0]["remove_insecure"] = False
    servers, warnings = gather_sources(
        groups, selected={1}, no_fetch=False, prefetched=prefetched, filter_insecure=True
    )
    assert len(servers) == 1
    assert servers[0].server == "2.2.2.2"
    assert any("Отфильтровано 1 небезопасных" in w for w in warnings)
