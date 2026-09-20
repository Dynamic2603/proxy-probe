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


def test_gather_sources_with_prefetched() -> None:
    # Интеграционный тест: проверяет сквозную цепочку gather_sources -> parse_subscription -> parse_vless
    groups = [
        {"id": 10, "name": "Test Group", "url": "http://example.com/sub"}
    ]
    # Simple vless link payload
    link = "vless://00000000-0000-0000-0000-000000000000@1.1.1.1:443?security=none#Server1"
    prefetched = {"http://example.com/sub": link.encode("utf-8")}

    servers, warnings = gather_sources(groups, selected={10}, no_fetch=False, prefetched=prefetched)
    assert len(servers) == 1
    assert servers[0].server == "1.1.1.1"
    assert servers[0].server_port == 443
    assert servers[0].source == "fresh"
    assert len(warnings) == 0
