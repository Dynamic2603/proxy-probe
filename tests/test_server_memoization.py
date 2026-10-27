from __future__ import annotations

from proxy_probe.models import Server


def _make_server() -> Server:
    obj = {
        "type": "vless",
        "server": "1.2.3.4",
        "server_port": 443,
        "uuid": "test-uuid-123",
        "tls": {
            "enabled": True,
            "server_name": "example.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
        },
    }
    return Server(
        group_id=1,
        group_name="grp",
        name="test-server",
        engine="sing-box",
        server="1.2.3.4",
        server_port=443,
        import_obj=obj,
        source="db",
    )


def test_server_properties_memoization() -> None:
    s = _make_server()

    # Свойства изначально не вычислены
    assert s._config_identity is None
    assert s._sni is None
    assert s._fingerprint is None
    assert s._cache_key is None
    assert s._is_tcp_protocol is None

    # Первое обращение
    cid1 = s.config_identity
    sni1 = s.sni
    fp1 = s.fingerprint
    ck1 = s.cache_key
    tcp1 = s.is_tcp_protocol

    # Поля теперь мемоизированы
    assert s._config_identity == cid1
    assert s._sni == sni1 == "example.com"
    assert s._fingerprint == fp1 == "chrome"
    assert s._cache_key == ck1
    assert s._is_tcp_protocol is True

    # Повторное обращение возвращает идентичные значения
    assert s.config_identity is cid1
    assert s.sni is sni1
    assert s.fingerprint is fp1
    assert s.cache_key is ck1
    assert s.is_tcp_protocol is tcp1


def test_server_dataclass_fields_clean() -> None:
    s = _make_server()
    # Приватные поля не должны влиять на repr или сравнение
    s2 = _make_server()
    _ = s.config_identity
    # s вычислен, s2 нет — равенство должно сохраняться
    assert s == s2

    # Проверка, что repr не захламлен приватными полями
    r = repr(s)
    assert "_config_identity" not in r
    assert "_cache_key" not in r
