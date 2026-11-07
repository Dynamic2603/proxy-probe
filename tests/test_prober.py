from __future__ import annotations

import proxy_probe.prober as prober
from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, RESULT_UNKNOWN


def test_classify_agy_ok() -> None:
    assert prober.classify_agy("OK", 0) == RESULT_OK
    assert prober.classify_agy("Here is the answer: OK", 0) == RESULT_OK


def test_classify_agy_block() -> None:
    assert prober.classify_agy("User location is not supported", 0) == RESULT_BLOCK
    assert prober.classify_agy("Error: user location is not supported.", 1) == RESULT_BLOCK


def test_classify_agy_block_precedence() -> None:
    # BLOCK побеждает DEAD (например dial tcp i/o timeout)
    assert prober.classify_agy("User location is not supported (dial tcp i/o timeout)", 0) == RESULT_BLOCK
    # BLOCK побеждает UNKNOWN (например 429 rate limit или rc != 0)
    assert prober.classify_agy("429 Too Many Requests: User location is not supported", 1) == RESULT_BLOCK


def test_classify_agy_unknown_patterns() -> None:
    assert prober.classify_agy("429 Too Many Requests: RESOURCE_EXHAUSTED", 0) == RESULT_UNKNOWN
    assert prober.classify_agy("401 Unauthorized: token expired", 0) == RESULT_UNKNOWN
    assert prober.classify_agy("permission denied", 0) == RESULT_UNKNOWN


def test_classify_agy_dead_patterns() -> None:
    assert prober.classify_agy("dial tcp 1.2.3.4:443: i/o timeout", 0) == RESULT_DEAD
    assert prober.classify_agy("connection refused", 0) == RESULT_DEAD
    assert prober.classify_agy("tls: handshake failure", 0) == RESULT_DEAD
    assert prober.classify_agy("stream read: unexpected EOF", 0) == RESULT_DEAD


def test_classify_agy_order_and_word_boundaries() -> None:
    # 429 (API rate limit) with connection refused -> UNKNOWN (proxy works, target API reached)
    assert prober.classify_agy("429 Too Many Requests (connection refused upstream)", 0) == RESULT_UNKNOWN
    # "thereof" does NOT match "EOF" as a dead marker
    assert prober.classify_agy("The summary thereof is OK", 0) == RESULT_OK


def test_classify_agy_return_codes() -> None:
    # -1 means probe timeout — classify_agy returns DEAD,
    # but run_probe overrides to UNKNOWN when preflight passed
    assert prober.classify_agy("", -1) == RESULT_DEAD
    # -2 means launch error
    assert prober.classify_agy("failed to exec", -2) == RESULT_DEAD
    # Generic non-zero with unclassified message -> UNKNOWN
    assert prober.classify_agy("unexpected output", 1) == RESULT_UNKNOWN
    # Empty string with rc 0 -> UNKNOWN
    assert prober.classify_agy("   ", 0) == RESULT_UNKNOWN


def test_get_default_agy_bin() -> None:
    prober.get_default_agy_bin.cache_clear()
    b1 = prober.get_default_agy_bin()
    assert isinstance(b1, str) and len(b1) > 0
    b2 = prober.get_default_agy_bin()
    assert b1 == b2
    prober.get_default_agy_bin.cache_clear()


def test_preflight_check_import() -> None:
    """Ensure preflight_check is importable and callable."""
    assert callable(prober.preflight_check)


def test_process_registry_basic() -> None:
    import subprocess
    import sys

    reg = prober.ProcessRegistry()
    assert reg.count == 0

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        reg.register(proc)
        assert reg.count == 1
        reg.unregister(proc)
        assert reg.count == 0
    finally:
        proc.kill()
        proc.wait(timeout=2)


def test_process_registry_kill_all() -> None:
    import subprocess
    import sys

    reg = prober.ProcessRegistry()
    p1 = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    p2 = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    reg.register(p1)
    reg.register(p2)
    assert reg.count == 2

    reg.kill_all()
    assert reg.count == 0

    p1.wait(timeout=2)
    p2.wait(timeout=2)
    assert p1.poll() is not None
    assert p2.poll() is not None


def test_agy_probe_with_stop_event() -> None:
    import threading

    stop_event = threading.Event()
    stop_event.set()

    out, rc = prober.agy_probe(12345, "agy", "5s", 10.0, stop_event=stop_event)
    assert rc == -1
    assert out == ""


def test_run_probe_with_stop_event(tmp_path: prober.Path) -> None:
    import threading

    stop_event = threading.Event()
    stop_event.set()

    res = prober.run_probe(
        "dummy_engine",
        False,
        {"type": "direct"},
        21999,
        tmp_path,
        {"start": 5.0, "probe": 5.0},
        stop_event=stop_event,
    )
    assert res["result"] == RESULT_DEAD
    assert res["latency_ms"] == 0
    assert "проверка отменена" in res["note"]
