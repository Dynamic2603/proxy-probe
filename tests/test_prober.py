from __future__ import annotations

import proxy_probe.prober as prober
from proxy_probe.models import RESULT_BLOCK, RESULT_DEAD, RESULT_OK, RESULT_UNKNOWN


def test_classify_agy_ok() -> None:
    assert prober.classify_agy("OK", 0) == RESULT_OK
    assert prober.classify_agy("Here is the answer: OK", 0) == RESULT_OK


def test_classify_agy_block() -> None:
    assert prober.classify_agy("User location is not supported", 0) == RESULT_BLOCK
    assert prober.classify_agy("Error: user location is not supported.", 1) == RESULT_BLOCK


def test_classify_agy_unknown_patterns() -> None:
    assert prober.classify_agy("429 Too Many Requests: RESOURCE_EXHAUSTED", 0) == RESULT_UNKNOWN
    assert prober.classify_agy("401 Unauthorized: token expired", 0) == RESULT_UNKNOWN
    assert prober.classify_agy("permission denied", 0) == RESULT_UNKNOWN


def test_classify_agy_dead_patterns() -> None:
    assert prober.classify_agy("dial tcp 1.2.3.4:443: i/o timeout", 0) == RESULT_DEAD
    assert prober.classify_agy("connection refused", 0) == RESULT_DEAD
    assert prober.classify_agy("tls: handshake failure", 0) == RESULT_DEAD


def test_classify_agy_return_codes() -> None:
    # -1 means probe timeout
    assert prober.classify_agy("", -1) == RESULT_DEAD
    # -2 means launch error
    assert prober.classify_agy("failed to exec", -2) == RESULT_DEAD
    # Generic non-zero with unclassified message -> UNKNOWN
    assert prober.classify_agy("unexpected output", 1) == RESULT_UNKNOWN
    # Empty string with rc 0 -> UNKNOWN
    assert prober.classify_agy("   ", 0) == RESULT_UNKNOWN


def test_get_default_agy_bin() -> None:
    b = prober.get_default_agy_bin()
    assert isinstance(b, str) and len(b) > 0
