from __future__ import annotations

import unittest.mock as mock

from proxy_probe.orchestrator import fetch_subscriptions_batch


def test_fetch_subscriptions_batch_empty() -> None:
    res = fetch_subscriptions_batch([])
    assert res == {}


def test_fetch_subscriptions_batch_success() -> None:
    def fake_fetch(url: str, timeout: float = 25.0) -> bytes | None:
        return f"payload_for_{url}".encode()

    with mock.patch("proxy_probe.orchestrator.fetch_subscription", side_effect=fake_fetch):
        urls = ["https://sub1.com", "https://sub2.com", "https://sub3.com"]
        res = fetch_subscriptions_batch(urls, max_workers=2)
        assert len(res) == 3
        for u in urls:
            assert res[u] == f"payload_for_{u}".encode()


def test_fetch_subscriptions_batch_partial_failure() -> None:
    def fake_fetch(url: str, timeout: float = 25.0) -> bytes | None:
        if "bad" in url:
            return None
        return b"ok"

    with mock.patch("proxy_probe.orchestrator.fetch_subscription", side_effect=fake_fetch):
        urls = ["https://ok1.com", "https://bad.com", "https://ok2.com"]
        res = fetch_subscriptions_batch(urls, max_workers=3)
        assert res["https://ok1.com"] == b"ok"
        assert res["https://bad.com"] is None
        assert res["https://ok2.com"] == b"ok"


def test_fetch_subscriptions_batch_deduplication() -> None:
    call_counts: dict[str, int] = {}

    def fake_fetch(url: str, timeout: float = 25.0) -> bytes | None:
        call_counts[url] = call_counts.get(url, 0) + 1
        return b"deduped"

    with mock.patch("proxy_probe.orchestrator.fetch_subscription", side_effect=fake_fetch):
        urls = ["https://dup.com", "https://dup.com", "https://other.com"]
        res = fetch_subscriptions_batch(urls)
        assert len(res) == 2
        assert call_counts["https://dup.com"] == 1
        assert call_counts["https://other.com"] == 1
