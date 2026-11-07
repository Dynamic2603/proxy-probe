from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from unittest.mock import patch

from proxy_probe.antidpi.catalogue import (
    default_catalogue_path,
    fetch_catalogue,
    get_strategy_by_number,
    load_catalogue,
    parse_catalogue_data,
    select_mechanical_diversity_sample,
)


def test_load_catalogue_real() -> None:
    cat_path = default_catalogue_path()
    assert cat_path.is_file(), f"Файл каталога должен присутствовать: {cat_path}"

    profiles = load_catalogue(cat_path)
    assert len(profiles) == 484

    # Проверка первой стратегии и очистки названия семейства от префиксов Golden/Silver
    s1 = profiles[0]
    assert s1.number == 1
    assert s1.family_number == 1
    assert not s1.family_name.startswith("Golden")
    assert not s1.family_name.startswith("Silver")
    assert s1.technical_family == s1.family_name
    assert s1.short_tag == "zapret:S01"
    assert len(s1.args) > 0
    assert any("multisplit" in a for a in s1.args)


def test_select_mechanical_diversity_sample() -> None:
    profiles = load_catalogue()
    diverse = select_mechanical_diversity_sample(profiles, limit=25)
    assert 15 <= len(diverse) <= 25

    # Проверяем, что в выборке представлены различные технические семейства
    families = {p.technical_family for p in diverse}
    assert len(families) >= 10


def test_get_strategy_by_number() -> None:
    s = get_strategy_by_number(1)
    assert s is not None
    assert s.number == 1

    s_last = get_strategy_by_number(484)
    assert s_last is not None
    assert s_last.number == 484

    assert get_strategy_by_number(999) is None


def test_parse_catalogue_data_custom() -> None:
    sample = {
        "FamilyRows": [
            {"Number": 1, "Name": "Golden / fake + multisplit", "Count": 1, "First": 1, "Last": 1},
            {"Number": 2, "Name": "Silver / tcpseg", "Count": 1, "First": 2, "Last": 2},
        ],
        "ProfileRows": [
            {
                "Number": 1,
                "Family": 1,
                "Variant": 1,
                "Name": "Strat 1",
                "Chain": "fake",
                "Args": ["--payload=tls_client_hello"],
                "RecipeSHA256": "abc",
            },
            {
                "Number": 2,
                "Family": 2,
                "Variant": 1,
                "Name": "Strat 2",
                "Chain": "tcpseg",
                "Args": ["--payload=tls_client_hello", "--split=1"],
                "RecipeSHA256": "def",
            },
        ],
    }
    profiles = parse_catalogue_data(sample)
    assert len(profiles) == 2
    assert profiles[0].technical_family == "fake + multisplit"
    assert profiles[0].short_tag == "zapret:S01"
    assert profiles[1].technical_family == "tcpseg"
    assert profiles[1].short_tag == "zapret:S02"


def test_fetch_catalogue_fallback_on_network_error(tmp_path: Path) -> None:
    local_file = tmp_path / "antidpi_catalogue.json"
    dummy_data = {
        "FamilyRows": [{"Number": 1, "Name": "fake + multisplit"}],
        "ProfileRows": [
            {
                "Number": i,
                "Family": 1,
                "Variant": 1,
                "Name": f"Dummy {i}",
                "Args": ["--dummy"],
            }
            for i in range(1, 60)
        ],
    }
    local_file.write_text(json.dumps(dummy_data), encoding="utf-8")

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("No internet")):
        loaded = fetch_catalogue(path=local_file)
        assert len(loaded) == 59
