from __future__ import annotations

from pathlib import Path

from proxy_probe.antidpi.benchmark import load_ratings, save_ratings
from proxy_probe.antidpi.isp import IspIdentity
from proxy_probe.antidpi.models import (
    AntidpiBenchmarkResult,
    AntidpiDatabase,
    StrategyRating,
)


def make_rating(strat_num: int, score: int, rescued: int = 5, total: int = 10) -> StrategyRating:
    return StrategyRating(
        strategy_number=strat_num,
        strategy_name=f"Strategy {strat_num}",
        family_name="multisplit",
        rescued_count=rescued,
        total_tested=total,
        success_rate=rescued / total,
        avg_latency_ms=100,
        score=score,
        status="TOP" if score >= 80 else "ACTIVE",
    )


def test_antidpi_database_isolation(tmp_path: Path) -> None:
    db_file = tmp_path / "antidpi_ratings.json"

    home_isp = IspIdentity(asn=12389, isp_name="Rostelecom", org_name="Rostelecom", ingress_ip="1.1.1.1")
    work_isp = IspIdentity(asn=8359, isp_name="MTS", org_name="MTS", ingress_ip="2.2.2.2")

    # 1. Сохраняем калибровку для Home (лидер S33)
    home_res = AntidpiBenchmarkResult(
        tested_at="2026-11-07T10:00:00",
        isp=home_isp.display_name,
        asn=home_isp.asn,
        isp_key=home_isp.key,
        best_strategy_number=33,
        ratings=[make_rating(33, score=90)],
    )
    save_ratings(home_res, path=db_file, isp_identity=home_isp)

    # 2. Сохраняем калибровку для Work (лидер S479)
    work_res = AntidpiBenchmarkResult(
        tested_at="2026-11-07T12:00:00",
        isp=work_isp.display_name,
        asn=work_isp.asn,
        isp_key=work_isp.key,
        best_strategy_number=479,
        ratings=[make_rating(479, score=85)],
    )
    save_ratings(work_res, path=db_file, isp_identity=work_isp)

    # 3. Загружаем и проверяем изоляцию
    loaded_home = load_ratings(path=db_file, isp_identity=home_isp)
    assert loaded_home is not None
    assert loaded_home.isp_key == home_isp.key
    assert loaded_home.best_strategy_number == 33
    assert len(loaded_home.ratings) == 1
    assert loaded_home.ratings[0].strategy_number == 33
    assert loaded_home.ratings[0].score == 90

    loaded_work = load_ratings(path=db_file, isp_identity=work_isp)
    assert loaded_work is not None
    assert loaded_work.isp_key == work_isp.key
    assert loaded_work.best_strategy_number == 479
    assert len(loaded_work.ratings) == 1
    assert loaded_work.ratings[0].strategy_number == 479
    assert loaded_work.ratings[0].score == 85

    # 4. Штрафуем стратегию на Work (0 спасенных серверов)
    loaded_work.record_live_feedback(strategy_number=479, rescued=0, total=10)
    save_ratings(loaded_work, path=db_file, isp_identity=work_isp)

    # 5. Проверяем, что Home остался абсолютно нетронутым!
    reloaded_home = load_ratings(path=db_file, isp_identity=home_isp)
    assert reloaded_home is not None
    assert reloaded_home.best_strategy_number == 33
    assert reloaded_home.ratings[0].score == 90
    assert reloaded_home.ratings[0].consecutive_failures == 0

    # А Work получил штраф
    reloaded_work = load_ratings(path=db_file, isp_identity=work_isp)
    assert reloaded_work is not None
    assert reloaded_work.ratings[0].score == 60  # 85 - 25
    assert reloaded_work.ratings[0].consecutive_failures == 1


def test_antidpi_database_migration_v1_to_v2(tmp_path: Path) -> None:
    db_file = tmp_path / "antidpi_ratings.json"

    # Создаем файл v1 схемы (старый однопровайдерный формат с верхнеуровневым ratings)
    v1_content = """{
      "tested_at": "2026-11-07T16:05:56.851704",
      "isp": "AutoDetected",
      "best_strategy_number": 174,
      "ratings": [
        {
          "strategy_number": 174,
          "strategy_name": "S174",
          "family_name": "fake",
          "rescued_count": 6,
          "total_tested": 100,
          "success_rate": 0.06,
          "avg_latency_ms": 1124,
          "score": 4,
          "status": "ACTIVE",
          "consecutive_failures": 0,
          "history_runs": 5,
          "last_tested": "2026-11-07T16:05:56.851704",
          "last_success": "2026-11-07T16:05:56.851704"
        }
      ]
    }"""
    db_file.write_text(v1_content, encoding="utf-8")

    current_isp = IspIdentity(
        asn=210558,
        isp_name="1337 Services GmbH",
        org_name="1337 Services GmbH",
        ingress_ip="45.80.158.20",
    )

    # Читаем через load_ratings
    res = load_ratings(path=db_file, isp_identity=current_isp)
    assert res is not None
    assert res.best_strategy_number == 174
    assert res.isp_key == current_isp.key
    assert len(res.ratings) == 1
    assert res.ratings[0].strategy_number == 174

    # Сохраняем обратно и проверяем, что на диске сформировалась валидная схема v2
    save_ratings(res, path=db_file, isp_identity=current_isp)

    raw_db = AntidpiDatabase.from_dict(__import__("json").loads(db_file.read_text(encoding="utf-8")))
    assert raw_db.schema_version == 2
    assert current_isp.key in raw_db.providers
    assert raw_db.providers[current_isp.key].best_strategy_number == 174
