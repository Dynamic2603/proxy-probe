from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from pathlib import Path

from ..engines import project_root
from .models import StrategyProfile

logger = logging.getLogger(__name__)

DEFAULT_CATALOGUE_URL = (
    "https://raw.githubusercontent.com/igareck/anti-dpi-for-russia/main/linux/data/catalogue.json"
)
DEFAULT_CATALOGUE_FILENAME = "antidpi_catalogue.json"


def default_catalogue_path() -> Path:
    """Возвращает путь к локальному каталогу стратегий (SSOT)."""
    return project_root() / "data" / DEFAULT_CATALOGUE_FILENAME


def parse_catalogue_data(data: dict) -> list[StrategyProfile]:
    """Парсит сырой JSON каталога в список канонических StrategyProfile (SSOT)."""
    family_rows = data.get("FamilyRows", [])
    families_by_id: dict[int, dict] = {int(f["Number"]): f for f in family_rows if "Number" in f}

    profile_rows = data.get("ProfileRows", [])
    profiles: list[StrategyProfile] = []

    for row in profile_rows:
        num = int(row.get("Number", 0))
        fam_id = int(row.get("Family", 0))
        fam_info = families_by_id.get(fam_id, {})
        fam_name = str(fam_info.get("Name", f"Family {fam_id}"))
        is_golden = fam_name.strip().lower().startswith("golden") if fam_info else (1 <= fam_id <= 5)

        raw_args = row.get("Args", [])
        args = tuple(str(a) for a in raw_args) if isinstance(raw_args, list) else ()

        p = StrategyProfile(
            number=num,
            family_number=fam_id,
            family_name=fam_name,
            variant=int(row.get("Variant", 1)),
            name=str(row.get("Name", f"Strategy {num}")),
            chain=str(row.get("Chain", "")),
            args=args,
            is_golden=is_golden,
            recipe_sha256=str(row.get("RecipeSHA256", "")),
            init_script=row.get("Init"),
        )
        profiles.append(p)

    return profiles


def load_catalogue(path: Path | None = None) -> list[StrategyProfile]:
    """Загружает локальный каталог стратегий из файла."""
    cat_path = path or default_catalogue_path()
    if not cat_path.is_file():
        raise FileNotFoundError(f"Каталог Anti-DPI стратегий не найден: {cat_path}")

    raw = json.loads(cat_path.read_text(encoding="utf-8"))
    return parse_catalogue_data(raw)


def fetch_catalogue(
    path: Path | None = None,
    url: str = DEFAULT_CATALOGUE_URL,
    timeout: float = 10.0,
) -> list[StrategyProfile]:
    """Обновляет каталог с удаленного upstream-репозитория и сохраняет локально."""
    cat_path = path or default_catalogue_path()
    cat_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "proxy-probe/antidpi-sync"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8")
        raw = json.loads(content)
        profiles = parse_catalogue_data(raw)
        if len(profiles) < 50:
            raise ValueError(f"Подозрительно мало стратегий в каталоге: {len(profiles)}")

        # Атомарная запись через .tmp
        tmp_path = cat_path.with_suffix(".tmp")
        tmp_path.write_text(content, encoding="utf-8")
        tmp_path.replace(cat_path)
        logger.info("Каталог Anti-DPI стратегий успешно обновлен: %d профилей", len(profiles))
        return profiles
    except Exception as exc:
        logger.warning("Сбой онлайн-обновления каталога (%s), пробуем локальный кэш", exc)
        if cat_path.is_file():
            return load_catalogue(cat_path)
        raise


def get_golden_strategies(path: Path | None = None) -> list[StrategyProfile]:
    """Возвращает список Golden-стратегий (топ-45 наиболее эффективных для обхода ТСПУ)."""
    return [p for p in load_catalogue(path) if p.is_golden]


def get_strategy_by_number(number: int, path: Path | None = None) -> StrategyProfile | None:
    """Находит стратегию по её порядковому номеру (1..484)."""
    for p in load_catalogue(path):
        if p.number == number:
            return p
    return None
