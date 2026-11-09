from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .isp import IspIdentity

_MARKETING_PREFIXES = ("Golden / ", "Silver / ", "Golden /", "Silver /")


def clean_family_name(raw_name: str) -> str:
    """Очищает название семейства от внешних маркетинговых префиксов ('Golden /', 'Silver /')."""
    cleaned = raw_name
    for prefix in _MARKETING_PREFIXES:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :].strip()
    return cleaned or raw_name


@dataclasses.dataclass(frozen=True)
class StrategyProfile:
    """Каноническое описание Anti-DPI стратегии (SSOT)."""

    number: int
    family_number: int
    family_name: str
    variant: int
    name: str
    chain: str
    args: tuple[str, ...]
    recipe_sha256: str = ""
    init_script: str | None = None

    @property
    def technical_family(self) -> str:
        """Очищенное от внешних ярлыков ('Golden /', 'Silver /') название механики десинхронизации."""
        return clean_family_name(self.family_name)

    @property
    def short_tag(self) -> str:
        """Короткий бейдж стратегии для имени прокси, например 'zapret:S01'."""
        return f"zapret:S{self.number:02d}"


@dataclasses.dataclass(frozen=True)
class CalibrationLevelConfig:
    """Декларативная конфигурация калибровочного уровня (SSOT)."""

    level: int
    title: str
    server_limit: int  # 15 для экспресс-теста, 100 для широкого
    strategy_mode: str  # "diversity", "top_living", "all"
    timeout: float
    next_level: int | None


CALIBRATION_LEVELS: dict[int, CalibrationLevelConfig] = {
    2: CalibrationLevelConfig(
        level=2,
        title="Уровень 2: Экспресс-калибровка разнообразия механик",
        server_limit=15,
        strategy_mode="diversity",
        timeout=1.8,
        next_level=3,
    ),
    3: CalibrationLevelConfig(
        level=3,
        title="Уровень 3: Расширенная калибровка на пуле живых серверов",
        server_limit=100,
        strategy_mode="top_living",
        timeout=2.5,
        next_level=4,
    ),
    4: CalibrationLevelConfig(
        level=4,
        title="Уровень 4: Глубокий перебор всех 484 стратегий каталога",
        server_limit=15,
        strategy_mode="all",
        timeout=1.8,
        next_level=None,
    ),
}


@dataclasses.dataclass
class StrategyRating:
    """Результат тестирования стратегии на выборке упавших узлов (SSOT)."""

    strategy_number: int
    strategy_name: str
    family_name: str
    rescued_count: int
    total_tested: int
    success_rate: float
    avg_latency_ms: int
    score: int
    status: str = "UNTESTED"  # "TOP", "ACTIVE", "DEGRADED", "DEAD", "UNTESTED"
    consecutive_failures: int = 0
    history_runs: int = 1
    last_tested: str = ""
    last_success: str = ""

    @property
    def technical_family(self) -> str:
        """Очищенное название механики десинхронизации."""
        return clean_family_name(self.family_name)

    @property
    def status_badge(self) -> str:
        """Индикатор надежности стратегии в консоли."""
        if self.score >= 80:
            return "[⭐TOP]"
        if self.score > 0 and self.consecutive_failures == 0:
            return "[✓ACTIVE]"
        if self.consecutive_failures > 0 and self.score > 0:
            return f"[⚠️DEG:{self.consecutive_failures}]"
        return "[DEAD]"


@dataclasses.dataclass
class AntidpiBenchmarkResult:
    """Сводный локальный живой рейтинг стратегий для конкретного провайдера (SSOT)."""

    tested_at: str
    isp: str
    best_strategy_number: int | None
    ratings: list[StrategyRating] = dataclasses.field(default_factory=list)
    asn: int = 0
    isp_key: str = ""

    def sort_ratings(self) -> None:
        """Сортирует стратегии по объективному скору и определяет лучшую."""
        self.ratings.sort(
            key=lambda r: (
                -r.score,
                -r.rescued_count,
                r.avg_latency_ms if r.avg_latency_ms > 0 else 99999,
            )
        )
        self.best_strategy_number = (
            self.ratings[0].strategy_number
            if self.ratings and self.ratings[0].score > 0
            else None
        )

    def record_live_feedback(self, strategy_number: int, rescued: int, total: int) -> None:
        """Фиксирует факт успеха или сбоя стратегии на Stage 2 основного сбора (run.cmd)."""
        now_iso = _dt.datetime.now().isoformat()
        for r in self.ratings:
            if r.strategy_number == strategy_number:
                r.history_runs += 1
                r.last_tested = now_iso
                if rescued > 0:
                    r.consecutive_failures = 0
                    r.last_success = now_iso
                    r.status = "TOP" if r.score >= 80 else "ACTIVE"
                else:
                    r.consecutive_failures += 1
                    r.score = max(0, r.score - 25)
                    r.status = "DEAD" if r.score == 0 else "DEGRADED"
                break
        self.sort_ratings()

    def merge_benchmark_results(self, new_ratings: list[StrategyRating]) -> None:
        """Объединяет результаты нового бенчмарка с накопленным живым рейтингом."""
        now_iso = _dt.datetime.now().isoformat()
        existing_by_num = {r.strategy_number: r for r in self.ratings}

        for nr in new_ratings:
            if nr.strategy_number in existing_by_num:
                old = existing_by_num[nr.strategy_number]
                old.strategy_name = nr.strategy_name
                old.family_name = nr.family_name
                old.rescued_count = nr.rescued_count
                old.total_tested = nr.total_tested
                old.success_rate = nr.success_rate
                old.avg_latency_ms = nr.avg_latency_ms
                old.score = nr.score
                old.history_runs += 1
                old.last_tested = now_iso
                if nr.rescued_count > 0:
                    old.consecutive_failures = 0
                    old.last_success = now_iso
                    old.status = "TOP" if nr.score >= 80 else "ACTIVE"
                else:
                    old.consecutive_failures += 1
                    old.status = "DEAD" if old.score == 0 else "DEGRADED"
            else:
                nr.last_tested = now_iso
                if nr.rescued_count > 0:
                    nr.last_success = now_iso
                    nr.status = "TOP" if nr.score >= 80 else "ACTIVE"
                else:
                    nr.status = "DEAD"
                self.ratings.append(nr)

        self.tested_at = now_iso
        self.sort_ratings()

    def to_dict(self) -> dict:
        return {
            "tested_at": self.tested_at,
            "isp": self.isp,
            "asn": self.asn,
            "isp_key": self.isp_key,
            "best_strategy_number": self.best_strategy_number,
            "ratings": [dataclasses.asdict(r) for r in self.ratings],
        }

    @classmethod
    def from_dict(cls, data: dict) -> AntidpiBenchmarkResult:
        ratings = [
            StrategyRating(
                strategy_number=int(r["strategy_number"]),
                strategy_name=str(r["strategy_name"]),
                family_name=str(r.get("family_name", "")),
                rescued_count=int(r.get("rescued_count", 0)),
                total_tested=int(r.get("total_tested", 0)),
                success_rate=float(r.get("success_rate", 0.0)),
                avg_latency_ms=int(r.get("avg_latency_ms", 0)),
                score=int(r.get("score", 0)),
                status=str(r.get("status", "UNTESTED")),
                consecutive_failures=int(r.get("consecutive_failures", 0)),
                history_runs=int(r.get("history_runs", 1)),
                last_tested=str(r.get("last_tested", "")),
                last_success=str(r.get("last_success", "")),
            )
            for r in data.get("ratings", [])
        ]
        return cls(
            tested_at=str(data.get("tested_at", "")),
            isp=str(data.get("isp", "")),
            best_strategy_number=data.get("best_strategy_number"),
            ratings=ratings,
            asn=int(data.get("asn", 0)),
            isp_key=str(data.get("isp_key", "")),
        )


@dataclasses.dataclass
class AntidpiDatabase:
    """Многопровайдерное хранилище живых рейтингов Anti-DPI (SSOT)."""

    schema_version: int = 2
    last_detected_isp: str = ""
    providers: dict[str, AntidpiBenchmarkResult] = dataclasses.field(default_factory=dict)

    def get_or_create(self, identity: IspIdentity | str) -> AntidpiBenchmarkResult:
        """Возвращает или создает изолированный профиль для переданного провайдера."""
        key = getattr(identity, "key", str(identity))
        isp_name = getattr(identity, "display_name", str(identity))
        asn = getattr(identity, "asn", 0)

        if key not in self.providers:
            self.providers[key] = AntidpiBenchmarkResult(
                tested_at=_dt.datetime.now().isoformat(),
                isp=isp_name,
                best_strategy_number=None,
                ratings=[],
                asn=asn,
                isp_key=key,
            )
        else:
            prof = self.providers[key]
            if isp_name and (not prof.isp or prof.isp == "AutoDetected"):
                prof.isp = isp_name
            if asn > 0 and not prof.asn:
                prof.asn = asn
            if not prof.isp_key:
                prof.isp_key = key

        self.last_detected_isp = key
        return self.providers[key]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "last_detected_isp": self.last_detected_isp,
            "providers": {k: v.to_dict() for k, v in self.providers.items()},
        }

    @classmethod
    def from_dict(cls, data: dict, current_identity: IspIdentity | None = None) -> AntidpiDatabase:
        # 1. Проверяем схему v2 (многопровайдерная)
        if "providers" in data and isinstance(data["providers"], dict):
            providers = {
                k: AntidpiBenchmarkResult.from_dict(v)
                for k, v in data["providers"].items()
                if isinstance(v, dict)
            }
            for k, p in providers.items():
                if not p.isp_key:
                    p.isp_key = k
            return cls(
                schema_version=int(data.get("schema_version", 2)),
                last_detected_isp=str(data.get("last_detected_isp", "")),
                providers=providers,
            )

        # 2. Обратная совместимость: прозрачная миграция схемы v1
        if "ratings" in data:
            v1_res = AntidpiBenchmarkResult.from_dict(data)
            target_key = (
                current_identity.key
                if current_identity
                else (f"AS{v1_res.asn}_{v1_res.isp}" if v1_res.asn else "migrated_profile")
            )
            v1_res.isp_key = target_key
            if current_identity and (not v1_res.isp or v1_res.isp == "AutoDetected"):
                v1_res.isp = current_identity.display_name
                v1_res.asn = current_identity.asn

            return cls(
                schema_version=2,
                last_detected_isp=target_key,
                providers={target_key: v1_res},
            )

        return cls()
