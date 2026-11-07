from __future__ import annotations

import dataclasses


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
    is_golden: bool
    recipe_sha256: str = ""
    init_script: str | None = None

    @property
    def short_tag(self) -> str:
        """Короткий бейдж стратегии для имени прокси, например 'zapret:S01'."""
        return f"zapret:S{self.number:02d}"


@dataclasses.dataclass(frozen=True)
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


@dataclasses.dataclass
class AntidpiBenchmarkResult:
    """Сводный локальный рейтинг стратегий для текущего провайдера (SSOT)."""

    tested_at: str
    isp: str
    best_strategy_number: int | None
    ratings: list[StrategyRating] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tested_at": self.tested_at,
            "isp": self.isp,
            "best_strategy_number": self.best_strategy_number,
            "ratings": [dataclasses.asdict(r) for r in self.ratings],
        }

    @classmethod
    def from_dict(cls, data: dict) -> AntidpiBenchmarkResult:
        ratings = [
            StrategyRating(
                strategy_number=int(r["strategy_number"]),
                strategy_name=str(r["strategy_name"]),
                family_name=str(r["family_name"]),
                rescued_count=int(r["rescued_count"]),
                total_tested=int(r["total_tested"]),
                success_rate=float(r["success_rate"]),
                avg_latency_ms=int(r["avg_latency_ms"]),
                score=int(r["score"]),
            )
            for r in data.get("ratings", [])
        ]
        return cls(
            tested_at=str(data.get("tested_at", "")),
            isp=str(data.get("isp", "")),
            best_strategy_number=data.get("best_strategy_number"),
            ratings=ratings,
        )
