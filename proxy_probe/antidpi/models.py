from __future__ import annotations

import dataclasses
import datetime as _dt


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
        cleaned = self.family_name
        for prefix in ("Golden / ", "Silver / ", "Golden /", "Silver /"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix) :].strip()
        return cleaned or self.family_name

    @property
    def short_tag(self) -> str:
        """Короткий бейдж стратегии для имени прокси, например 'zapret:S01'."""
        return f"zapret:S{self.number:02d}"


@dataclasses.dataclass(frozen=True)
class CalibrationLevelConfig:
    """Декларативная конфигурация калибровочного уровня (SSOT)."""

    level: int
    title: str
    cmd_file: str
    server_limit: int  # 15 для экспресс-теста, 0 (все живые) для широкого
    strategy_mode: str  # "diversity", "top_living", "all"
    timeout: float
    next_cmd_file: str | None


CALIBRATION_LEVELS: dict[int, CalibrationLevelConfig] = {
    2: CalibrationLevelConfig(
        level=2,
        title="Уровень 2: Экспресс-калибровка разнообразия механик",
        cmd_file="calibrate_level2.cmd",
        server_limit=15,
        strategy_mode="diversity",
        timeout=1.8,
        next_cmd_file="calibrate_level3.cmd",
    ),
    3: CalibrationLevelConfig(
        level=3,
        title="Уровень 3: Расширенная калибровка на пуле живых серверов",
        cmd_file="calibrate_level3.cmd",
        server_limit=100,
        strategy_mode="top_living",
        timeout=2.5,
        next_cmd_file="calibrate_level4.cmd",
    ),
    4: CalibrationLevelConfig(
        level=4,
        title="Уровень 4: Глубокий перебор всех 484 стратегий каталога",
        cmd_file="calibrate_level4.cmd",
        server_limit=15,
        strategy_mode="all",
        timeout=1.8,
        next_cmd_file=None,
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
        cleaned = self.family_name
        for prefix in ("Golden / ", "Silver / ", "Golden /", "Silver /"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix) :].strip()
        return cleaned or self.family_name

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
    """Сводный локальный живой рейтинг стратегий для текущего провайдера (SSOT)."""

    tested_at: str
    isp: str
    best_strategy_number: int | None
    ratings: list[StrategyRating] = dataclasses.field(default_factory=list)

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
        )
