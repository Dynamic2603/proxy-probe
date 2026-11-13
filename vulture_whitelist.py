"""Белый список для статического анализатора Vulture (технические слепые зоны)."""

from proxy_probe.antidpi.elevation import SHELLEXECUTEINFO
from proxy_probe.antidpi.models import StrategyProfile, StrategyRating
from proxy_probe.models import EngineType, ExportRank
from tests.conftest import _isolate_relay_state

# Поля C-структуры WinAPI SHELLEXECUTEINFO (используются через ctypes.byref в ShellExecuteExW)
_ = (
    SHELLEXECUTEINFO.cbSize,
    SHELLEXECUTEINFO.fMask,
    SHELLEXECUTEINFO.hwnd,
    SHELLEXECUTEINFO.lpVerb,
    SHELLEXECUTEINFO.lpFile,
    SHELLEXECUTEINFO.lpParameters,
    SHELLEXECUTEINFO.lpDirectory,
    SHELLEXECUTEINFO.nShow,
    SHELLEXECUTEINFO.hInstApp,
    SHELLEXECUTEINFO.lpIDList,
    SHELLEXECUTEINFO.lpClass,
    SHELLEXECUTEINFO.hkeyClass,
    SHELLEXECUTEINFO.dwHotKey,
    SHELLEXECUTEINFO.hIconOrMonitor,
    SHELLEXECUTEINFO.hProcess,
)

# Поля датаклассов, сериализуемые/десериализуемые через asdict/astuple/JSON reflection
_fields = (
    StrategyRating.history_runs,
    StrategyRating.last_tested,
    StrategyRating.last_success,
    StrategyProfile.variant,  # type: ignore[misc]
    StrategyProfile.chain,  # type: ignore[misc]
    StrategyProfile.recipe_sha256,
    ExportRank.neg_index,  # type: ignore[misc]
)

_enums = (
    EngineType.SINGBOX,
    EngineType.XRAY,
)

# Pytest autouse-фикстуры вызываются рантаймом pytest неявно
_fixtures = (_isolate_relay_state,)
