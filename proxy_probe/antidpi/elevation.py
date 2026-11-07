from __future__ import annotations

import contextlib
import ctypes
import logging
import os
import sys
from ctypes import wintypes
from pathlib import Path

logger = logging.getLogger(__name__)

SEE_MASK_NOCLOSEPROCESS = 0x00000040
INFINITE = 0xFFFFFFFF


class SHELLEXECUTEINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", wintypes.LPVOID),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def is_admin() -> bool:
    """Проверяет, запущен ли текущий процесс с правами Администратора (Windows)."""
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_elevated_and_wait(
    executable: str | Path | None = None,
    params: str | None = None,
    cwd: str | Path | None = None,
    show_window: bool = True,
) -> int:
    """Запускает процесс с повышением привилегий через системный Windows UAC prompt.

    Ожидает завершения повышенного процесса и возвращает его код возврата.
    При отказе пользователя от UAC вызывает PermissionError.
    """
    if os.name != "nt":
        raise OSError("Повышение прав через UAC поддерживается только в Windows.")

    target_exe = str(executable or sys.executable)
    target_params = (
        params
        if params is not None
        else " ".join(f'"{arg}"' if " " in arg else arg for arg in sys.argv[1:])
    )
    target_cwd = str(cwd or Path.cwd())

    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.hwnd = None
    sei.lpVerb = "runas"
    sei.lpFile = target_exe
    sei.lpParameters = target_params
    sei.lpDirectory = target_cwd
    sei.nShow = 1 if show_window else 0

    success = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
    if not success:
        err = ctypes.GetLastError()
        if err == 1223:  # ERROR_CANCELLED (user clicked "No")
            raise PermissionError("Запрос прав Администратора (UAC) был отклонён пользователем.")
        raise ctypes.WinError(err)

    h_process = sei.hProcess
    if not h_process:
        return 0

    try:
        ctypes.windll.kernel32.WaitForSingleObject(h_process, INFINITE)
        exit_code = wintypes.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(h_process, ctypes.byref(exit_code))
        return int(exit_code.value)
    finally:
        ctypes.windll.kernel32.CloseHandle(h_process)


class TeeOutput:
    """Дублирует консольный вывод в файл для передачи между процессами UAC (SSOT)."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self._file = None
        self._orig_stdout = sys.stdout

    def write(self, data: str) -> int:
        self._orig_stdout.write(data)
        if self._file:
            self._file.write(data)
            self._file.flush()
        return len(data)

    def flush(self) -> None:
        self._orig_stdout.flush()
        if self._file:
            self._file.flush()

    def __enter__(self) -> TeeOutput:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.log_path, "w", encoding="utf-8", errors="replace")
        sys.stdout = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        sys.stdout = self._orig_stdout
        if self._file:
            with contextlib.suppress(Exception):
                self._file.close()
        self._file = None
