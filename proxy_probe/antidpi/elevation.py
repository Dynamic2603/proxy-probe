from __future__ import annotations

import contextlib
import ctypes
import logging
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import IO, TextIO, cast

logger = logging.getLogger(__name__)

SEE_MASK_NOCLOSEPROCESS = 0x00000040
INFINITE = 0xFFFFFFFF
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
STD_INPUT_HANDLE = -10
ENABLE_QUICK_EDIT_MODE = 0x0040
ENABLE_EXTENDED_FLAGS = 0x0080


def disable_quick_edit_mode() -> None:
    """Отключает QuickEdit Mode в консоли Windows, предотвращая зависание вывода при клике мышью."""
    if os.name != "nt":
        return
    with contextlib.suppress(Exception):
        kernel32 = ctypes.windll.kernel32
        h_stdin = kernel32.GetStdHandle(STD_INPUT_HANDLE)
        if not h_stdin or h_stdin == -1:
            return
        mode = wintypes.DWORD()
        if kernel32.GetConsoleMode(h_stdin, ctypes.byref(mode)):
            new_mode = (mode.value & ~ENABLE_QUICK_EDIT_MODE) | ENABLE_EXTENDED_FLAGS
            kernel32.SetConsoleMode(h_stdin, new_mode)


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


def is_process_alive(pid: int) -> bool:
    """Проверяет, активен ли процесс с указанным PID (работает в т.ч. для повышенных процессов)."""
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        return bool(ok) and int(exit_code.value) == STILL_ACTIVE
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def run_elevated_detached(
    executable: str | Path | None = None,
    params: str | None = None,
    cwd: str | Path | None = None,
    show_window: bool = False,
) -> int:
    """Запускает процесс с повышением привилегий через UAC в фоновом режиме без ожидания завершения.

    Возвращает PID запущенного процесса.
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
        if err == 1223:
            raise PermissionError("Запрос прав Администратора (UAC) был отклонён пользователем.")
        raise ctypes.WinError(err)

    h_process = sei.hProcess
    if not h_process:
        return 0

    try:
        pid = int(ctypes.windll.kernel32.GetProcessId(h_process))
        return pid
    finally:
        ctypes.windll.kernel32.CloseHandle(h_process)


class TeeOutput:
    """Дублирует консольный вывод в файл для передачи между процессами UAC (SSOT)."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self._file: IO[str] | None = None
        self._orig_stdout: TextIO = sys.stdout

    def write(self, data: str) -> int:
        self._orig_stdout.write(data)
        if self._file is not None:
            self._file.write(data)
            self._file.flush()
        return len(data)

    def flush(self) -> None:
        self._orig_stdout.flush()
        if self._file is not None:
            self._file.flush()

    def __enter__(self) -> TeeOutput:
        disable_quick_edit_mode()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.log_path, "w", encoding="utf-8", errors="replace")
        sys.stdout = cast(TextIO, self)
        return self

    def __exit__(self, _exc_type: object, _exc_val: object, _exc_tb: object) -> None:
        sys.stdout = self._orig_stdout
        if self._file is not None:
            with contextlib.suppress(Exception):
                self._file.close()
        self._file = None
