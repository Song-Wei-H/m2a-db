from __future__ import annotations

import json
import locale
import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from app.port_check import find_listening_pids

SECRET_PATTERN = re.compile(r"(?i)(password|token|api[_-]?key|authorization)(\s*[=:]\s*)([^\s]+)")


def redact(value: str) -> str:
    return SECRET_PATTERN.sub(r"\1\2<已遮罩>", value)


def decode_output(data: bytes) -> str:
    for encoding in ("utf-8", locale.getpreferredencoding(False), "cp950", "cp437"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def configure_console() -> None:
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except (AttributeError, OSError):
            pass


def make_logger(root: Path, debug: bool) -> logging.Logger:
    log_dir = root / "logs"
    log_dir.mkdir(exist_ok=True)
    logger = logging.getLogger("m2a_launcher")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    handler = logging.FileHandler(log_dir / f"launcher-{time.strftime('%Y%m%d')}.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    return logger


def port_open(host: str, port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.4)
        return sock.connect_ex((host, port)) == 0


def http_status(url: str, timeout: float = 2.0) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": "M2A-Launcher/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read()


def is_m2a_backend(url: str) -> bool:
    try:
        status, body = http_status(f"{url}/health")
        return status == 200 and json.loads(body).get("service") == "M2A Backend"
    except (OSError, ValueError, urllib.error.URLError):
        return False


def wait_until(check: Callable[[], bool], timeout: int, interval: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(interval)
    return False


def wsl_distros() -> list[str]:
    completed = subprocess.run(["wsl.exe", "--list", "--quiet"], capture_output=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"wsl.exe 結束代碼：{completed.returncode}\n{decode_output(completed.stderr).strip()}")
    text = completed.stdout.decode("utf-16-le", errors="replace") if completed.stdout.startswith((b"\xff\xfe", b"\x00")) or b"\x00" in completed.stdout else decode_output(completed.stdout)
    return [item.strip().lstrip("\ufeff") for item in text.splitlines() if item.strip()]


class SingleInstance:
    def __init__(self, root: Path):
        self.path = root / ".m2a-launcher.lock"
        self.file = None

    def acquire(self) -> bool:
        self.file = self.path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            return False
        self.file.seek(0)
        self.file.truncate()
        self.file.write(str(os.getpid()).encode("ascii"))
        self.file.flush()
        return True

    def release(self) -> None:
        if not self.file:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self.file.close()
            self.file = None


class ProcessManager:
    def __init__(self, root: Path, logger: logging.Logger):
        self.root = root
        self.logger = logger
        self.processes: list[tuple[str, subprocess.Popen[bytes]]] = []

    def start(self, component: str, command: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.Popen[bytes]:
        safe = redact(subprocess.list2cmdline(command))
        self.logger.info("[%s] 正在啟動；command=%s", component, safe)
        process = subprocess.Popen(command, cwd=cwd or self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.processes.append((component, process))
        self.logger.info("[%s] 已建立 process；PID=%s", component, process.pid)
        threading.Thread(target=self._drain, args=(component, process), daemon=True).start()
        return process

    def _drain(self, component: str, process: subprocess.Popen[bytes]) -> None:
        assert process.stdout is not None
        for raw in iter(process.stdout.readline, b""):
            message = redact(decode_output(raw).rstrip())
            if message:
                self.logger.info("[%s] %s", component, message)
        process.stdout.close()

    def stop_all(self, notify: Callable[[str], None] | None = None) -> None:
        for component, process in reversed(self.processes):
            if process.poll() is not None:
                continue
            self.logger.info("[%s] 正在停止；PID=%s", component, process.pid)
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.logger.warning("[%s] graceful shutdown 逾時；PID=%s", component, process.pid)
            if process.poll() is None:
                self.logger.warning("[%s] process 仍在執行；PID=%s；Launcher 不會終止不明 process", component, process.pid)
            else:
                self.logger.info("[%s] 已停止；exit_code=%s", component, process.returncode)
                if notify:
                    notify(component)


def collision_details(port: int) -> str:
    pids = find_listening_pids(port)
    return ", ".join(str(pid) for pid in pids) if pids else "未知"
