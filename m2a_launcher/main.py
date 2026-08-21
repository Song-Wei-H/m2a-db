from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
import urllib.error
import webbrowser

from m2a_launcher import __version__
from m2a_launcher.config import LauncherConfig
from m2a_launcher.envfile import read_env_values
from m2a_launcher.menu import configure_llm, configure_worker, show_current_config
from m2a_launcher.runtime import (
    ProcessManager, SingleInstance, collision_details, configure_console, http_status,
    is_m2a_backend, make_logger, port_open, wait_until, wsl_distros,
)


class LauncherError(RuntimeError):
    pass


class UI:
    def __init__(self, debug: bool): self.debug_enabled = debug
    def line(self, tag: str, text: str): print(f"[{tag}] {text}", flush=True)
    def debug(self, text: str):
        if self.debug_enabled: self.line("除錯", text)
    def banner(self, title: str): print(f"\n{'=' * 40}\n{title:^40}\n{'=' * 40}\n", flush=True)


def _technical_info(exc: Exception) -> str:
    details = [f"{type(exc).__name__}: {exc}"]
    cause = exc.__cause__
    while cause is not None:
        details.append(f"{type(cause).__name__}: {cause}")
        cause = cause.__cause__
    return "\n".join(details)


def _run(command: list[str], timeout: int = 15) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, capture_output=True, timeout=timeout, check=False)


def _wait_before_close(input_fn=input) -> None:
    try:
        input_fn("\n按 Enter 關閉視窗...")
    except (EOFError, KeyboardInterrupt):
        pass


def launch_services(config: LauncherConfig, *, pause_on_error: bool = False) -> int:
    ui = UI(config.debug)
    logger = make_logger(config.root, config.debug)
    logger.info("[Launcher] M2A Launcher version=%s；startup_timestamp=%s", __version__, time.strftime("%Y-%m-%d %H:%M:%S"))
    ui.banner("M2A 啟動器")
    ui.line("資訊", "正在載入 M2A 設定...")
    ui.line("成功", "設定載入完成")
    ui.debug(f"Worker Mode: {config.worker_mode}")
    ui.debug(f"WSL Distro: {config.wsl_distro}")
    ui.debug(f"Worker Directory: {config.wsl_worker_dir}")
    ui.debug(f"Health Check: {config.backend_url}/health")

    instance = SingleInstance(config.root)
    if not instance.acquire():
        ui.line("資訊", "M2A 已在執行中，正在開啟既有 M2A 介面...")
        webbrowser.open(config.frontend_url)
        return 0

    manager = ProcessManager(config.root, logger)
    try:
        ui.line("檢查", "Docker Engine...")
        docker = _run(["docker", "version", "--format", "{{.Server.Version}}"])
        if docker.returncode != 0:
            raise LauncherError("Docker Engine 無法使用。\n\n建議：\n請確認 Docker Desktop 已啟動。")
        ui.line("成功", "Docker Engine 正常")

        ui.line("檢查", "PostgreSQL...")
        compose = _run(["docker", "compose", "up", "-d", "postgres"], config.startup_timeout)
        logger.info("[PostgreSQL] docker compose exit_code=%s", compose.returncode)
        if compose.returncode != 0:
            raise LauncherError("PostgreSQL 無法啟動。\n\n技術資訊：\ndocker compose exit code: " + str(compose.returncode))
        ready = wait_until(lambda: _run(["docker", "exec", "m2a-postgres", "pg_isready", "-U", "m2a_user", "-d", "m2a_pentest"], 5).returncode == 0, config.startup_timeout)
        if not ready:
            raise LauncherError(f"PostgreSQL 啟動逾時。\n\n等待時間：{config.startup_timeout} 秒\n\n請查看：\nlogs/launcher-{time.strftime('%Y%m%d')}.log")
        ui.line("成功", "PostgreSQL 已就緒")

        if port_open(config.backend_host, config.backend_port):
            if not is_m2a_backend(config.backend_url):
                raise LauncherError(f"M2A Backend 無法啟動。\n\n原因：\n連接埠 {config.backend_port} 已被其他程式使用。\n\nPID：{collision_details(config.backend_port)}\n\nLauncher 不會自動終止該程式。")
            ui.line("成功", "偵測到既有 M2A Backend，將直接使用")
        else:
            ui.line("啟動", "M2A Backend...")
            python = config.root / ".venv" / "Scripts" / "python.exe"
            if not python.exists(): raise LauncherError("找不到 M2A Python 虛擬環境：.venv\\Scripts\\python.exe")
            env = os.environ.copy(); env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "KALI_WORKER_URL": config.worker_url})
            backend = manager.start("Backend", [str(python), "-m", "uvicorn", "app.main:app", "--host", config.backend_host, "--port", str(config.backend_port)], env=env)
            ui.debug(f"Backend PID: {backend.pid}")
            if not wait_until(lambda: is_m2a_backend(config.backend_url), config.startup_timeout):
                raise LauncherError(f"M2A Backend 啟動逾時。\n\n等待時間：{config.startup_timeout} 秒")
            status, _ = http_status(f"{config.backend_url}/health")
            ui.debug(f"Health Check 回應: HTTP {status}")
            ui.line("成功", f"M2A Backend 已啟動\n       PID: {backend.pid}\n       URL: {config.backend_url}")

        if config.worker_mode == "wsl":
            ui.line("檢查", "WSL Kali...")
            distros = wsl_distros()
            if config.wsl_distro.casefold() not in {item.casefold() for item in distros}:
                raise LauncherError(f"無法啟動 M2A Worker。\n\n原因：\n找不到 WSL 發行版「{config.wsl_distro}」。\n\n建議：\n請確認 Kali Linux 已安裝，並執行：\nwsl.exe --list --quiet")
            worker_command = f"cd {shlex.quote(config.wsl_worker_dir)} && exec ./scripts/start-worker.sh {config.wsl_worker_port}"
            worker = manager.start("WSL", ["wsl.exe", "-d", config.wsl_distro, "--", "bash", "-lc", worker_command])
            ui.line("成功", "Kali Linux 已啟動")

        ui.line("檢查", "M2A Worker Health Check...")
        def worker_ready() -> bool:
            try: return http_status(f"{config.worker_url}/health")[0] == 200
            except (OSError, urllib.error.URLError): return False
        if not wait_until(worker_ready, config.worker_timeout):
            raise LauncherError(f"M2A Worker Health Check 失敗。\n\n等待時間：{config.worker_timeout} 秒\n\nURL：{config.worker_url}/health")
        ui.line("成功", "Worker Health Check 通過")

        ui.line("啟動", "M2A Dispatcher...")
        python = config.root / ".venv" / "Scripts" / "python.exe"
        env = os.environ.copy(); env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "KALI_WORKER_URL": config.worker_url})
        dispatcher = manager.start("Dispatcher", [str(python), "-m", "worker.task_poller"], env=env)
        time.sleep(1)
        if dispatcher.poll() is not None: raise LauncherError(f"M2A Dispatcher 啟動失敗。\n\n技術資訊：\nexit code: {dispatcher.returncode}")
        ui.line("成功", f"Dispatcher 已啟動\n       PID: {dispatcher.pid}")

        if port_open(config.backend_host, config.frontend_port):
            raise LauncherError(f"M2A Frontend 無法啟動。\n\n原因：\n連接埠 {config.frontend_port} 已被其他程式使用。\n\nPID：{collision_details(config.frontend_port)}\n\nLauncher 不會自動終止該程式。")
        ui.line("啟動", "M2A Frontend...")
        env["VITE_M2A_PROXY_TARGET"] = config.backend_url
        frontend = manager.start("Frontend", ["pnpm.cmd", "exec", "vite", "--host", config.backend_host, "--port", str(config.frontend_port)], env=env, cwd=config.root / "frontend")
        if not wait_until(lambda: port_open(config.backend_host, config.frontend_port), config.startup_timeout):
            raise LauncherError(f"M2A Frontend 啟動逾時。\n\n等待時間：{config.startup_timeout} 秒")
        ui.line("成功", f"M2A Frontend 已啟動\n       PID: {frontend.pid}\n       URL: {config.frontend_url}")

        ui.banner("M2A 已就緒")
        print(f"正在開啟：\n{config.frontend_url}\n", flush=True)
        if config.auto_open_browser: webbrowser.open(config.frontend_url)
        while True: time.sleep(1)
    except KeyboardInterrupt:
        ui.line("資訊", "正在停止 M2A...")
        return 0
    except Exception as exc:
        logger.exception("[Launcher] 啟動失敗")
        ui.line("錯誤", str(exc))
        if not isinstance(exc, LauncherError): print(f"\n技術資訊：\n{type(exc).__name__}: {exc}", file=sys.stderr)
        if pause_on_error:
            _wait_before_close()
        return 1
    finally:
        manager.stop_all(lambda component: ui.line("成功", f"{component} 已停止"))
        instance.release()


def launch() -> int:
    configure_console()
    root = LauncherConfig.load().root
    values = read_env_values(root / ".env")
    ui = UI(False)
    ui.banner("M2A 啟動器")
    if not values.get("LLM_API_KEY"):
        ui.line("警告", "尚未設定 LLM API Key。")
        try:
            answer = input("是否現在設定？ [y/N]：").strip().lower()
        except EOFError:
            ui.line("錯誤", "無法讀取使用者輸入，M2A 啟動器將安全結束。")
            return 1
        if answer in {"y", "yes", "是"}:
            try:
                configure_llm(root)
            except Exception as exc:
                ui.line("錯誤", "無法更新 M2A 設定。")
                print(f"\n技術資訊：\n{_technical_info(exc)}", file=sys.stderr)

    while True:
        print("\n[1] 啟動 M2A\n[2] API / LLM 設定\n[3] Worker 設定\n[4] 顯示目前設定\n[5] 離開\n")
        try:
            choice = input("請選擇：").strip()
        except EOFError:
            ui.line("錯誤", "無法讀取使用者輸入，M2A 啟動器將安全結束。")
            return 1
        try:
            if choice == "1":
                return launch_services(LauncherConfig.load(root), pause_on_error=True)
            if choice == "2":
                configure_llm(root)
            elif choice == "3":
                configure_worker(root)
            elif choice == "4":
                show_current_config(root)
            elif choice == "5":
                ui.line("資訊", "已離開 M2A 啟動器。")
                return 0
            else:
                ui.line("錯誤", "請輸入 1 到 5。")
        except Exception as exc:
            ui.line("錯誤", "無法更新 M2A 設定。")
            print(f"\n技術資訊：\n{_technical_info(exc)}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(launch())
