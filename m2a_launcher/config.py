from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


@dataclass(frozen=True)
class LauncherConfig:
    root: Path
    worker_mode: str
    wsl_distro: str
    wsl_worker_dir: str
    remote_worker_url: str
    backend_host: str
    backend_port: int
    frontend_port: int
    wsl_worker_port: int
    startup_timeout: int
    worker_timeout: int
    auto_open_browser: bool
    debug: bool
    llm_api_key: str = field(repr=False)
    llm_model: str
    llm_base_url: str
    llm_send_auth: bool

    @property
    def backend_url(self) -> str:
        return f"http://{self.backend_host}:{self.backend_port}"

    @property
    def frontend_url(self) -> str:
        return f"http://{self.backend_host}:{self.frontend_port}"

    @property
    def worker_url(self) -> str:
        if self.worker_mode == "wsl":
            return f"http://127.0.0.1:{self.wsl_worker_port}"
        return self.remote_worker_url.rstrip("/")

    @classmethod
    def load(cls, root: Path | None = None) -> "LauncherConfig":
        project_root = (root or discover_project_root()).resolve()
        file_values = _read_env(project_root / ".env")

        def value(name: str, default: str) -> str:
            return os.environ.get(name, file_values.get(name, default))

        mode = value("M2A_WORKER_MODE", "wsl").strip().lower()
        if mode not in {"wsl", "remote"}:
            raise ValueError("M2A_WORKER_MODE 必須是 wsl 或 remote。")
        config = cls(
            root=project_root,
            worker_mode=mode,
            wsl_distro=value("M2A_WSL_DISTRO", "kali-linux"),
            wsl_worker_dir=value("M2A_WSL_WORKER_DIR", "/opt/m2a"),
            remote_worker_url=value("M2A_REMOTE_WORKER_URL", file_values.get("KALI_WORKER_URL", "")),
            backend_host=value("M2A_BACKEND_HOST", "127.0.0.1"),
            backend_port=int(value("M2A_BACKEND_PORT", "8000")),
            frontend_port=int(value("M2A_FRONTEND_PORT", "5173")),
            wsl_worker_port=int(value("M2A_WSL_WORKER_PORT", "18000")),
            startup_timeout=int(value("M2A_STARTUP_TIMEOUT", "60")),
            worker_timeout=int(value("M2A_WORKER_TIMEOUT", "30")),
            auto_open_browser=_bool(value("M2A_AUTO_OPEN_BROWSER", "true"), True),
            debug=_bool(value("M2A_LAUNCHER_DEBUG", "false"), False),
            llm_api_key=value("LLM_API_KEY", ""),
            llm_model=value("LLM_MODEL", "openai/replace-with-model-name"),
            llm_base_url=value("LLM_BASE_URL", "http://192.0.2.20:8000/v1"),
            llm_send_auth=_bool(value("LLM_SEND_AUTH", "false"), False),
        )
        if config.worker_mode == "remote" and not config.remote_worker_url:
            raise ValueError("Remote 模式需要設定 M2A_REMOTE_WORKER_URL。")
        return config


def discover_project_root() -> Path:
    """Locate the deployed M2A root without relying on PyInstaller internals."""
    candidates = [Path.cwd(), Path(__file__).resolve().parents[1]]
    if getattr(sys, "frozen", False):
        executable_dir = Path(sys.executable).resolve().parent
        candidates = [Path.cwd(), executable_dir, executable_dir.parent, executable_dir.parent.parent, Path(__file__).resolve().parents[1]]
    for candidate in candidates:
        if (candidate / "docker-compose.yml").is_file() and (candidate / "app").is_dir():
            return candidate
    return candidates[0]
