from __future__ import annotations

import getpass
from pathlib import Path
from typing import Callable

from m2a_launcher.config import LauncherConfig
from m2a_launcher.envfile import mask_secret, read_env_values, update_env


Input = Callable[[str], str]
SecretInput = Callable[[str], str]


def _yes_no(prompt: str, input_fn: Input, *, default: bool = False) -> bool:
    suffix = " [Y/n]：" if default else " [y/N]："
    answer = input_fn(prompt + suffix).strip().lower()
    return default if not answer else answer in {"y", "yes", "是"}


def configure_llm(root: Path, input_fn: Input = input, secret_fn: SecretInput = getpass.getpass) -> bool:
    values = read_env_values(root / ".env")
    current_key = values.get("LLM_API_KEY", "")
    print("\n========================================\n          M2A API / LLM 設定\n========================================\n")
    print("LLM Provider\n\n[1] OpenAI-Compatible\n")
    input_fn("請按 Enter 繼續：")

    api_key = current_key
    if current_key:
        print(f"目前 API Key：{mask_secret(current_key)}\n\n[1] 保留目前 API Key\n[2] 輸入新的 API Key\n[3] 取消")
        choice = input_fn("請選擇：").strip() or "1"
        if choice == "3":
            return False
        if choice == "2":
            api_key = secret_fn("API Key（輸入後不會顯示）：").strip()
            if not api_key:
                print("[錯誤] API Key 不可為空。")
                return False
    else:
        api_key = secret_fn("API Key（輸入 C 可取消）：").strip()
        if api_key.lower() == "c":
            return False
        if not api_key:
            print("[錯誤] API Key 不可為空。")
            return False

    model_current = values.get("LLM_MODEL", "openai/qwen3-4b-thinking-2507-heretic")
    base_current = values.get("LLM_BASE_URL", "http://10.56.67.11/v1")
    model = input_fn(f"Model [{model_current}]：").strip() or model_current
    base_url = input_fn(f"API Base URL [{base_current}]：").strip() or base_current
    send_auth_current = values.get("LLM_SEND_AUTH", "false").lower() in {"1", "true", "yes", "on"}
    send_auth = _yes_no("是否傳送 Bearer Authorization header？", input_fn, default=send_auth_current)
    update_env(root, {
        "LLM_API_KEY": api_key,
        "LLM_MODEL": model,
        "LLM_BASE_URL": base_url,
        "LLM_SEND_AUTH": "true" if send_auth else "false",
    }, required_non_empty={"LLM_API_KEY"})
    print("[成功] API 設定已儲存。")
    return True


def configure_worker(root: Path, input_fn: Input = input) -> bool:
    values = read_env_values(root / ".env")
    print("\n========================================\n            M2A Worker 設定\n========================================\n")
    print("Worker Mode\n\n[1] WSL Kali\n[2] Remote Kali\n[3] 取消")
    choice = input_fn("請選擇：").strip()
    if choice == "3" or choice not in {"1", "2"}:
        return False
    if choice == "1":
        distro_current = values.get("M2A_WSL_DISTRO", "kali-linux")
        directory_current = values.get("M2A_WSL_WORKER_DIR", "/opt/m2a")
        distro = input_fn(f"WSL Distro [{distro_current}]：").strip() or distro_current
        directory = input_fn(f"Worker Directory [{directory_current}]：").strip() or directory_current
        update_env(root, {
            "M2A_WORKER_MODE": "wsl",
            "M2A_WSL_DISTRO": distro,
            "M2A_WSL_WORKER_DIR": directory,
        })
    else:
        url_current = values.get("M2A_REMOTE_WORKER_URL", "")
        url = input_fn(f"Remote Worker URL [{url_current}]：").strip() or url_current
        if not url:
            print("[錯誤] Remote Worker URL 不可為空。")
            return False
        update_env(root, {"M2A_WORKER_MODE": "remote", "M2A_REMOTE_WORKER_URL": url})
    print("[成功] Worker 設定已儲存。")
    return True


def show_current_config(root: Path) -> None:
    values = read_env_values(root / ".env")
    config = LauncherConfig.load(root)
    print("\n========================================\n          M2A 目前設定\n========================================\n")
    print("LLM Provider : OpenAI-Compatible")
    print(f"Model        : {values.get('LLM_MODEL', config.llm_model)}")
    print(f"Base URL     : {values.get('LLM_BASE_URL', config.llm_base_url)}")
    print(f"API Key      : {mask_secret(values.get('LLM_API_KEY'))}")
    print(f"傳送驗證資訊 : {'是' if config.llm_send_auth else '否'}")
    print(f"\nWorker Mode  : {config.worker_mode.upper()}")
    print(f"WSL Distro   : {config.wsl_distro}")
    print(f"Backend      : {config.backend_host}:{config.backend_port}\n")
