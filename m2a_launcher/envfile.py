from __future__ import annotations

import os
import re
import shutil
from pathlib import Path


ENV_ASSIGNMENT = re.compile(r"^(?P<prefix>\s*(?:export\s+)?)(?P<key>[A-Za-z_][A-Za-z0-9_]*)(?P<separator>\s*=\s*)(?P<value>.*)$")
SAFE_UNQUOTED = re.compile(r"^[A-Za-z0-9_./:@+,-]+$")


class EnvUpdateError(RuntimeError):
    pass


def read_env_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        match = ENV_ASSIGNMENT.match(raw)
        if not match:
            continue
        value = match.group("value").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
            if raw.strip().endswith('"'):
                value = value.replace(r"\"", '"').replace(r"\\", "\\")
        values[match.group("key")] = value
    return values


def mask_secret(secret: str | None) -> str:
    if not secret or len(secret) < 8:
        return "********"
    prefix = secret[:3] if len(secret) >= 12 else ""
    return f"{prefix}****{secret[-4:]}"


def _serialize(value: str) -> str:
    if SAFE_UNQUOTED.fullmatch(value):
        return value
    return '"' + value.replace("\\", r"\\").replace('"', r'\"') + '"'


def ensure_env_file(root: Path) -> tuple[Path, bool]:
    env_path = root / ".env"
    if env_path.exists():
        return env_path, False
    example = root / ".env.example"
    if not example.exists():
        raise EnvUpdateError("找不到 .env.example，無法安全建立 .env。")
    shutil.copy2(example, env_path)
    return env_path, True


def update_env(root: Path, updates: dict[str, str], *, required_non_empty: set[str] | None = None) -> Path:
    required = required_non_empty or set()
    for key in required:
        if not updates.get(key, "").strip():
            raise ValueError(f"{key} 不可為空。")

    env_path, created = ensure_env_file(root)
    if not created:
        shutil.copy2(env_path, root / ".env.backup")

    original = env_path.read_text(encoding="utf-8-sig")
    newline = "\r\n" if "\r\n" in original else "\n"
    had_final_newline = original.endswith(("\n", "\r"))
    lines = original.splitlines()
    remaining = dict(updates)
    rendered: list[str] = []
    for line in lines:
        match = ENV_ASSIGNMENT.match(line)
        key = match.group("key") if match else None
        if key not in updates:
            rendered.append(line)
            continue
        rendered.append(f"{match.group('prefix')}{key}{match.group('separator')}{_serialize(updates[key])}")
        remaining.pop(key, None)

    if remaining:
        if rendered and rendered[-1].strip():
            rendered.append("")
        rendered.extend(f"{key}={_serialize(value)}" for key, value in remaining.items())

    output = newline.join(rendered)
    if had_final_newline or remaining:
        output += newline
    temporary = root / ".env.launcher-tmp"
    try:
        temporary.write_text(output, encoding="utf-8", newline="")
        os.replace(temporary, env_path)
    except Exception as exc:
        raise EnvUpdateError("無法寫入 .env。") from exc
    finally:
        if temporary.exists():
            temporary.unlink()
    return env_path
