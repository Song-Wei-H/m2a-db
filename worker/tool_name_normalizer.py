from __future__ import annotations

TOOL_ALIASES = {
    "httpx": "httpx_basic",
    "nuclei": "nuclei_safe",
    "ssh_enum": "ssh-enum",
    "mysql_info": "mysql-info",
}

def normalize_tool_name(tool_name: str | None) -> str | None:
    if not tool_name:
        return None
    return TOOL_ALIASES.get(tool_name, tool_name)