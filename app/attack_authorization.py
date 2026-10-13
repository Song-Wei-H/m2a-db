"""M2A's cumulative engagement authorization depth and ATT&CK descriptions.

These seven levels are an M2A policy model, not official linear ATT&CK phases.
Action requirements live in the Action Contract; this module only defines the
single authoritative level vocabulary and cumulative decision helper.
"""
from __future__ import annotations

from app.action_contracts import ACTION_REQUIRED_ATTACK_DEPTH, TOOL_BY_ACTION

POLICY_VERSION = "m2a-attack-depth-v1"

ATTACK_AUTHORIZATION_LEVELS = {
    1: {
        "key": "reconnaissance", "name_zh": "偵察與弱點盤點",
        "tactics": ["Reconnaissance"],
        "description": "目標、服務盤點與受限弱點評估；不含利用授權。",
    },
    2: {
        "key": "initial_access", "name_zh": "初始存取驗證",
        "tactics": ["Initial Access"],
        "description": "驗證已授權的初始存取路徑，仍須有證據與 action contract。",
    },
    3: {
        "key": "execution", "name_zh": "執行驗證",
        "tactics": ["Execution"],
        "description": "受控且明確授權的執行驗證；不含任意 shell。",
    },
    4: {
        "key": "persistence_privilege", "name_zh": "權限提升與持久性",
        "tactics": ["Persistence", "Privilege Escalation"],
        "description": "僅限明確授權的評估情境，且維持既有安全限制。",
    },
    5: {
        "key": "credential_defense", "name_zh": "憑證與防禦規避",
        "tactics": ["Credential Access", "Defense Evasion"],
        "description": "授權上限不會啟用密碼噴灑、憑證填充或惡意程式規避能力。",
    },
    6: {
        "key": "discovery_lateral", "name_zh": "內部探索與橫向移動",
        "tactics": ["Discovery", "Lateral Movement"],
        "description": "供明確授權的內部攻擊路徑驗證。",
    },
    7: {
        "key": "full_chain", "name_zh": "完整攻擊鏈",
        "tactics": ["Collection", "Command and Control", "Exfiltration", "Impact"],
        "description": "完整鏈授權上限仍不略過證據、工具契約、範圍、核准或 runtime controls。",
    },
}


def level_definitions() -> list[dict]:
    """Return API-safe definitions plus executable action coverage by level."""
    return [
        {
            "level": level,
            **definition,
            "cumulative": list(range(1, level + 1)),
            "registered_actions": sorted(
                TOOL_BY_ACTION[action_id]
                for action_id, required in ACTION_REQUIRED_ATTACK_DEPTH.items()
                if required == level
            ),
        }
        for level, definition in ATTACK_AUTHORIZATION_LEVELS.items()
    ]


def depth_decision(authorized_depth: int, required_depth: int) -> dict:
    """Evaluate only the ceiling check; other authorization gates remain separate."""
    valid = (
        isinstance(authorized_depth, int) and not isinstance(authorized_depth, bool)
        and 1 <= authorized_depth <= 7
        and isinstance(required_depth, int) and not isinstance(required_depth, bool)
        and 1 <= required_depth <= 7
    )
    if not valid:
        return {"passed": False, "reason_code": "ATTACK_DEPTH_INVALID"}
    if required_depth > authorized_depth:
        return {
            "passed": False,
            "reason_code": "ATTACK_DEPTH_EXCEEDED",
            "authorized_depth": authorized_depth,
            "required_depth": required_depth,
        }
    return {
        "passed": True,
        "reason_code": None,
        "authorized_depth": authorized_depth,
        "required_depth": required_depth,
    }
