"""Central allowlist and validation for LLM → Dispatcher → Worker."""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.mitre_rules import FORBIDDEN_TOOLS
from app.security.dangerous_chars import assert_safe_string, reject_forbidden_keys
from app.security.llm_schema import LlmToolProposal
from app.security.scope import assert_target_in_scope
from app.tool_catalog import CANONICAL_ALLOWED_TOOLS, LEGACY_TOOL_ALIASES

# LLM-facing tool IDs (no shell, template-only on worker).
LLM_ALLOWED_TOOLS = CANONICAL_ALLOWED_TOOLS

# Decision engine / legacy task names mapped to templates.


def resolve_template_tool(tool_name: str) -> str:
    name = tool_name.strip().lower()
    allowed_config = {t.lower() for t in settings.allowed_tools_list}
    if name in LLM_ALLOWED_TOOLS:
        if allowed_config and name not in allowed_config:
            raise ValueError(f"Tool {name!r} not in ALLOWED_TOOLS env list")
        return name
    if name in LEGACY_TOOL_ALIASES:
        resolved = LEGACY_TOOL_ALIASES[name]
        if allowed_config and resolved not in allowed_config:
            raise ValueError(f"Tool {name!r} maps to {resolved!r} not in ALLOWED_TOOLS")
        return resolved
    raise ValueError(f"Tool {tool_name!r} is not in allowed_tools")


def validate_profile(profile: str, target_scope: str | None) -> None:
    profile = profile.strip().lower()
    if profile not in settings.allowed_llm_profiles_list:
        allowed = ", ".join(settings.allowed_llm_profiles_list)
        raise ValueError(f"Profile {profile!r} not in ALLOWED_LLM_PROFILES ({allowed})")
    if target_scope and profile != target_scope.strip().lower():
        raise ValueError(
            f"Profile {profile!r} does not match target scope {target_scope!r}"
        )


def parse_llm_payload(raw: Any) -> LlmToolProposal:
    """Parse and validate raw LLM JSON; reject commands and extra keys."""
    if isinstance(raw, str):
        raise ValueError("LLM output must be JSON object, not a shell command string")
    if not isinstance(raw, dict):
        raise ValueError("LLM output must be a JSON object")

    reject_forbidden_keys(raw)

    for key, value in raw.items():
        if isinstance(value, str):
            assert_safe_string(value, key)

    proposal = LlmToolProposal.model_validate(raw)
    assert_safe_string(proposal.tool, "tool")
    assert_safe_string(proposal.target, "target")
    assert_safe_string(proposal.reason, "reason")

    template_tool = resolve_template_tool(proposal.tool)
    if template_tool in FORBIDDEN_TOOLS:
        raise ValueError(f"Tool {proposal.tool!r} is forbidden")

    assert_target_in_scope(proposal.target)
    return proposal


def validate_llm_proposal(proposal: LlmToolProposal) -> LlmToolProposal:
    """Re-validate a parsed proposal (scope + chars + tool)."""
    assert_safe_string(proposal.tool, "tool")
    assert_safe_string(proposal.target, "target")
    assert_safe_string(proposal.reason, "reason")
    resolve_template_tool(proposal.tool)
    assert_target_in_scope(proposal.target)
    return proposal
