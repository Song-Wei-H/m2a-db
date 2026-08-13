"""Version-evidence gate for product-only CVE candidates.

The gate is deliberately non-executable.  It prevents a product CPE hit from
being treated as target applicability or from automatically scheduling a broad
vulnerability scan.
"""

from __future__ import annotations

from typing import Any


PRODUCT_ONLY_MATCH = "cpe_product_only"
VERSION_VERIFICATION_REQUIRED = "VERSION_VERIFICATION_REQUIRED"


def requires_version_verification(cve_summary: Any | None) -> bool:
    return bool(
        cve_summary
        and getattr(cve_summary, "cve_count", 0)
        and getattr(cve_summary, "best_match_type", None) == PRODUCT_ONLY_MATCH
    )


def version_verification_decision(*, cve_summary: Any, tool_name: str) -> dict[str, Any]:
    return {
        "recommended_action": "stop",
        "recommended_tool": None,
        "requires_approval": False,
        "suppress_http_followup": True,
        "verification_state": VERSION_VERIFICATION_REQUIRED,
        "reasoning": [
            "Observed CPE is product-only; installed version is not evidence.",
            "No CVE validation ToolTask is created until version applicability is confirmed.",
            "Use an approved read-only version source, then reassess affected-version ranges.",
        ],
        "cve_gate": {
            "candidate_count": int(getattr(cve_summary, "cve_count", 0) or 0),
            "best_cve": getattr(cve_summary, "best_cve", None),
            "match_type": getattr(cve_summary, "best_match_type", None),
            "match_confidence": getattr(cve_summary, "best_match_confidence", None),
            "source_tool": tool_name,
        },
    }
