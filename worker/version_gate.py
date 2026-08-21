"""Version-evidence gate for product-only CVE candidates.

The gate is deliberately non-executable.  It prevents a product CPE hit from
being treated as target applicability or from automatically scheduling a broad
vulnerability scan.
"""

from __future__ import annotations

from typing import Any

from app.config import settings
from worker.cve_validation_policy import select_validation_candidates


PRODUCT_ONLY_MATCH = "cpe_product_only"
VERSION_VERIFICATION_REQUIRED = "VERSION_VERIFICATION_REQUIRED"


def requires_version_verification(cve_summary: Any | None) -> bool:
    return bool(
        cve_summary
        and getattr(cve_summary, "cve_count", 0)
        and getattr(cve_summary, "best_match_type", None) == PRODUCT_ONLY_MATCH
    )


def version_verification_decision(
    *, cve_summary: Any, tool_name: str, compatible_tool: bool = True
) -> dict[str, Any]:
    selected, evaluated = select_validation_candidates(
        getattr(cve_summary, "candidates", ()),
        compatible_tool=compatible_tool,
        limit=settings.max_cve_validations_per_round,
    )
    selected_ids = [item.get("cve_id") for item in selected]
    if selected:
        action = "verify"
        recommended_tool = "nuclei_safe"
        state = "VALIDATION_PENDING"
    else:
        action = "defer"
        recommended_tool = None
        state = "VERSION_UNRESOLVED"
    return {
        "recommended_action": action,
        "recommended_tool": recommended_tool,
        "requires_approval": bool(selected),
        "suppress_http_followup": True,
        "cve_validation": True,
        "verification_state": state,
        "reasoning": [
            "Observed CPE is product-only; installed version remains unverified.",
            "Product identity confidence is independent from version status and CVE threat priority.",
            (
                f"Selected {len(selected)} candidate(s) for governed safe validation."
                if selected
                else "No product-relevant candidate with a compatible validation tool was eligible; validation is deferred."
            ),
        ],
        "cve_gate": {
            "candidate_count": int(getattr(cve_summary, "cve_count", 0) or 0),
            "best_cve": getattr(cve_summary, "best_cve", None),
            "match_type": getattr(cve_summary, "best_match_type", None),
            "match_confidence": getattr(cve_summary, "best_match_confidence", None),
            "source_tool": tool_name,
            "selected_cve_ids": selected_ids,
            "max_validations_per_round": settings.max_cve_validations_per_round,
            "candidate_decisions": evaluated,
        },
    }
