"""Utility functions for checking existing command templates.

This module provides deterministic helpers that inspect available command
templates and determine whether a service already has a governed template.

No database writes, subprocesses, shell operations, or command execution occur
in this module.
"""

from __future__ import annotations

from typing import Any, Iterable

__all__ = ["template_exists_for_service"]


def template_exists_for_service(
    service: str | None,
    available_templates: Iterable[dict[str, Any]] | None = None,
) -> bool:
    """Return True if service has a governed command template.

    Parameters
    ----------
    service:
        Service name such as "http", "ssh", "mysql", or "smb".
    available_templates:
        Iterable of dictionaries. Each dictionary may contain one of:
        - service
        - supported_service
        - service_name

    Returns
    -------
    bool
        True when a matching governed template is present.
    """
    if not service or not available_templates:
        return False

    target = service.strip().lower()

    for template in available_templates:
        candidates = {
            str(template.get("service") or "").strip().lower(),
            str(template.get("supported_service") or "").strip().lower(),
            str(template.get("service_name") or "").strip().lower(),
        }

        if target in candidates:
            return True

    return False