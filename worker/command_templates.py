"""Utility functions for loading and rendering command templates.

The command templates are stored in the :class:`app.models.CommandTemplate` table.  Each
row contains an ``argv_template`` which is a JSON array of command‑line arguments.  The
:func:`build_command_with_template` function performs a safe, deterministic rendering
of this template using the context provided by the worker.

The implementation follows the constraints in the task:

* Only the four placeholders ``{target}``, ``{port}``, ``{service}``, ``{protocol}``
  are allowed.
* The rendered command must not contain any shell syntax (``;``, ``&&``, ``|``, ``>``
  etc.) so that it can safely be executed with ``subprocess.run(..., shell=False)``.
* ``argv_template`` must be a list of strings; any other type is considered a
  configuration error.
* The placeholders used in the template must be declared in
  ``CommandTemplate.allowed_fields``.

If any of the above checks fail a :class:`ValueError` is raised and the worker
will reject the task.
"""

from __future__ import annotations

import re
import shlex
from typing import List, Tuple

from app.models import CommandTemplate

# Regular expression used to extract placeholder names from a string.
_PLACEHOLDER_RE = re.compile(r"{([^}]+)}")

# Disallowed shell meta‑characters that could enable command injection.
_SHELL_META = {";", "&&", "|", ">", "<", "`", "$("}


def _contains_shell_meta(part: str) -> bool:
    """Return ``True`` if *part* contains any disallowed shell meta‑characters.

    The check is intentionally conservative; any presence of a forbidden token
    causes a :class:`ValueError`.
    """
    for meta in _SHELL_META:
        if meta in part:
            return True
    return False


def build_command_with_template(
    template_row: CommandTemplate, ctx
) -> Tuple[List[str], str]:
    """Render a command template into an argv list.

    Parameters
    ----------
    template_row:
        A :class:`CommandTemplate` instance fetched from the database.
    ctx:
        An object providing the attributes ``host``, ``port``, ``service`` and
        ``protocol``.  The worker passes its own :class:`worker.tool_runner.TaskContext`.

    Returns
    -------
    argv: list[str]
        The list of command‑line arguments ready for :func:`subprocess.run`.
    rendered_command: str
        A single string representation of the command (joined with spaces).  This
        is useful for logging.

    Raises
    ------
    ValueError
        If the template is malformed or contains disallowed placeholders or
        shell syntax.
    """

    # ------------------------------------------------------------------
    # Validate ``argv_template`` type and content.
    # ------------------------------------------------------------------
    if not isinstance(template_row.argv_template, list):
        raise ValueError("argv_template must be a JSON array of strings")

    if not isinstance(template_row.allowed_fields, list):
        raise ValueError("allowed_fields must be a JSON array")

    allowed = set(template_row.allowed_fields)

    # All elements must be strings.
    for idx, part in enumerate(template_row.argv_template):
        if not isinstance(part, str):
            raise ValueError(
                f"argv_template element at index {idx} is not a string"
            )
        if _contains_shell_meta(part):
            raise ValueError("Template contains disallowed shell syntax")

    # ------------------------------------------------------------------
    # Render placeholders.
    # ------------------------------------------------------------------
    rendered_parts: List[str] = []

    # Mapping for placeholder substitution.
    substitution = {
        "target": ctx.host,
        "port": str(ctx.port) if ctx.port is not None else "",
        "service": ctx.service or "",
        "protocol": ctx.protocol or "",
    }

    for part in template_row.argv_template:
        # Find placeholders.
        placeholders = _PLACEHOLDER_RE.findall(part)
        # Validate placeholders against allowed list.
        if not set(placeholders).issubset(allowed):
            raise ValueError(
                f"Template uses disallowed placeholder(s) {placeholders}"
            )
        # Perform substitution.
        rendered = part.format(**substitution)
        rendered_parts.append(rendered)

    # ------------------------------------------------------------------
    # Final safety check – the rendered argv must still be free of shell meta.
    # ------------------------------------------------------------------
    for part in rendered_parts:
        if _contains_shell_meta(part):
            raise ValueError("Rendered command contains disallowed shell syntax")

    rendered_command = shlex.join(rendered_parts)
    return rendered_parts, rendered_command


__all__ = ["build_command_with_template"]


