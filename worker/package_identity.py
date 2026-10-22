"""Strict package identity extraction for vulnerability enrichment.

Product banners and generic ``version`` fields are deliberately not treated as
package identities. OSV lookups require explicit package/ecosystem/version
evidence or a supported Package URL (PURL).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from urllib.parse import unquote
from typing import Any


_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "go": "Go",
    "golang": "Go",
    "maven": "Maven",
    "crates.io": "crates.io",
    "crates": "crates.io",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "gem": "RubyGems",
    "packagist": "Packagist",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
}

_PURL_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
}
_PURL_RE = re.compile(r"^pkg:([A-Za-z0-9.+-]+)/([^?#]+)(?:\?[^#]*)?(?:#.*)?$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class PackageIdentity:
    ecosystem: str
    name: str
    version: str
    purl: str | None = None
    identity_source: str = "normalized.package_identity"

    @property
    def cache_key(self) -> str:
        canonical = json.dumps(
            {"ecosystem": self.ecosystem, "name": self.name, "version": self.version},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, str | None]:
        return asdict(self)


def _clean_scalar(value: Any, *, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > limit or _CONTROL_RE.search(value):
        return None
    return value


def _ecosystem(value: Any) -> str | None:
    raw = _clean_scalar(value, limit=80)
    return _ECOSYSTEMS.get(raw.lower()) if raw else None


def _identity_from_purl(purl_value: Any, *, source: str) -> PackageIdentity | None:
    purl = _clean_scalar(purl_value, limit=2048)
    if not purl:
        return None
    match = _PURL_RE.fullmatch(purl)
    if not match:
        return None
    purl_type = match.group(1).lower()
    ecosystem = _PURL_ECOSYSTEMS.get(purl_type)
    if not ecosystem:
        return None

    path = unquote(match.group(2))
    segments = [part for part in path.split("/") if part]
    if not segments:
        return None
    last = segments[-1]
    if "@" not in last:
        return None
    name_part, version = last.rsplit("@", 1)
    if not name_part or not version:
        return None
    segments[-1] = name_part
    if purl_type == "maven":
        name = ":".join(segments)
    else:
        name = "/".join(segments)
    name = _clean_scalar(name, limit=500)
    version = _clean_scalar(version, limit=255)
    if not name or not version:
        return None
    return PackageIdentity(ecosystem, name, version, purl=purl, identity_source=source)


def _identity_from_object(value: Any, *, source: str) -> PackageIdentity | None:
    if isinstance(value, str):
        return _identity_from_purl(value, source=source)
    if not isinstance(value, dict):
        return None

    purl = value.get("purl") or value.get("package_url")
    if purl is not None:
        parsed = _identity_from_purl(purl, source=source)
        if parsed is None:
            return None
        # If redundant explicit fields exist, they must agree with the PURL.
        explicit_name = _clean_scalar(value.get("name"), limit=500)
        explicit_ecosystem = _ecosystem(value.get("ecosystem"))
        explicit_version = _clean_scalar(value.get("version"), limit=255)
        if explicit_name and explicit_name != parsed.name:
            return None
        if explicit_ecosystem and explicit_ecosystem != parsed.ecosystem:
            return None
        if explicit_version and explicit_version != parsed.version:
            return None
        return parsed

    ecosystem = _ecosystem(value.get("ecosystem"))
    name = _clean_scalar(value.get("name"), limit=500)
    version = _clean_scalar(value.get("version"), limit=255)
    if not ecosystem or not name or not version:
        return None
    return PackageIdentity(ecosystem, name, version, identity_source=source)


def extract_package_identities(normalized_output: Any) -> tuple[list[PackageIdentity], str]:
    """Return only identities explicitly carried by normalized evidence.

    The second result is ``ready``, ``not_provided`` or ``unsupported``. Fields
    such as ``product`` and a service/banner ``version`` are never promoted.
    """
    if not isinstance(normalized_output, dict):
        return [], "not_provided"

    candidates: list[tuple[Any, str]] = []
    locations = [(normalized_output, "normalized")]
    details = normalized_output.get("details")
    if isinstance(details, dict):
        locations.append((details, "normalized.details"))

    for container, prefix in locations:
        for key in ("package_identity", "package_identities", "package", "packages", "purl", "package_url"):
            if key not in container:
                continue
            value = container[key]
            if isinstance(value, list):
                candidates.extend((item, f"{prefix}.{key}") for item in value)
            else:
                candidates.append((value, f"{prefix}.{key}"))

    if not candidates:
        return [], "not_provided"

    identities: dict[str, PackageIdentity] = {}
    invalid = False
    for value, source in candidates:
        identity = _identity_from_object(value, source=source)
        if identity is None:
            invalid = True
            continue
        identities[identity.cache_key] = identity

    if not identities:
        return [], "unsupported"
    # Do not silently omit a malformed identity alongside valid ones.
    if invalid:
        return [], "unsupported"
    return list(identities.values()), "ready"
