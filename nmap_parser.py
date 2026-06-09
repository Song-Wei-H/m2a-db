"""Parse nmap raw_output from scan_results and store open ports."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models import OpenPort, ScanResult, Target

logger = logging.getLogger(__name__)

# Examples:
#   22/tcp open ssh OpenSSH 9.9p1 Debian 3
#   9001/tcp open tor-orport?
OPEN_PORT_LINE_RE = re.compile(
    r"^(\d{1,5})/(tcp|udp|sctp)\s+open\s+(\S+)(?: +([^\r\n]+))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
HOST_IP_IN_PARENS_RE = re.compile(
    r"Nmap scan report for .+ \(([^)]+)\)",
    re.IGNORECASE,
)
HOST_IP_DIRECT_RE = re.compile(
    r"Nmap scan report for ([0-9a-fA-F\.:]+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class ParsedOpenPort:
    ip: str
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None


def extract_ip(raw_output: str, fallback: str) -> str:
    match = HOST_IP_IN_PARENS_RE.search(raw_output)
    if match:
        return match.group(1).strip()

    match = HOST_IP_DIRECT_RE.search(raw_output)
    if match:
        return match.group(1).strip()

    return fallback


def _split_version_fields(remainder: str | None) -> tuple[str | None, str | None, str | None]:
    if not remainder or not remainder.strip():
        return None, None, None

    parts = remainder.strip().split()
    if len(parts) == 1:
        return None, None, parts[0]

    product = parts[0]
    version = parts[1]
    extra_info = " ".join(parts[2:]) if len(parts) > 2 else None
    return product, version, extra_info


def parse_open_ports(raw_output: str, ip: str) -> list[ParsedOpenPort]:
    """Parse nmap port table lines where STATE is open."""
    seen: set[tuple[int, str]] = set()
    results: list[ParsedOpenPort] = []

    for match in OPEN_PORT_LINE_RE.finditer(raw_output):
        port = int(match.group(1))
        protocol = match.group(2).lower()
        service = match.group(3)
        remainder = match.group(4)

        key = (port, protocol)
        if key in seen:
            continue
        seen.add(key)

        product, version, extra_info = _split_version_fields(remainder)
        results.append(
            ParsedOpenPort(
                ip=ip,
                port=port,
                protocol=protocol,
                service=service,
                product=product,
                version=version,
                extra_info=extra_info,
            )
        )

    return results


async def _port_exists(
    db: AsyncSession,
    scan_run_id: int,
    port: int,
    protocol: str,
) -> bool:
    result = await db.execute(
        select(OpenPort.id).where(
            OpenPort.scan_run_id == scan_run_id,
            OpenPort.port == port,
            OpenPort.protocol == protocol,
        )
    )
    return result.scalar_one_or_none() is not None


async def parse_and_store(scan_result_id: int) -> int:
    """
    Load scan_results by id, parse open ports, insert into open_ports.
    Skips duplicates for the same scan_run_id + port + protocol.
    Returns number of rows inserted.
    """
    async with async_session() as db:
        row = await db.execute(
            select(ScanResult, Target.target)
            .join(Target, Target.id == ScanResult.target_id)
            .where(ScanResult.id == scan_result_id)
        )
        data = row.one_or_none()
        if data is None:
            raise ValueError(f"scan_result_id={scan_result_id} not found")

        scan_result, target_host = data

    ip = extract_ip(scan_result.raw_output, target_host)
    parsed = parse_open_ports(scan_result.raw_output, ip)

    if not parsed:
        logger.warning(
            "No open ports parsed for scan_result_id=%s scan_run_id=%s",
            scan_result_id,
            scan_result.scan_run_id,
        )
        return 0

    inserted = 0
    async with async_session() as db, db.begin():
        for item in parsed:
            if await _port_exists(db, scan_result.scan_run_id, item.port, item.protocol):
                logger.debug(
                    "Skip duplicate open_port scan_run_id=%s %s/%s",
                    scan_result.scan_run_id,
                    item.port,
                    item.protocol,
                )
                continue

            db.add(
                OpenPort(
                    target_id=scan_result.target_id,
                    scan_run_id=scan_result.scan_run_id,
                    ip=item.ip,
                    port=item.port,
                    protocol=item.protocol,
                    service=item.service,
                    product=item.product,
                    version=item.version,
                    extra_info=item.extra_info,
                    state="open",
                )
            )
            inserted += 1

    logger.info(
        "Stored %s open port(s) for scan_result_id=%s scan_run_id=%s",
        inserted,
        scan_result_id,
        scan_result.scan_run_id,
    )
    return inserted
