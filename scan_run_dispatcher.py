from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select, update

from app.config import settings
from app.database import async_session
from app.models import ScanRun, ToolTask

logger = logging.getLogger(__name__)


async def poll_once() -> int:
    async with async_session() as db, db.begin():
        result = await db.execute(
            select(ScanRun)
            .where(
                ScanRun.status == "pending",
                ScanRun.scan_type == "nmap",
            )
            .order_by(ScanRun.id)
            .with_for_update(skip_locked=True)
        )

        scan_runs = result.scalars().all()

        if not scan_runs:
            return 0

        count = 0

        for scan_run in scan_runs:
            exists = await db.execute(
                select(ToolTask.id)
                .where(
                    ToolTask.target_id == scan_run.target_id,
                    ToolTask.tool_name == "nmap_service",
                    ToolTask.status.in_(["pending", "running", "completed"]),
                )
                .limit(1)
            )

            if exists.scalar_one_or_none():
                await db.execute(
                    update(ScanRun)
                    .where(ScanRun.id == scan_run.id)
                    .values(status="completed")
                )
                continue

            task = ToolTask(
                target_id=scan_run.target_id,
                tool_name="nmap_service",
                status="pending",
                approval_required=False,
                approval_status="not_required",
                priority=50,
            )

            db.add(task)

            await db.execute(
                update(ScanRun)
                .where(ScanRun.id == scan_run.id)
                .values(status="completed")
            )

            logger.info(
                "Created nmap_service tool_task for scan_run_id=%s target_id=%s",
                scan_run.id,
                scan_run.target_id,
            )

            count += 1

        return count


async def run_dispatcher() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    logger.info("ScanRun Dispatcher started")

    while True:
        try:
            count = await poll_once()
            if count:
                logger.info("Processed %s pending scan_run(s)", count)
        except Exception:
            logger.exception("ScanRun dispatcher poll failed")

        await asyncio.sleep(settings.dispatcher_poll_interval_seconds)


def main() -> None:
    asyncio.run(run_dispatcher())


if __name__ == "__main__":
    main()