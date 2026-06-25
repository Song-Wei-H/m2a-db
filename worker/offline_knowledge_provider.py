"""Offline advisory knowledge providers for tool ranking priors."""

from __future__ import annotations

from typing import Protocol

from worker.learning_context import LearningContext


class OfflineKnowledgeProvider(Protocol):
    async def load_prior(self, learning_context: LearningContext) -> dict[str, float]:
        ...


class BuiltinKnowledgeProvider:
    """Small built-in prior table.

    This intentionally does not load HTB/VulnHub/Pentest-R1 datasets. It only
    provides a provider interface and compact defaults for future offline
    datasets.
    """

    async def load_prior(self, learning_context: LearningContext) -> dict[str, float]:
        bucket = learning_context.port_bucket
        service = (learning_context.service or "").lower()

        if bucket == "web" or service in {"http", "https", "ssl/http", "http-alt", "www"}:
            return {
                "httpx_basic": 1.0,
                "nuclei_safe": 0.85,
                "dirb_safe": 0.60,
            }

        if bucket == "ssh" or service == "ssh":
            return {"ssh-enum": 1.0}

        if bucket == "database" or service in {"mysql", "mariadb"}:
            return {"mysql-info": 1.0}

        return {"nmap_service": 0.80}
