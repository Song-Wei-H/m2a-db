from types import SimpleNamespace

import pytest

from worker.learning_context import LearningContext
from worker.offline_knowledge_provider import BuiltinKnowledgeProvider


def context(port, service):
    return LearningContext.from_target(
        open_port=SimpleNamespace(port=port, service=service),
        evidence={"evidence_type": f"{service}_service"},
    )


@pytest.mark.asyncio
async def test_builtin_provider_returns_http_priors_without_external_dataset():
    prior = await BuiltinKnowledgeProvider().load_prior(context(443, "https"))

    assert prior == {
        "httpx_basic": 1.0,
        "nuclei_safe": 0.85,
        "dirb_safe": 0.60,
    }


@pytest.mark.asyncio
async def test_builtin_provider_returns_service_specific_priors():
    assert await BuiltinKnowledgeProvider().load_prior(context(22, "ssh")) == {"ssh-enum": 1.0}
    assert await BuiltinKnowledgeProvider().load_prior(context(3306, "mysql")) == {"mysql-info": 1.0}


@pytest.mark.asyncio
async def test_builtin_provider_unknown_context_returns_nmap_prior():
    prior = await BuiltinKnowledgeProvider().load_prior(context(12345, "unknown"))

    assert prior == {"nmap_service": 0.80}
