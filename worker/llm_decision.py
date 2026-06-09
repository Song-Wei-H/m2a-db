from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from ollama import Client
from sqlalchemy import select

from app.database import async_session
from app.models import DecisionScore, LlmRecommendation
from worker.llm_validator import validate_recommendation


SYSTEM_PROMPT = """
You are a governed pentest decision engine.

You DO NOT execute commands.
You DO NOT create shell commands.
You ONLY recommend actions.

Allowed actions:
- stop
- continue
- verify
- remediate

Allowed tools:
- nmap_service
- httpx_basic
- nuclei_safe
- dirb_safe

Important governance rules:
- If match_confidence is below 0.7, do not recommend remediate.
- If CVSS/EPSS/KEV are high but match_confidence is below 0.7, recommend verify.
- If verification is needed, prefer nuclei_safe.
- If a tool is unavailable, the validator may override your recommendation.

Output JSON only.

Required schema:
{
  "recommended_action": "stop|continue|verify|remediate",
  "recommended_tool": "nmap_service|httpx_basic|nuclei_safe|dirb_safe|null",
  "confidence": 0.0,
  "reasoning": ["reason1", "reason2"]
}
"""


OLLAMA_HOST = "http://192.0.2.220:11434"
OLLAMA_MODEL = "gemma3:27b"


def extract_json(text: str) -> dict[str, Any]:
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"LLM did not return JSON: {text}")

    return json.loads(match.group(0))


def build_payload(decision: DecisionScore) -> dict[str, Any]:
    snapshot = decision.input_snapshot or {}
    cve = snapshot.get("cve") or {}

    return {
        "target_id": decision.target_id,
        "decision_score_id": decision.id,
        "open_port_id": decision.open_port_id,
        "port": snapshot.get("port"),
        "protocol": snapshot.get("protocol"),
        "service": snapshot.get("service"),
        "product": snapshot.get("product"),
        "version": snapshot.get("version"),
        "state": snapshot.get("state"),
        "risk_score": decision.risk_score,
        "decision_action": decision.next_action,
        "decision_next_tool": decision.next_tool,
        "evidence_confidence": cve.get("best_match_confidence"),
        "best_cve": cve.get("best_cve"),
        "cvss": cve.get("max_cvss"),
        "epss": cve.get("max_epss"),
        "kev": cve.get("has_kev"),
        "match_type": cve.get("best_match_type"),
        "match_confidence": cve.get("best_match_confidence"),
    }


def call_ollama(payload: dict[str, Any]) -> dict[str, Any]:
    client = Client(host=OLLAMA_HOST)

    response = client.chat(
        model=OLLAMA_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Analyze this governed pentest evidence and return ONLY valid JSON. "
                    "Do not use markdown. Do not explain outside JSON.\n\n"
                    + json.dumps(payload, ensure_ascii=False)
                ),
            },
        ],
        options={
            "temperature": 0,
        },
    )

    content = response["message"]["content"]
    raw = extract_json(content)

    validated = validate_recommendation(
        raw,
        match_confidence=payload.get("match_confidence"),
        httpx_enabled=False,
    )

    return {
        "raw": raw,
        "validated": validated,
    }


async def save_llm_recommendation(
    *,
    decision: DecisionScore,
    payload: dict[str, Any],
    llm_result: dict[str, Any],
) -> int:
    raw = llm_result["raw"]
    validated = llm_result["validated"]

    reasoning = validated.get("reasoning")
    if isinstance(reasoning, list):
        reasoning_text = "\n".join(str(x) for x in reasoning)
    else:
        reasoning_text = str(reasoning)

    changed = raw != validated

    row = LlmRecommendation(
        target_id=decision.target_id,
        decision_score_id=decision.id,
        recommended_action=validated.get("recommended_action"),
        recommended_tool=validated.get("recommended_tool"),
        confidence=validated.get("confidence"),
        reasoning=reasoning_text,
        raw_response={
            "payload": payload,
            "raw_llm": raw,
            "validated": validated,
        },
        validator_status="overridden" if changed else "accepted",
        validator_reason=(
            "LLM recommendation was modified by governance validator."
            if changed
            else "LLM recommendation accepted by governance validator."
        ),
    )

    async with async_session() as db, db.begin():
        db.add(row)
        await db.flush()
        return row.id


async def run_for_decision_score(decision_score_id: int) -> int:
    async with async_session() as db:
        decision = await db.get(DecisionScore, decision_score_id)

    if decision is None:
        raise ValueError(f"decision_score_id={decision_score_id} not found")

    payload = build_payload(decision)
    llm_result = call_ollama(payload)

    return await save_llm_recommendation(
        decision=decision,
        payload=payload,
        llm_result=llm_result,
    )


async def run_latest() -> int:
    async with async_session() as db:
        result = await db.execute(
            select(DecisionScore)
            .order_by(DecisionScore.id.desc())
            .limit(1)
        )
        decision = result.scalar_one_or_none()

    if decision is None:
        raise ValueError("No decision_scores found")

    payload = build_payload(decision)
    llm_result = call_ollama(payload)

    return await save_llm_recommendation(
        decision=decision,
        payload=payload,
        llm_result=llm_result,
    )


def main() -> None:
    row_id = asyncio.run(run_latest())
    print(f"saved llm_recommendations.id={row_id}")


if __name__ == "__main__":
    main()