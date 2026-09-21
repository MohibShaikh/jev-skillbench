"""Run detectors over benchmark items and persist raw per-sample records.

Two Jev transports:

- `sdk`: the TypeSafe Python SDK against api.typesafe.ai, needs TYPESAFE_API_KEY.
- `openrouter`: the `/api/alpha/decisions` endpoint, needs OPENROUTER_API_KEY.
  Jev is a decisions model there rather than a chat model, so the request and
  response bodies match TypeSafe's `systemone` shape, and usage includes cost.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx

from .dataset import SkillItem
from .questions import skill_questions

DEFAULT_MODEL = "jev-1.13.0"
OPENROUTER_MODEL = "~typesafe/jev-latest"
OPENROUTER_BASE = "https://openrouter.ai/api"


@dataclass
class Record:
    id: str
    label: int
    split: str
    gold_vector: str | None
    gold_behavior: str | None
    arm: str
    model: str | None = None
    prob_malicious: float | None = None
    pred_vector: str | None = None
    pred_behavior: str | None = None
    harm_severity: float | None = None
    vector_probs: dict | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    state_tokens: int = 0
    truncated: bool = False
    error: str | None = None


def _base_record(item: SkillItem, arm: str) -> Record:
    return Record(
        id=item.id,
        label=item.label,
        split=item.split,
        gold_vector=item.vector,
        gold_behavior=item.behavior,
        arm=arm,
        state_tokens=item.state_tokens,
        truncated=item.truncated,
    )


def _fill(
    rec: Record,
    model: str | None,
    answers: Mapping,
    input_tokens: int | None,
    output_tokens: int | None,
    cost: float | None,
) -> None:
    rec.model = model
    rec.input_tokens = input_tokens
    rec.output_tokens = output_tokens
    rec.cost_usd = cost
    noul = answers.get("is_malicious")
    if noul:
        rec.prob_malicious = float(noul["noul"])
    vector = answers.get("attack_vector")
    if vector:
        rec.pred_vector = vector.get("choice")
        rec.vector_probs = vector.get("probabilities")
    severity = answers.get("harm_severity")
    if severity:
        rec.harm_severity = severity.get("score")
    behavior = answers.get("behavior")
    if behavior:
        rec.pred_behavior = behavior.get("choice")


def _wire(questions: Mapping) -> dict:
    return {k: (v.model_dump(exclude_none=True) if hasattr(v, "model_dump") else v) for k, v in questions.items()}


async def run_jev_sdk(
    items: list[SkillItem],
    model: str = DEFAULT_MODEL,
    concurrency: int = 16,
    include_behavior: bool = True,
    timeout: float = 90.0,
) -> list[Record]:
    from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy

    questions = skill_questions(include_behavior=include_behavior)
    sem = asyncio.Semaphore(concurrency)
    client = AsyncTypeSafeClient(model=model, retry=RetryPolicy(max_retries=3, timeout=timeout))

    async def one(item: SkillItem) -> Record:
        rec = _base_record(item, "jev")
        async with sem:
            start = time.perf_counter()
            try:
                response = await client.system_one(state=item.state(), questions=questions, timeout=timeout)
            except Exception as exc:
                rec.error = f"{type(exc).__name__}: {exc}"
                rec.latency_ms = (time.perf_counter() - start) * 1000
                return rec
            rec.latency_ms = (time.perf_counter() - start) * 1000
            answers = {k: v.model_dump() for k, v in response.answers.items()}
            _fill(rec, response.model, answers, response.usage.input_tokens, response.usage.output_tokens, None)
            return rec

    try:
        return list(await asyncio.gather(*(one(i) for i in items)))
    finally:
        await client.aclose()


async def run_jev_openrouter(
    items: list[SkillItem],
    model: str = OPENROUTER_MODEL,
    base_url: str | None = None,
    api_key: str | None = None,
    concurrency: int = 16,
    include_behavior: bool = True,
    timeout: float = 90.0,
) -> list[Record]:
    base_url = (base_url or os.environ.get("OPENROUTER_BASE_URL") or OPENROUTER_BASE).rstrip("/")
    api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")
    questions = _wire(skill_questions(include_behavior=include_behavior))
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=timeout) as http:
        async def one(item: SkillItem) -> Record:
            rec = _base_record(item, "jev")
            rec.model = model
            async with sem:
                start = time.perf_counter()
                try:
                    resp = await http.post(
                        f"{base_url}/alpha/decisions",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={"model": model, "state": item.state(), "questions": questions},
                    )
                    payload = resp.json()
                    if resp.status_code >= 400 or "error" in payload:
                        raise RuntimeError((payload.get("error") or {}).get("message", resp.text))
                except Exception as exc:
                    rec.error = f"{type(exc).__name__}: {exc}"
                    rec.latency_ms = (time.perf_counter() - start) * 1000
                    return rec
                rec.latency_ms = (time.perf_counter() - start) * 1000
                usage = payload.get("usage") or {}
                _fill(
                    rec,
                    payload.get("model", model),
                    payload.get("answers", {}),
                    usage.get("input_tokens"),
                    usage.get("output_tokens"),
                    usage.get("cost"),
                )
                return rec

        return list(await asyncio.gather(*(one(i) for i in items)))


def resolve_backend(backend: str) -> str:
    if backend != "auto":
        return backend
    if os.environ.get("TYPESAFE_API_KEY"):
        return "sdk"
    if os.environ.get("OPENROUTER_API_KEY"):
        return "openrouter"
    return "sdk"


def run_jev_sync(items: list[SkillItem], backend: str = "auto", **kwargs) -> list[Record]:
    resolved = resolve_backend(backend)
    runner = run_jev_openrouter if resolved == "openrouter" else run_jev_sdk
    return asyncio.run(runner(items, **kwargs))


def write_records(path: str | Path, records: list[Record]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")


def read_records(path: str | Path) -> list[Record]:
    path = Path(path)
    if not path.exists():
        return []
    out: list[Record] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(Record(**json.loads(line)))
    return out


def completed_ids(path: str | Path) -> set[str]:
    return {r.id for r in read_records(path) if r.error is None}
