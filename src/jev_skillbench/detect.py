"""Run detectors over benchmark items and persist raw per-sample records.

Three Jev transports:

- `sdk`: the TypeSafe Python SDK against api.typesafe.ai, needs TYPESAFE_API_KEY.
- `vercel`: Vercel AI Gateway's TypeSafe-compatible route at
  https://ai-gateway.vercel.sh/typesafe/v1/systemone, model `typesafe-ai/jev`,
  needs AI_GATEWAY_API_KEY or VERCEL_API_KEY.
- `openrouter`: OpenRouter's `/api/alpha/decisions` endpoint, needs
  OPENROUTER_API_KEY with purchased credits.

Jev bills input at $42 per billion tokens ($0.042 per million); output is free.
The vercel and sdk transports compute cost from input tokens accordingly.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx

from .dataset import SkillItem
from .questions import skill_questions

DEFAULT_MODEL = "jev-1.13.0"
VERCEL_MODEL = "typesafe-ai/jev"
VERCEL_BASE = "https://ai-gateway.vercel.sh/typesafe"
OPENROUTER_MODEL = "~typesafe/jev-latest"
OPENROUTER_BASE = "https://openrouter.ai/api"

JEV_USD_PER_INPUT_TOKEN = 0.042 / 1_000_000

RETRY_STATUSES = {429, 500, 502, 503, 504, 529}


async def _post_with_retry(
    http: httpx.AsyncClient,
    url: str,
    api_key: str,
    body: dict,
    max_retries: int,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> httpx.Response:
    delay = base_delay
    response: httpx.Response | None = None
    for attempt in range(max_retries + 1):
        response = await http.post(url, headers={"Authorization": f"Bearer {api_key}"}, json=body)
        if response.status_code not in RETRY_STATUSES or attempt == max_retries:
            return response
        header = response.headers.get("retry-after")
        try:
            wait = float(header) if header else delay
        except ValueError:
            wait = delay
        await asyncio.sleep(min(wait, max_delay) + random.uniform(0, 0.5))
        delay = min(delay * 2, max_delay)
    assert response is not None
    return response


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
    return {
        k: (v.model_dump(exclude_none=True) if hasattr(v, "model_dump") else v)
        for k, v in questions.items()
    }


async def _drain(tasks: list, sink: Callable[[Record], None] | None) -> list[Record]:
    out: list[Record] = []
    for coro in asyncio.as_completed(tasks):
        rec = await coro
        out.append(rec)
        if sink is not None:
            sink(rec)
    return out


async def run_jev_sdk(
    items: list[SkillItem],
    model: str = DEFAULT_MODEL,
    concurrency: int = 16,
    include_behavior: bool = True,
    timeout: float = 90.0,
    sink: Callable[[Record], None] | None = None,
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
            cost = (response.usage.input_tokens or 0) * JEV_USD_PER_INPUT_TOKEN
            _fill(rec, response.model, answers, response.usage.input_tokens, response.usage.output_tokens, cost)
            return rec

    try:
        return await _drain([asyncio.create_task(one(i)) for i in items], sink)
    finally:
        await client.aclose()


async def _run_jev_http(
    items: list[SkillItem],
    url: str,
    model: str,
    api_key: str,
    concurrency: int,
    include_behavior: bool,
    timeout: float,
    cost_from_tokens: bool,
    sink: Callable[[Record], None] | None = None,
    max_retries: int = 5,
) -> list[Record]:
    questions = _wire(skill_questions(include_behavior=include_behavior))
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=timeout) as http:

        async def one(item: SkillItem) -> Record:
            rec = _base_record(item, "jev")
            rec.model = model
            async with sem:
                start = time.perf_counter()
                try:
                    resp = await _post_with_retry(
                        http,
                        url,
                        api_key,
                        {"model": model, "state": item.state(), "questions": questions},
                        max_retries,
                    )
                    payload = resp.json()
                    if resp.status_code >= 400 or "error" in payload:
                        message = payload.get("error", payload).get("message", resp.text)
                        raise RuntimeError(f"HTTP {resp.status_code}: {message}")
                except Exception as exc:
                    rec.error = f"{type(exc).__name__}: {exc}"
                    rec.latency_ms = (time.perf_counter() - start) * 1000
                    return rec
                rec.latency_ms = (time.perf_counter() - start) * 1000
                usage = payload.get("usage") or {}
                input_tokens = usage.get("input_tokens")
                cost = usage.get("cost")
                if cost is None and cost_from_tokens and input_tokens is not None:
                    cost = input_tokens * JEV_USD_PER_INPUT_TOKEN
                _fill(
                    rec,
                    payload.get("model", model),
                    payload.get("answers", {}),
                    input_tokens,
                    usage.get("output_tokens"),
                    cost,
                )
                return rec

        return await _drain([asyncio.create_task(one(i)) for i in items], sink)


async def run_jev_vercel(
    items: list[SkillItem],
    model: str = VERCEL_MODEL,
    base_url: str | None = None,
    api_key: str | None = None,
    concurrency: int = 16,
    include_behavior: bool = True,
    timeout: float = 90.0,
    sink: Callable[[Record], None] | None = None,
    max_retries: int = 5,
) -> list[Record]:
    base_url = (base_url or os.environ.get("VERCEL_BASE_URL") or VERCEL_BASE).rstrip("/")
    api_key = (
        api_key
        or os.environ.get("AI_GATEWAY_API_KEY")
        or os.environ.get("VERCEL_API_KEY")
    )
    if not api_key:
        raise RuntimeError("AI_GATEWAY_API_KEY or VERCEL_API_KEY is not set")
    return await _run_jev_http(
        items,
        url=f"{base_url}/v1/systemone",
        model=model,
        api_key=api_key,
        concurrency=concurrency,
        include_behavior=include_behavior,
        timeout=timeout,
        cost_from_tokens=True,
        sink=sink,
        max_retries=max_retries,
    )


async def run_jev_openrouter(
    items: list[SkillItem],
    model: str = OPENROUTER_MODEL,
    base_url: str | None = None,
    api_key: str | None = None,
    concurrency: int = 16,
    include_behavior: bool = True,
    timeout: float = 90.0,
    sink: Callable[[Record], None] | None = None,
    max_retries: int = 5,
) -> list[Record]:
    base_url = (base_url or os.environ.get("OPENROUTER_BASE_URL") or OPENROUTER_BASE).rstrip("/")
    api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")
    return await _run_jev_http(
        items,
        url=f"{base_url}/alpha/decisions",
        model=model,
        api_key=api_key,
        concurrency=concurrency,
        include_behavior=include_behavior,
        timeout=timeout,
        cost_from_tokens=False,
        sink=sink,
        max_retries=max_retries,
    )


def resolve_backend(backend: str) -> str:
    if backend != "auto":
        return backend
    if os.environ.get("TYPESAFE_API_KEY"):
        return "sdk"
    if os.environ.get("AI_GATEWAY_API_KEY") or os.environ.get("VERCEL_API_KEY"):
        return "vercel"
    if os.environ.get("OPENROUTER_API_KEY"):
        return "openrouter"
    return "sdk"


def default_model_for(backend: str) -> str:
    return {"vercel": VERCEL_MODEL, "openrouter": OPENROUTER_MODEL}.get(backend, DEFAULT_MODEL)


def run_jev_sync(items: list[SkillItem], backend: str = "auto", **kwargs) -> list[Record]:
    resolved = resolve_backend(backend)
    runners = {
        "vercel": run_jev_vercel,
        "openrouter": run_jev_openrouter,
        "sdk": run_jev_sdk,
    }
    return asyncio.run(runners[resolved](items, **kwargs))


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
