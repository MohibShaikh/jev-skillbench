"""Claude Code headless arm.

Runs one skill per `claude -p` call on the Claude Code subscription rather than
the API. The harness is invoked with user settings and tools stripped, because
otherwise Claude Code injects ~85k tokens of machine context per call.

`total_cost_usd` from Claude Code is list-price equivalent, not a subscription
charge. It is stored in `cost_usd` for comparability and labeled as such in meta.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from .dataset import SkillItem
from .detect import Record, _base_record
from .llm import system_prompt
from .questions import ATTACK_VECTORS, BEHAVIORS

DEFAULT_CLAUDE_MODEL = "claude-opus-5"
WORKDIR = "/tmp/jev-skillbench-claude"
SYSTEM_FILE = "/tmp/jev-skillbench-claude-system.txt"


def _prepare(cwd: str, include_behavior: bool) -> None:
    Path(cwd).mkdir(parents=True, exist_ok=True)
    Path(SYSTEM_FILE).write_text(system_prompt(include_behavior), encoding="utf-8")


def _call(state: dict, model: str, cwd: str, timeout: float, effort: str | None = None) -> dict:
    cmd = [
        "claude",
        "-p",
        "--output-format",
        "json",
        "--model",
        model,
        "--system-prompt-file",
        SYSTEM_FILE,
        "--tools",
        "",
        "--setting-sources",
        "",
        "--no-session-persistence",
    ]
    if effort:
        cmd += ["--effort", effort]
    proc = subprocess.run(
        cmd,
        input=json.dumps(state, ensure_ascii=False),
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=timeout,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
        raise RuntimeError(detail[:300])
    return json.loads(proc.stdout)


def _extract_json(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in result")
    return json.loads(text[start : end + 1])


def run_claude_cli(
    items: list[SkillItem],
    model: str = DEFAULT_CLAUDE_MODEL,
    cwd: str = WORKDIR,
    timeout: float = 600.0,
    include_behavior: bool = True,
    sink=None,
    max_retries: int = 2,
    effort: str | None = None,
) -> list[Record]:
    _prepare(cwd, include_behavior)
    out: list[Record] = []
    for item in items:
        rec = _base_record(item, "claude")
        start = time.perf_counter()
        spent = 0.0
        for attempt in range(max_retries + 1):
            try:
                payload = _call(item.state(), model, cwd, timeout, effort)
                # Count every attempt's cost, including refusals and unparseable answers.
                spent += payload.get("total_cost_usd") or 0.0
                if payload.get("is_error"):
                    raise RuntimeError(str(payload.get("result"))[:200])
                data = _extract_json(payload["result"])
                rec.prob_malicious = float(data["is_malicious"])
                vector = str(data.get("attack_vector", "")).lower()
                rec.pred_vector = vector if vector in ATTACK_VECTORS else None
                behavior = str(data.get("behavior", "")).upper()
                rec.pred_behavior = behavior if behavior in BEHAVIORS else None
                severity = data.get("harm_severity")
                rec.harm_severity = float(severity) if severity is not None else None
                usage = payload.get("usage") or {}
                rec.input_tokens = (
                    (usage.get("input_tokens") or 0)
                    + (usage.get("cache_creation_input_tokens") or 0)
                    + (usage.get("cache_read_input_tokens") or 0)
                )
                rec.output_tokens = usage.get("output_tokens")
                models = payload.get("modelUsage") or {}
                if models:
                    ranked = sorted(
                        models.items(),
                        key=lambda kv: kv[1].get("costUSD", 0) or 0,
                        reverse=True,
                    )
                    rec.model = ranked[0][0]
                    rec.models = ";".join(f"{name}:{u.get('costUSD', 0):.4f}" for name, u in ranked)
                else:
                    rec.model = model
                rec.error = None
                break
            except Exception as exc:
                rec.error = f"{type(exc).__name__}: {exc}"
                if attempt < max_retries:
                    time.sleep(2 * (attempt + 1))
        rec.cost_usd = spent
        rec.latency_ms = (time.perf_counter() - start) * 1000
        out.append(rec)
        if sink is not None:
            sink(rec)
    return out
