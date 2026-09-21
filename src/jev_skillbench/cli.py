"""Command line entry point."""

from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path

import typer
from dotenv import load_dotenv

from .dataset import load_benchmark
from .detect import (
    DEFAULT_MODEL,
    OPENROUTER_MODEL,
    completed_ids,
    read_records,
    resolve_backend,
    run_jev_sync,
    write_records,
)
from .llm import cascade_decision, run_llm_sync
from .metrics import summarize
from .report import summary_table, write_report

load_dotenv()

app = typer.Typer(add_completion=False, help="Measure Jev as a malicious agent-skill detector.")

REPO_URL = "https://github.com/lxyeternal/MalSkillBench.git"
DEFAULT_DATA = "data/MalSkillBench"
SKILLS_SUBDIR = "Dataset/Skills"


@app.command()
def fetch(
    dest: Path = typer.Option(Path(DEFAULT_DATA), help="Clone destination."),
    force: bool = typer.Option(False, help="Re-clone even if present."),
) -> None:
    """Sparse-clone only the skill packages from MalSkillBench."""
    if dest.exists() and not force:
        typer.echo(f"{dest} exists; pass --force to re-clone")
        raise typer.Exit()
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--filter=blob:none", "--sparse", REPO_URL, str(dest)], check=True)
    subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", SKILLS_SUBDIR], check=True)
    typer.echo(f"skills at {dest / SKILLS_SUBDIR}")


def _skills_root(data: Path) -> Path:
    return data / SKILLS_SUBDIR


def _require(env: str, arm: str) -> None:
    if not os.environ.get(env):
        typer.echo(f"{arm} needs {env} in the environment (see .env.example)", err=True)
        raise typer.Exit(1)


@app.command()
def stats(
    data: Path = typer.Option(Path(DEFAULT_DATA)),
    only_generated: bool = typer.Option(False),
) -> None:
    """Count items by label, split, and attack vector."""
    items = load_benchmark(_skills_root(data), read_files=False, only_generated=only_generated)
    typer.echo(f"total {len(items)}")
    for key, fn in (("label", lambda i: i.label), ("split", lambda i: i.split), ("vector", lambda i: i.vector)):
        typer.echo(f"{key}: {dict(Counter(fn(i) for i in items))}")


@app.command()
def models() -> None:
    """List TypeSafe models available to the account."""
    from typesafe_sdk import TypeSafeClient

    _require("TYPESAFE_API_KEY", "models")
    with TypeSafeClient() as client:
        for m in client.models.list().models:
            typer.echo(f"{m.name}\t{m.release_date}\t{m.description}")


@app.command()
def run(
    arm: str = typer.Option("jev", help="jev or llm"),
    out: Path = typer.Option(Path("runs/jev.jsonl")),
    data: Path = typer.Option(Path(DEFAULT_DATA)),
    model: str = typer.Option("", help="Model id; default depends on arm and backend."),
    backend: str = typer.Option("auto", help="Jev transport: auto, sdk, or openrouter."),
    per_class: int = typer.Option(0, help="Stratified sample per class; 0 means all."),
    limit: int = typer.Option(0, help="Raw cap; ignored when per_class is set."),
    concurrency: int = typer.Option(16),
    only_generated: bool = typer.Option(False),
    no_behavior: bool = typer.Option(False, help="Drop the B1..B15 question."),
    resume: bool = typer.Option(True),
) -> None:
    """Run one detector arm and append raw per-sample records."""
    if arm not in {"jev", "llm"}:
        raise typer.BadParameter("arm must be jev or llm")
    items = load_benchmark(
        _skills_root(data),
        per_class=per_class or None,
        limit=limit or None,
        only_generated=only_generated,
    )
    if resume:
        done = completed_ids(out)
        items = [i for i in items if i.id not in done]
    typer.echo(f"running {arm} on {len(items)} items -> {out}")
    if not items:
        return
    if arm == "jev":
        resolved = resolve_backend(backend)
        _require("TYPESAFE_API_KEY" if resolved == "sdk" else "OPENROUTER_API_KEY", f"jev via {resolved}")
        jev_model = model or (OPENROUTER_MODEL if resolved == "openrouter" else DEFAULT_MODEL)
        records = run_jev_sync(
            items, backend=resolved, model=jev_model, concurrency=concurrency, include_behavior=not no_behavior
        )
    else:
        llm_model = model or os.environ.get("OPENAI_MODEL", "")
        _require("OPENAI_API_KEY", "llm")
        records = run_llm_sync(items, model=llm_model, concurrency=concurrency)
    write_records(out, records)
    all_records = read_records(out)
    errors = sum(1 for r in all_records if r.error)
    typer.echo(summary_table([summarize(all_records)]))
    typer.echo(f"errors {errors}")


@app.command()
def cascade(
    jev_records: Path = typer.Option(Path("runs/jev.jsonl")),
    out: Path = typer.Option(Path("runs/cascade.jsonl")),
    data: Path = typer.Option(Path(DEFAULT_DATA)),
    model: str = typer.Option(..., help="Frontier LLM model id."),
    t_low: float = typer.Option(0.2),
    t_high: float = typer.Option(0.8),
    concurrency: int = typer.Option(8),
) -> None:
    """Jev triages every skill; only the ambiguous band escalates to an LLM."""
    jev = {r.id: r for r in read_records(jev_records)}
    items = load_benchmark(_skills_root(data), read_files=True)
    escalate = [
        i for i in items
        if i.id in jev and jev[i.id].prob_malicious is not None and t_low <= jev[i.id].prob_malicious < t_high
    ]
    typer.echo(f"escalating {len(escalate)} of {len(items)} to {model}")
    done = completed_ids(out)
    escalate = [i for i in escalate if i.id not in done]
    if escalate:
        write_records(out, run_llm_sync(escalate, model=model, concurrency=concurrency))
    llm = {r.id: r for r in read_records(out)}
    decisions = []
    for item in items:
        j = jev.get(item.id)
        llm_rec = llm.get(item.id)
        decisions.append(
            cascade_decision(
                j.prob_malicious if j else None,
                llm_rec.prob_malicious if llm_rec else None,
                t_low=t_low,
                t_high=t_high,
            )
        )
    labels = [i.label for i in items]
    tp = sum(1 for d, y in zip(decisions, labels, strict=True) if d == 1 and y == 1)
    fn = sum(1 for d, y in zip(decisions, labels, strict=True) if d == 0 and y == 1)
    fp = sum(1 for d, y in zip(decisions, labels, strict=True) if d == 1 and y == 0)
    tn = sum(1 for d, y in zip(decisions, labels, strict=True) if d == 0 and y == 0)
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    typer.echo(json.dumps({"recall": recall, "fpr": fpr, "tp": tp, "fp": fp, "tn": tn, "fn": fn}, indent=2))


@app.command()
def score(
    records: Path = typer.Option(Path("runs/jev.jsonl")),
    threshold: float = typer.Option(0.5),
    price_in_per_1k: float = typer.Option(0.0),
    price_out_per_1k: float = typer.Option(0.0),
    out: Path = typer.Option(Path("reports/summary.json")),
) -> None:
    """Summarize an existing run."""
    summary = summarize(read_records(records), threshold, price_in_per_1k, price_out_per_1k)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    typer.echo(summary_table([summary]))
    typer.echo(f"wrote {out}")


@app.command()
def report(
    records: Path = typer.Option(Path("runs/jev.jsonl")),
    out_dir: Path = typer.Option(Path("reports")),
    threshold: float = typer.Option(0.5),
    price_in_per_1k: float = typer.Option(0.0),
    price_out_per_1k: float = typer.Option(0.0),
) -> None:
    """Write the markdown report and charts."""
    path = write_report(read_records(records), out_dir, threshold, price_in_per_1k, price_out_per_1k)
    typer.echo(f"wrote {path}")


if __name__ == "__main__":
    app()
