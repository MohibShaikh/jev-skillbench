"""Command line entry point."""

from __future__ import annotations

import datetime
import json
import os
import subprocess
from collections import Counter
from pathlib import Path

import typer
from dotenv import load_dotenv

from .dataset import (
    DEFAULT_MAX_FILE_TOKENS,
    DEFAULT_MAX_TOTAL_TOKENS,
    POLICY_VERSION,
    load_benchmark,
)
from .detect import (
    completed_ids,
    default_model_for,
    read_records,
    resolve_backend,
    run_jev_sync,
    write_records,
)
from .holdout import analyze_holdout
from .llm import cascade_decision, run_llm_sync
from .metrics import summarize
from .report import summary_table, write_report

load_dotenv()

app = typer.Typer(add_completion=False, help="Measure Jev as a malicious agent-skill detector.")

REPO_URL = "https://github.com/lxyeternal/MalSkillBench.git"
DEFAULT_DATA = "data/MalSkillBench"
SKILLS_SUBDIR = "Dataset/Skills"
RESULTS_DIR = "results"


def _skills_root(data: Path) -> Path:
    return data / SKILLS_SUBDIR


def _timestamp() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")


def _git_sha() -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        )
        return proc.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None


def _require(label: str, *envs: str) -> None:
    if not any(os.environ.get(env) for env in envs):
        joined = " or ".join(envs)
        typer.echo(f"{label} needs {joined} in the environment (see .env.example)", err=True)
        raise typer.Exit(1)


def _run_dir(run_dir: str, arm: str) -> Path:
    if run_dir:
        return Path(run_dir)
    return Path(RESULTS_DIR) / f"{_timestamp()}-{arm}"


def _write_meta(run_dir: Path, payload: dict) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "meta.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


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

    _require("models", "TYPESAFE_API_KEY")
    with TypeSafeClient() as client:
        for m in client.models.list().models:
            typer.echo(f"{m.name}\t{m.release_date}\t{m.description}")


@app.command()
def run(
    arm: str = typer.Option("jev", help="jev or llm"),
    run_dir: str = typer.Option("", help="Run directory; a timestamped one under results/ is created when empty."),
    data: Path = typer.Option(Path(DEFAULT_DATA)),
    model: str = typer.Option("", help="Model id; default depends on arm and backend."),
    backend: str = typer.Option("auto", help="Jev transport: auto, sdk, vercel, or openrouter."),
    per_class: int = typer.Option(0, help="Stratified sample per class; 0 means all."),
    limit: int = typer.Option(0, help="Raw cap; ignored when per_class is set."),
    ids_from: Path = typer.Option(None, help="Restrict to ids present in this records file."),
    concurrency: int = typer.Option(16),
    max_retries: int = typer.Option(5, help="Retries per call on 429/5xx for HTTP Jev backends."),
    only_generated: bool = typer.Option(False),
    no_behavior: bool = typer.Option(False, help="Drop the B1..B15 question."),
    max_total_tokens: int = typer.Option(DEFAULT_MAX_TOTAL_TOKENS),
    max_file_tokens: int = typer.Option(DEFAULT_MAX_FILE_TOKENS),
    resume: bool = typer.Option(True),
) -> None:
    """Run one detector arm. Appends to <run_dir>/<arm>.jsonl and resumes by default."""
    if arm not in {"jev", "llm"}:
        raise typer.BadParameter("arm must be jev or llm")
    rd = _run_dir(run_dir, arm)
    out = rd / f"{arm}.jsonl"

    items = load_benchmark(
        _skills_root(data),
        per_class=per_class or None,
        limit=limit or None,
        only_generated=only_generated,
        max_total_tokens=max_total_tokens,
        max_file_tokens=max_file_tokens,
    )
    if ids_from is not None:
        wanted = {r.id for r in read_records(ids_from)}
        items = [i for i in items if i.id in wanted]
    already = completed_ids(out) if resume else set()
    if already:
        items = [i for i in items if i.id not in already]

    resolved = resolve_backend(backend) if arm == "jev" else None
    resolved_model = model
    if arm == "jev" and not resolved_model:
        assert resolved is not None
        resolved_model = default_model_for(resolved)
    if arm == "llm" and not resolved_model:
        resolved_model = os.environ.get("OPENAI_MODEL", "")

    _write_meta(
        rd,
        {
            "arm": arm,
            "backend": resolved,
            "model": resolved_model,
            "timestamp": _timestamp(),
            "git_sha": _git_sha(),
            "dataset": str(_skills_root(data)),
            "per_class": per_class or None,
            "limit": limit or None,
            "only_generated": only_generated,
            "include_behavior": not no_behavior,
            "max_total_tokens": max_total_tokens,
            "max_file_tokens": max_file_tokens,
            "policy_version": POLICY_VERSION,
            "ids_from": str(ids_from) if ids_from else None,
            "n_planned": len(items),
            "n_resumed": len(already),
        },
    )
    typer.echo(f"running {arm} on {len(items)} items -> {out}")
    if not items:
        return

    def sink(record) -> None:
        write_records(out, [record])

    if arm == "jev":
        assert resolved is not None
        envs = {
            "sdk": ("TYPESAFE_API_KEY",),
            "vercel": ("AI_GATEWAY_API_KEY", "VERCEL_API_KEY"),
            "openrouter": ("OPENROUTER_API_KEY",),
        }[resolved]
        _require(f"jev via {resolved}", *envs)
        kwargs = {
            "model": resolved_model,
            "concurrency": concurrency,
            "include_behavior": not no_behavior,
            "sink": sink,
        }
        if resolved in {"vercel", "openrouter"}:
            kwargs["max_retries"] = max_retries
        run_jev_sync(items, backend=resolved, **kwargs)
    else:
        _require("llm", "OPENAI_API_KEY")
        run_llm_sync(
            items,
            model=resolved_model,
            concurrency=concurrency,
            include_behavior=not no_behavior,
            sink=sink,
        )
    all_records = read_records(out)
    typer.echo(summary_table([summarize(all_records)]))
    typer.echo(f"errors {sum(1 for r in all_records if r.error)}")


@app.command()
def evaluate(
    records: Path = typer.Option(Path("results"), help="Records file, or a run directory."),
    threshold: float = typer.Option(0.5, help="Reported operating point to compare against."),
    fit_fraction: float = typer.Option(0.5),
    target_fpr: float = typer.Option(0.05),
    bootstrap: int = typer.Option(1000),
    out: Path = typer.Option(None),
) -> None:
    """Held-out threshold tuning and isotonic calibration."""
    path = _records_file(records)
    result = analyze_holdout(
        read_records(path),
        threshold=threshold,
        fit_fraction=fit_fraction,
        target_fpr=target_fpr,
        n_boot=bootstrap,
    )
    dest = out or path.parent / "holdout.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2), encoding="utf-8")
    typer.echo(json.dumps(result, indent=2))
    typer.echo(f"wrote {dest}")


def _records_file(path: Path) -> Path:
    if path.is_dir():
        candidates = sorted(path.glob("*.jsonl"))
        if not candidates:
            raise typer.BadParameter(f"no .jsonl records in {path}")
        return candidates[0]
    return path


@app.command()
def cascade(
    jev_records: Path = typer.Option(Path("results"), help="Jev records file or run directory."),
    run_dir: str = typer.Option("", help="Run directory for cascade output."),
    data: Path = typer.Option(Path(DEFAULT_DATA)),
    model: str = typer.Option(..., help="Frontier LLM model id."),
    t_low: float = typer.Option(0.2),
    t_high: float = typer.Option(0.8),
    concurrency: int = typer.Option(8),
) -> None:
    """Jev triages every skill; only the ambiguous band escalates to an LLM."""
    rd = _run_dir(run_dir, "cascade")
    out = rd / "cascade.jsonl"
    jev = {r.id: r for r in read_records(_records_file(jev_records))}
    items = load_benchmark(_skills_root(data), read_files=True)
    escalate = [
        i
        for i in items
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
    records: Path = typer.Option(Path("results"), help="Records file, or a run directory."),
    threshold: float = typer.Option(0.5),
    bootstrap: int = typer.Option(1000),
    price_in_per_1k: float = typer.Option(0.0),
    price_out_per_1k: float = typer.Option(0.0),
    out: Path = typer.Option(None),
) -> None:
    """Summarize an existing run, with bootstrap intervals."""
    path = _records_file(records)
    summary = summarize(
        read_records(path),
        threshold,
        price_in_per_1k,
        price_out_per_1k,
        n_boot=bootstrap,
    )
    dest = out or path.parent / "summary.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    typer.echo(summary_table([summary]))
    typer.echo(f"wrote {dest}")


@app.command()
def report(
    records: Path = typer.Option(Path("results"), help="Records file, or a run directory."),
    out_dir: Path = typer.Option(None),
    threshold: float = typer.Option(0.5),
    bootstrap: int = typer.Option(1000),
    price_in_per_1k: float = typer.Option(0.0),
    price_out_per_1k: float = typer.Option(0.0),
) -> None:
    """Write the markdown report and charts."""
    path = _records_file(records)
    dest = out_dir or path.parent
    written = write_report(
        read_records(path), dest, threshold, price_in_per_1k, price_out_per_1k, n_boot=bootstrap
    )
    typer.echo(f"wrote {written}")


if __name__ == "__main__":
    app()
