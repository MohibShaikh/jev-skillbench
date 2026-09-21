"""Turn per-sample records into tables and charts."""

from __future__ import annotations

import json
from pathlib import Path

from .detect import Record
from .metrics import reliability_bins, summarize


def _fmt(x, places: int = 3) -> str:
    if x is None:
        return "-"
    if isinstance(x, float):
        return f"{x:.{places}f}"
    return str(x)


def summary_table(summaries: list[dict]) -> str:
    cols = ["arm", "model", "threshold", "recall", "fpr", "precision", "f1", "brier", "ece"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for s in summaries:
        o = s["overall"]
        lines.append(
            "| "
            + " | ".join(
                [
                    str(s.get("arm")),
                    str(s.get("model")),
                    _fmt(s.get("threshold")),
                    _fmt(o["recall"]),
                    _fmt(o["fpr"]),
                    _fmt(o["precision"]),
                    _fmt(o["f1"]),
                    _fmt(s.get("brier")),
                    _fmt(s.get("ece")),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


def vector_table(summaries: list[dict]) -> str:
    vectors = ["ci", "pi", "mixed", "wild"]
    cols = ["arm", "threshold", *vectors, "n"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for s in summaries:
        by = s.get("by_vector", {})
        row = [str(s.get("arm")), _fmt(s.get("threshold"))]
        for v in vectors:
            rec = by.get(v, {})
            row.append(f"{_fmt(rec.get('recall'))} ({rec.get('tp', 0)}/{rec.get('tp', 0) + rec.get('fn', 0)})")
        row.append(str(s["overall"].get("n")))
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def reliability_table(records: list[Record], n_bins: int = 10) -> str:
    lines = ["| bin | n | mean confidence | empirical rate | gap |", "|---|---|---|---|---|"]
    for b in reliability_bins(records, n_bins):
        if not b["n"]:
            continue
        gap = b["mean_confidence"] - b["empirical_rate"]
        lines.append(
            f"| {b['lo']:.1f}-{b['hi']:.1f} | {b['n']} | "
            f"{b['mean_confidence']:.3f} | {b['empirical_rate']:.3f} | {gap:+.3f} |"
        )
    return "\n".join(lines)


def charts(records: list[Record], out_dir: str | Path) -> list[Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []

    bins = [b for b in reliability_bins(records, 10) if b["n"]]
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], linestyle="--", color="grey", linewidth=1)
    if bins:
        ax.plot([b["mean_confidence"] for b in bins], [b["empirical_rate"] for b in bins], marker="o")
    ax.set_xlabel("Jev P(malicious)")
    ax.set_ylabel("Empirical malicious rate")
    ax.set_title("Reliability")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    path = out / "reliability.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    written.append(path)

    from .metrics import recall_by_vector

    by = recall_by_vector(records)
    if by:
        keys = sorted(by)
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(keys, [by[k].recall or 0 for k in keys])
        ax.set_ylabel("Recall")
        ax.set_ylim(0, 1)
        ax.set_title("Recall by attack vector")
        path = out / "recall_by_vector.png"
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        written.append(path)

    from .metrics import threshold_sweep

    sweep = threshold_sweep(records)
    if sweep:
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.plot([s["threshold"] for s in sweep], [s["recall"] or 0 for s in sweep], label="recall")
        ax.plot([s["threshold"] for s in sweep], [s["fpr"] or 0 for s in sweep], label="FPR")
        ax.set_xlabel("threshold")
        ax.set_title("Operating point")
        ax.set_ylim(0, 1)
        ax.legend()
        path = out / "threshold_sweep.png"
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        written.append(path)

    return written


def interval_table(summary: dict) -> str:
    intervals = summary.get("intervals") or {}
    if not intervals:
        return "_Run `score --bootstrap N` or `report --bootstrap N` for intervals._"
    lines = ["| metric | point | 95% CI |", "|---|---|---|"]
    for name, ci in intervals.items():
        lines.append(f"| {name} | {_fmt(ci.get('point'))} | [{_fmt(ci.get('lo'))}, {_fmt(ci.get('hi'))}] |")
    return "\n".join(lines)


def truncation_table(summary: dict) -> str:
    groups = summary.get("by_truncation") or {}
    if not groups:
        return "_No records._"
    lines = ["| group | n | recall | FPR | precision |", "|---|---|---|---|---|"]
    for name, c in groups.items():
        lines.append(
            f"| {name} | {c['n']} | {_fmt(c['recall'])} | {_fmt(c['fpr'])} | {_fmt(c['precision'])} |"
        )
    return "\n".join(lines)


def holdout_section(out_dir: Path) -> str:
    path = out_dir / "holdout.json"
    if not path.exists():
        return ""
    data = json.loads(path.read_text(encoding="utf-8"))
    at_default = data["eval_at_default"]
    at_tuned = data["eval_at_tuned"]
    lines = [
        "## Held-out calibration",
        "",
        f"Fit n={data['fit_n']}, eval n={data['eval_n']}, target FPR {data['target_fpr']}.",
        "",
        "| operating point | recall | FPR | precision |",
        "|---|---|---|---|",
        f"| default {data['default_threshold']} | {_fmt(at_default['recall'])} | {_fmt(at_default['fpr'])} | {_fmt(at_default['precision'])} |",
        f"| tuned {_fmt(data['tuned_threshold'])} | {_fmt(at_tuned['recall'])} | {_fmt(at_tuned['fpr'])} | {_fmt(at_tuned['precision'])} |",
        "",
        f"Brier raw {_fmt(data['eval_brier_raw'])} to isotonic {_fmt(data['eval_brier_isotonic'])}. ECE raw {_fmt(data['eval_ece_raw'])} to isotonic {_fmt(data['eval_ece_isotonic'])}.",
    ]
    per_vector = data.get("eval_by_vector_at_tuned") or {}
    if per_vector:
        lines += [
            "",
            "Per-vector recall on the eval split at each operating point:",
            "",
            "| vector | n | recall @ default | recall @ tuned |",
            "|---|---|---|---|",
        ]
        for name in sorted(per_vector):
            tuned = per_vector[name]
            default = (data.get("eval_by_vector_at_default") or {}).get(name, {})
            lines.append(
                f"| {name} | {tuned['tp'] + tuned['fn']} | {_fmt(default.get('recall'))} | {_fmt(tuned.get('recall'))} |"
            )
    return "\n".join(lines)


def write_report(
    records: list[Record],
    out_dir: str | Path,
    threshold: float = 0.5,
    price_in_per_1k: float = 0.0,
    price_out_per_1k: float = 0.0,
    n_boot: int = 0,
) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = summarize(records, threshold, price_in_per_1k, price_out_per_1k, n_boot=n_boot)
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    parts = [
        f"# Results: {summary['arm']} ({summary['model']})",
        "",
        f"Threshold {threshold}.",
        "",
        "## Overall",
        "",
        summary_table([summary]),
        "",
        "## Bootstrap intervals",
        "",
        interval_table(summary),
        "",
        "## Recall by attack vector",
        "",
        vector_table([summary]),
        "",
        "## Truncation split",
        "",
        truncation_table(summary),
        "",
        "## Calibration",
        "",
        reliability_table(records),
        "",
        f"Brier: {_fmt(summary['brier'])}  ",
        f"ECE: {_fmt(summary['ece'])}",
        "",
        "## Latency and cost",
        "",
        f"p50 {_fmt(summary['latency']['p50_ms'], 1)} ms, p95 {_fmt(summary['latency']['p95_ms'], 1)} ms, cost per 1k skills {_fmt(summary['cost_per_1k_skills'], 4)}",
    ]
    holdout = holdout_section(out)
    if holdout:
        parts += ["", holdout]
    md = out / "report.md"
    md.write_text("\n".join(parts) + "\n", encoding="utf-8")
    charts(records, out)
    return md
