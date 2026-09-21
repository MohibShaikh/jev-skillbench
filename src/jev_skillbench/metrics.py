"""Evaluation metrics for malicious-skill detection."""

from __future__ import annotations

import math
import random
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from .detect import Record


def _usable(records: list[Record]) -> list[Record]:
    return [r for r in records if r.prob_malicious is not None]


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    n_errors: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None

    @property
    def fpr(self) -> float | None:
        d = self.fp + self.tn
        return self.fp / d if d else None

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return self.tp / d if d else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def accuracy(self) -> float | None:
        return (self.tp + self.tn) / self.n if self.n else None

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "n": self.n,
            "n_errors": self.n_errors,
            "recall": self.recall,
            "fpr": self.fpr,
            "precision": self.precision,
            "f1": self.f1,
            "accuracy": self.accuracy,
        }


def confusion(records: list[Record], threshold: float = 0.5) -> Confusion:
    c = Confusion(n_errors=sum(1 for r in records if r.prob_malicious is None))
    for r in _usable(records):
        predicted = r.prob_malicious >= threshold
        if r.label == 1 and predicted:
            c.tp += 1
        elif r.label == 1:
            c.fn += 1
        elif predicted:
            c.fp += 1
        else:
            c.tn += 1
    return c


def recall_by_vector(records: list[Record], threshold: float = 0.5) -> dict[str, Confusion]:
    out: dict[str, Confusion] = defaultdict(Confusion)
    for r in _usable(records):
        if r.label != 1:
            continue
        key = r.gold_vector or "wild"
        if r.prob_malicious >= threshold:
            out[key].tp += 1
        else:
            out[key].fn += 1
    return dict(out)


def _resample(records: list[Record], rng: random.Random) -> list[Record]:
    n = len(records)
    return [records[rng.randrange(n)] for _ in range(n)]


def bootstrap_ci(
    records: list[Record],
    fn: Callable[[list[Record]], float | None],
    n_boot: int = 1000,
    alpha: float = 0.05,
    seed: int = 0,
) -> dict:
    point = fn(records)
    if point is None or n_boot <= 0 or len(records) < 2:
        return {"point": point, "lo": None, "hi": None, "n_boot": 0}
    rng = random.Random(seed)
    samples = []
    for _ in range(n_boot):
        value = fn(_resample(records, rng))
        if value is not None:
            samples.append(value)
    if not samples:
        return {"point": point, "lo": None, "hi": None, "n_boot": 0}
    samples.sort()
    lo = samples[max(0, int(alpha / 2 * len(samples)))]
    hi = samples[min(len(samples) - 1, int((1 - alpha / 2) * len(samples)))]
    return {"point": point, "lo": lo, "hi": hi, "n_boot": n_boot}


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float | None, float | None]:
    if total == 0:
        return (None, None)
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def vector_accuracy(records: list[Record]) -> float | None:
    pairs = [
        (r.pred_vector, r.gold_vector)
        for r in _usable(records)
        if r.label == 1 and r.gold_vector and r.pred_vector
    ]
    if not pairs:
        return None
    return sum(p == g for p, g in pairs) / len(pairs)


def brier(records: list[Record]) -> float | None:
    rows = _usable(records)
    if not rows:
        return None
    return sum((r.prob_malicious - r.label) ** 2 for r in rows) / len(rows)


def reliability_bins(records: list[Record], n_bins: int = 10) -> list[dict]:
    rows = _usable(records)
    bins = []
    for i in range(n_bins):
        lo, hi = i / n_bins, (i + 1) / n_bins
        chunk = [r for r in rows if lo <= r.prob_malicious < hi or (i == n_bins - 1 and r.prob_malicious == 1.0)]
        if not chunk:
            bins.append({"lo": lo, "hi": hi, "n": 0, "mean_confidence": None, "empirical_rate": None})
            continue
        bins.append(
            {
                "lo": lo,
                "hi": hi,
                "n": len(chunk),
                "mean_confidence": sum(r.prob_malicious for r in chunk) / len(chunk),
                "empirical_rate": sum(r.label for r in chunk) / len(chunk),
            }
        )
    return bins


def ece(records: list[Record], n_bins: int = 10) -> float | None:
    rows = _usable(records)
    if not rows:
        return None
    total = 0.0
    for b in reliability_bins(rows, n_bins):
        if b["n"]:
            total += (b["n"] / len(rows)) * abs(b["mean_confidence"] - b["empirical_rate"])
    return total


def threshold_sweep(records: list[Record], thresholds: list[float] | None = None) -> list[dict]:
    thresholds = thresholds or [i / 20 for i in range(1, 20)]
    out = []
    for t in thresholds:
        c = confusion(records, t)
        out.append({"threshold": t, "recall": c.recall, "fpr": c.fpr, "precision": c.precision, "f1": c.f1})
    return out


def latency_stats(records: list[Record]) -> dict:
    vals = sorted(r.latency_ms for r in records if r.latency_ms is not None)
    if not vals:
        return {"n": 0, "p50_ms": None, "p95_ms": None, "mean_ms": None}

    def pick(q: float) -> float:
        return vals[min(len(vals) - 1, int(q * len(vals)))]

    return {
        "n": len(vals),
        "p50_ms": pick(0.50),
        "p95_ms": pick(0.95),
        "mean_ms": sum(vals) / len(vals),
    }


def token_usage(records: list[Record]) -> dict:
    inp = sum(r.input_tokens or 0 for r in records)
    out = sum(r.output_tokens or 0 for r in records)
    n = sum(1 for r in records if r.input_tokens is not None)
    costs = [r.cost_usd for r in records if r.cost_usd is not None]
    return {
        "input_tokens": inp,
        "output_tokens": out,
        "n_with_usage": n,
        "cost_usd_total": sum(costs) if costs else None,
    }


def cost_per_1k(records: list[Record], input_per_1k: float, output_per_1k: float) -> float | None:
    costs = [r.cost_usd for r in records if r.cost_usd is not None]
    if costs:
        return sum(costs) / len(costs) * 1000
    usage = token_usage(records)
    if not usage["n_with_usage"]:
        return None
    per_skill = (
        usage["input_tokens"] / usage["n_with_usage"] / 1000 * input_per_1k
        + usage["output_tokens"] / usage["n_with_usage"] / 1000 * output_per_1k
    )
    return per_skill * 1000


def truncation_split(records: list[Record], threshold: float = 0.5) -> dict[str, dict]:
    groups = {
        "truncated": [r for r in records if r.truncated],
        "intact": [r for r in records if not r.truncated],
    }
    return {name: confusion(chunk, threshold).as_dict() for name, chunk in groups.items() if chunk}


def summarize(
    records: list[Record],
    threshold: float = 0.5,
    price_in_per_1k: float = 0.0,
    price_out_per_1k: float = 0.0,
    n_bins: int = 10,
    n_boot: int = 0,
) -> dict:
    c = confusion(records, threshold)
    vectors = {k: v.as_dict() for k, v in recall_by_vector(records, threshold).items()}
    summary = {
        "arm": records[0].arm if records else None,
        "model": next((r.model for r in records if r.model), None),
        "threshold": threshold,
        "overall": c.as_dict(),
        "by_vector": vectors,
        "by_truncation": truncation_split(records, threshold),
        "vector_label_accuracy": vector_accuracy(records),
        "brier": brier(records),
        "ece": ece(records, n_bins),
        "reliability": reliability_bins(records, n_bins),
        "latency": latency_stats(records),
        "tokens": token_usage(records),
        "cost_per_1k_skills": cost_per_1k(records, price_in_per_1k, price_out_per_1k),
    }
    if n_boot:
        summary["intervals"] = {
            "recall": bootstrap_ci(records, lambda r: confusion(r, threshold).recall, n_boot),
            "fpr": bootstrap_ci(records, lambda r: confusion(r, threshold).fpr, n_boot),
            "brier": bootstrap_ci(records, brier, n_boot),
            "ece": bootstrap_ci(records, lambda r: ece(r, n_bins), n_boot),
        }
    return summary
