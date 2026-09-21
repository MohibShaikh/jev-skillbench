"""Held-out threshold tuning and probability calibration.

Thresholds and calibration maps are fit on one split and scored on another, so
neither the tuned operating point nor the calibrated probabilities are circular.
"""

from __future__ import annotations

import random
from dataclasses import replace

from .detect import Record
from .metrics import bootstrap_ci, brier, confusion, ece, recall_by_vector, wilson_interval


def stratified_split(
    records: list[Record], fit_fraction: float = 0.5, seed: int = 0
) -> tuple[list[Record], list[Record]]:
    rng = random.Random(seed)
    groups: dict[tuple[int, str, str | None], list[Record]] = {}
    for record in records:
        if record.prob_malicious is None:
            continue
        groups.setdefault((record.label, record.split, record.gold_vector), []).append(record)
    fit: list[Record] = []
    evaluation: list[Record] = []
    for key in sorted(groups, key=str):
        pool = groups[key]
        rng.shuffle(pool)
        cut = round(len(pool) * fit_fraction)
        fit.extend(pool[:cut])
        evaluation.extend(pool[cut:])
    fit.sort(key=lambda r: r.id)
    evaluation.sort(key=lambda r: r.id)
    return fit, evaluation


def fit_threshold(records: list[Record], target_fpr: float = 0.05, default: float = 0.5) -> float:
    candidates = sorted({r.prob_malicious for r in records if r.prob_malicious is not None})
    threshold = default
    best: tuple[float, float, float] | None = None
    for t in candidates:
        c = confusion(records, t)
        if c.fpr is None or c.fpr > target_fpr:
            continue
        score = (c.recall or 0.0, -(c.fpr or 0.0), -t)
        if best is None or score > best:
            best = score
            threshold = t
    return threshold


def fit_isotonic(records: list[Record]) -> list[tuple[float, float]]:
    points = sorted((r.prob_malicious, r.label) for r in records if r.prob_malicious is not None)
    xs: list[float] = []
    ys: list[float] = []
    ws: list[int] = []
    for x, y in points:
        if xs and x == xs[-1]:
            ys[-1] = (ys[-1] * ws[-1] + y) / (ws[-1] + 1)
            ws[-1] += 1
        else:
            xs.append(x)
            ys.append(float(y))
            ws.append(1)
    i = 0
    while i < len(ys) - 1:
        if ys[i] > ys[i + 1]:
            w = ws[i] + ws[i + 1]
            ys[i] = (ys[i] * ws[i] + ys[i + 1] * ws[i + 1]) / w
            ws[i] = w
            del ys[i + 1]
            del ws[i + 1]
            del xs[i + 1]
            i = max(0, i - 1)
        else:
            i += 1
    return list(zip(xs, ys, strict=True))


def apply_isotonic(model: list[tuple[float, float]], p: float) -> float:
    if not model:
        return p
    value = model[0][1]
    for x, y in model:
        if p >= x:
            value = y
        else:
            break
    return value


def calibrated(records: list[Record], model: list[tuple[float, float]]) -> list[Record]:
    out = []
    for r in records:
        if r.prob_malicious is None:
            out.append(r)
        else:
            out.append(replace(r, prob_malicious=apply_isotonic(model, r.prob_malicious)))
    return out


def analyze_holdout(
    records: list[Record],
    threshold: float = 0.5,
    fit_fraction: float = 0.5,
    target_fpr: float = 0.05,
    default_threshold: float = 0.5,
    n_boot: int = 0,
    seed: int = 0,
) -> dict:
    fit, evaluation = stratified_split(records, fit_fraction, seed)
    tuned = fit_threshold(fit, target_fpr=target_fpr, default=default_threshold)
    model = fit_isotonic(fit)
    evaluation_calibrated = calibrated(evaluation, model)
    result = {
        "fit_n": len(fit),
        "eval_n": len(evaluation),
        "default_threshold": default_threshold,
        "tuned_threshold": tuned,
        "target_fpr": target_fpr,
        "fit_at_reported": confusion(fit, threshold).as_dict(),
        "eval_at_default": confusion(evaluation, default_threshold).as_dict(),
        "eval_at_tuned": confusion(evaluation, tuned).as_dict(),
        "eval_brier_raw": brier(evaluation),
        "eval_ece_raw": ece(evaluation),
        "eval_brier_isotonic": brier(evaluation_calibrated),
        "eval_ece_isotonic": ece(evaluation_calibrated),
        "eval_by_vector_at_default": {
            k: v.as_dict() for k, v in recall_by_vector(evaluation, default_threshold).items()
        },
        "eval_by_vector_at_tuned": {
            k: v.as_dict() for k, v in recall_by_vector(evaluation, tuned).items()
        },
        "isotonic_points": len(model),
    }
    if n_boot:
        result["eval_intervals_at_tuned"] = {
            "recall": bootstrap_ci(evaluation, lambda r: confusion(r, tuned).recall, n_boot, seed=seed),
            "fpr": bootstrap_ci(evaluation, lambda r: confusion(r, tuned).fpr, n_boot, seed=seed),
        }
    return result


def wilson_recall(records: list[Record], threshold: float = 0.5) -> dict[str, dict]:
    c = confusion(records, threshold)
    lo, hi = wilson_interval(c.tp, c.tp + c.fn)
    lo_f, hi_f = wilson_interval(c.fp, c.fp + c.tn)
    return {
        "recall": {"point": c.recall, "lo": lo, "hi": hi},
        "fpr": {"point": c.fpr, "lo": lo_f, "hi": hi_f},
    }
