from jev_skillbench.detect import Record
from jev_skillbench.holdout import (
    analyze_holdout,
    apply_isotonic,
    calibrated,
    fit_isotonic,
    fit_threshold,
    stratified_split,
    wilson_recall,
)
from jev_skillbench.llm import system_prompt
from jev_skillbench.metrics import bootstrap_ci, confusion, truncation_split, wilson_interval


def mk(id, label, prob, truncated=False, vector=None):
    return Record(
        id=id,
        label=label,
        split="generated",
        gold_vector=vector,
        gold_behavior=None,
        arm="jev",
        prob_malicious=prob,
        truncated=truncated,
    )


def test_bootstrap_ci_brackets_point():
    records = [mk(f"m{i}", 1, 0.9) for i in range(20)] + [mk(f"b{i}", 0, 0.1) for i in range(20)]
    ci = bootstrap_ci(records, lambda r: confusion(r, 0.5).recall, n_boot=200)
    assert ci["point"] == 1.0
    assert ci["lo"] <= ci["point"] <= ci["hi"]
    assert ci["n_boot"] == 200


def test_bootstrap_ci_handles_tiny_sample():
    ci = bootstrap_ci([mk("a", 1, 0.9)], lambda r: confusion(r, 0.5).recall, n_boot=100)
    assert ci["lo"] is None and ci["hi"] is None


def test_wilson_interval_zero_successes():
    lo, hi = wilson_interval(0, 50)
    assert lo == 0.0
    assert 0.05 < hi < 0.10


def test_truncation_split():
    records = [
        mk("a", 1, 0.9, truncated=True),
        mk("b", 0, 0.1, truncated=True),
        mk("c", 1, 0.9),
        mk("d", 0, 0.1),
    ]
    groups = truncation_split(records)
    assert groups["truncated"]["n"] == 2
    assert groups["intact"]["n"] == 2
    assert groups["intact"]["recall"] == 1.0


def test_fit_threshold_respects_target_fpr():
    records = [
        mk("b1", 0, 0.01),
        mk("b2", 0, 0.02),
        mk("m1", 1, 0.30),
        mk("m2", 1, 0.90),
    ]
    assert fit_threshold(records, target_fpr=0.0) == 0.30


def test_isotonic_is_monotone_and_calibrates():
    records = [mk(f"b{i}", 0, 0.01 * i) for i in range(10)]
    records += [mk(f"m{i}", 1, 0.5 + 0.05 * i) for i in range(10)]
    model = fit_isotonic(records)
    ys = [y for _, y in model]
    assert ys == sorted(ys)
    assert apply_isotonic(model, 0.0) < apply_isotonic(model, 1.0)
    recalibrated = calibrated(records, model)
    assert all(0.0 <= r.prob_malicious <= 1.0 for r in recalibrated)


def test_stratified_split_keeps_both_classes():
    records = [mk(f"m{i}", 1, 0.9) for i in range(10)] + [mk(f"b{i}", 0, 0.1) for i in range(10)]
    fit, evaluation = stratified_split(records, 0.5, seed=1)
    assert {r.label for r in fit} == {0, 1}
    assert {r.label for r in evaluation} == {0, 1}
    assert len(fit) == 10 and len(evaluation) == 10


def test_stratified_split_keeps_vectors_on_both_sides():
    records = []
    for vec in ("ci", "pi", "mixed"):
        records += [mk(f"{vec}_m{i}", 1, 0.9, vector=vec) for i in range(6)]
    records += [mk(f"b{i}", 0, 0.1) for i in range(12)]
    fit, evaluation = stratified_split(records, 0.5, seed=3)
    for vec in ("ci", "pi", "mixed"):
        assert sum(1 for r in fit if r.gold_vector == vec) == 3
        assert sum(1 for r in evaluation if r.gold_vector == vec) == 3


def test_analyze_holdout_structure():
    records = [mk(f"m{i}", 1, 0.4 + 0.01 * i) for i in range(30)]
    records += [mk(f"b{i}", 0, 0.0 + 0.001 * i) for i in range(30)]
    result = analyze_holdout(records, n_boot=50, seed=2)
    assert result["eval_n"] > 0
    assert result["tuned_threshold"] <= 0.5
    assert result["eval_at_tuned"]["recall"] >= result["eval_at_default"]["recall"]
    assert "eval_intervals_at_tuned" in result


def test_wilson_recall_shape():
    records = [mk(f"m{i}", 1, 0.9) for i in range(4)] + [mk(f"b{i}", 0, 0.1) for i in range(6)]
    out = wilson_recall(records)
    assert out["recall"]["point"] == 1.0
    assert out["fpr"]["point"] == 0.0


def test_system_prompt_uses_same_questions():
    prompt = system_prompt(include_behavior=True)
    assert "is_malicious" in prompt
    assert "attack_vector" in prompt
    assert "harm_severity" in prompt
    assert "behavior" in prompt
    assert "B10" in prompt
    without = system_prompt(include_behavior=False)
    assert "B10" not in without


def test_backend_model_defaults_and_resolution(monkeypatch):
    from jev_skillbench import detect

    monkeypatch.delenv("AI_GATEWAY_API_KEY", raising=False)
    monkeypatch.delenv("VERCEL_API_KEY", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert detect.resolve_backend("auto") == "sdk"
    assert detect.default_model_for("vercel") == "typesafe-ai/jev"
    assert detect.default_model_for("sdk") == "jev-1.13.0"
    monkeypatch.setenv("VERCEL_API_KEY", "vck_x")
    assert detect.resolve_backend("auto") == "vercel"
    monkeypatch.setenv("TYPESAFE_API_KEY", "apikey_x")
    assert detect.resolve_backend("auto") == "vercel"
    assert detect.resolve_backend("sdk") == "sdk"


def test_sdk_runner_rejects_unknown_kwargs():
    import inspect

    from jev_skillbench.detect import run_jev_sdk

    params = inspect.signature(run_jev_sdk).parameters
    assert "sink" in params
    assert "max_retries" not in params
