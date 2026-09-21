from jev_skillbench.detect import Record
from jev_skillbench.llm import cascade_decision
from jev_skillbench.metrics import brier, confusion, ece, recall_by_vector, summarize


def mk(id, label, prob, vector=None, arm="jev"):
    return Record(
        id=id,
        label=label,
        split="generated",
        gold_vector=vector,
        gold_behavior=None,
        arm=arm,
        prob_malicious=prob,
    )


def test_confusion_basic():
    records = [mk("a", 1, 0.9), mk("b", 1, 0.4), mk("c", 0, 0.7), mk("d", 0, 0.1)]
    c = confusion(records, 0.5)
    assert (c.tp, c.fn, c.fp, c.tn) == (1, 1, 1, 1)
    assert c.recall == 0.5
    assert c.fpr == 0.5
    assert c.precision == 0.5
    assert c.f1 == 0.5


def test_confusion_ignores_errors():
    records = [mk("a", 1, 0.9), Record("b", 1, "generated", "ci", None, "jev", error="boom")]
    c = confusion(records)
    assert c.n == 1
    assert c.n_errors == 1


def test_brier():
    records = [mk("a", 1, 1.0), mk("b", 0, 0.0), mk("c", 1, 0.5)]
    assert brier(records) == (0 + 0 + 0.25) / 3


def test_ece_perfect_calibration():
    records = [mk("a", 1, 1.0), mk("b", 0, 0.0)] * 50
    assert ece(records) == 0.0


def test_ece_detects_overconfidence():
    records = [mk(f"m{i}", 1, 0.9) for i in range(50)] + [mk(f"b{i}", 0, 0.9) for i in range(50)]
    assert ece(records) > 0.3


def test_recall_by_vector():
    records = [mk("a", 1, 0.9, "ci"), mk("b", 1, 0.1, "ci"), mk("c", 1, 0.9, "pi")]
    by = recall_by_vector(records)
    assert by["ci"].recall == 0.5
    assert by["pi"].recall == 1.0


def test_summarize_shape():
    records = [mk("a", 1, 0.9, "ci"), mk("b", 0, 0.1)]
    s = summarize(records)
    assert s["overall"]["n"] == 2
    assert s["overall"]["recall"] == 1.0
    assert s["overall"]["fpr"] == 0.0
    assert s["arm"] == "jev"


def test_cascade_decision():
    assert cascade_decision(0.05, None, 0.2, 0.8) == 0
    assert cascade_decision(0.95, None, 0.2, 0.8) == 1
    assert cascade_decision(0.5, 0.9, 0.2, 0.8) == 1
    assert cascade_decision(0.5, 0.1, 0.2, 0.8) == 0
    assert cascade_decision(0.5, None, 0.2, 0.8) == 1
