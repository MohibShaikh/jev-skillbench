import json
from pathlib import Path

from jev_skillbench import claude_cli
from jev_skillbench.dataset import SkillItem


def _item() -> SkillItem:
    return SkillItem(id="s1", label=1, split="generated", vector="pi", behavior="B1", behavior_name=None, root=Path("."))


def _run(monkeypatch, tmp_path, payloads):
    calls = iter(payloads)
    monkeypatch.setattr(claude_cli, "_call", lambda *a, **k: next(calls))
    monkeypatch.setattr(claude_cli, "SYSTEM_FILE", str(tmp_path / "system.txt"))
    monkeypatch.setattr(claude_cli.time, "sleep", lambda s: None)
    return claude_cli.run_claude_cli([_item()], cwd=str(tmp_path), max_retries=2)[0]


def test_cost_counts_failed_attempts(monkeypatch, tmp_path):
    verdict = json.dumps({"is_malicious": 0.9, "attack_vector": "pi"})
    rec = _run(
        monkeypatch,
        tmp_path,
        [
            {"is_error": True, "result": "refused", "total_cost_usd": 0.10},
            {"result": "not json", "total_cost_usd": 0.05},
            {"result": verdict, "total_cost_usd": 0.02, "usage": {"output_tokens": 7}},
        ],
    )
    assert rec.error is None
    assert rec.prob_malicious == 0.9
    assert abs(rec.cost_usd - 0.17) < 1e-9


def test_cost_kept_when_every_attempt_fails(monkeypatch, tmp_path):
    rec = _run(monkeypatch, tmp_path, [{"is_error": True, "result": "refused", "total_cost_usd": 0.1}] * 3)
    assert rec.error is not None
    assert rec.prob_malicious is None
    assert abs(rec.cost_usd - 0.3) < 1e-9
