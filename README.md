# jev-skillbench

Measure whether Jev can catch malicious agent skills, on MalSkillBench.

Jev is TypeSafe's System One model. It returns typed judgments and calibrated
probabilities instead of prose. This repo asks one question with numbers: does a
semantic judgment model close the instruction-level gap where static and LLM
skill scanners fail, and what does that cost per skill?

The harness is built and unit tested. No live numbers are in it yet.

## Why this gap

MalSkillBench reports that the strongest skill-specific detector reaches 98.4%
recall on code injection, then collapses on prompt-injection and agent-control
attacks. Detecting a malicious skill means reasoning over the relationship
between a skill's code and its instructions at the same time. That is the shape
of judgment Jev is built for.

Jev guard tools exist (`jev-guard`, `is-malicious`) but none publish per-sample
measurements on a skill corpus. This repo produces the measurements.

## Data

`lxyeternal/MalSkillBench` (arXiv 2606.07131):

| Split | Count |
|---|---|
| Generated (runtime verified) | 3,214 |
| Wild | 703 |
| Tool test | 27 |
| Malicious total | 3,944 |
| Benign | 4,000 |

Labels come from `malware/_source_inventory.txt`, which the benchmark ships. It
classifies every entry as generated, wild, or test, and carries the attack vector
and behavior for generated entries. Behavior labels for wild and test entries come
from the `*_LABEL` sections of the same file. Verified against the manifest header:
3,214 generated, 703 wild, 27 test, and vector counts CI 1,346, PI 1,300, MIXED 568.

The repo is academic-research-only and about 1.5 GB. `fetch` sparse-clones just
`Dataset/Skills`. Skills are inert text here. Nothing in this repo executes them.

A second, unrelated dataset has a nearly identical name:
`ProtectSkills/MaliciousSkillBench` (arXiv 2608.19901), 9,740 identities with
frozen eval splits. It is a candidate second protocol, not the current target.

## What gets measured

One request per skill. The state is the whole package as structured JSON:
`skill.name` plus `skill.files[]` with `path` and `content`, so the model can judge
how the SKILL.md instructions and the bundled scripts interact.

Questions, all typed:

| ID | Primitive | Judgment |
|---|---|---|
| `is_malicious` | Noul | P(malicious), the detection score |
| `attack_vector` | Choice | ci, pi, mixed, none |
| `behavior` | Choice | B1..B15, none |
| `harm_severity` | Score | four named levels |

Reported per arm: recall and false positive rate overall and by attack vector,
Brier score, expected calibration error, a reliability table, vector-label
accuracy, p50/p95 latency, token usage, and cost per 1,000 skills.

Arms:

1. `jev` alone.
2. `llm`, a frontier model asked the same questions as JSON. Deliberately the
   weakest fair LLM baseline.
3. `cascade`, Jev triage with an LLM only on the ambiguous band.
4. MalSkillBench's published baselines, cited, not rerun.

Thresholds and cost are the two things to fit on validation data, not on test.

## Quickstart

```bash
uv venv .venv && uv pip install -e ".[dev]"
cp .env.example .env    # add a key, see below
.venv/bin/jev-skillbench fetch
.venv/bin/jev-skillbench stats
.venv/bin/jev-skillbench run --arm jev --per-class 50 --out runs/smoke.jsonl
.venv/bin/jev-skillbench report --records runs/smoke.jsonl
```

Two Jev transports, chosen with `--backend`:

- `sdk` talks to `api.typesafe.ai` and needs `TYPESAFE_API_KEY` from
  console.typesafe.ai/keys.
- `openrouter` talks to OpenRouter's `/api/alpha/decisions` endpoint and needs
  `OPENROUTER_API_KEY`. Jev is a decisions model there, not a chat model, and the
  key needs credits. `models` only works on the SDK backend.

`--backend auto` (the default) picks `sdk` when `TYPESAFE_API_KEY` is set,
otherwise `openrouter`.

Runs append to JSONL and resume by default, so a killed run restarts where it
stopped. Every raw per-sample record is kept, including the model version, token
counts, and reported cost, so results can be recomputed without new API spend.

Scale up with `--per-class 500` for a stratified sample or drop it for all 7,944
items. Ask for a real model id from `models`, not the `jev-latest` alias, and pin
it in the README before publishing numbers.

## Layout

```
src/jev_skillbench/
  dataset.py    MalSkillBench loader, label parsing, truncation policy
  questions.py  the Jev question set, the main experimental variable
  detect.py     Jev arm, JSONL records, resume
  llm.py        frontier LLM arm and cascade policy
  metrics.py    confusion, per-vector recall, Brier, ECE, latency, cost
  report.py     markdown tables and charts
  cli.py        fetch, stats, models, run, cascade, score, report
tests/
```

## Results

Smoke run, 100 skills (50 malicious, 50 benign), stratified sample with `seed 0`.
Model `typesafe/jev-1.13-20260917`, threshold 0.5. Raw records in
`runs/jev_smoke.jsonl`, report in `reports/smoke/`.

| arm | model | n | recall | FPR | precision | Brier | ECE |
|---|---|---|---|---|---|---|---|
| jev | typesafe/jev-1.13-20260917 | 100 | 0.76 | 0.00 | 1.00 | 0.091 | 0.135 |

Recall by attack vector:

| vector | recall | n |
|---|---|---|
| mixed | 1.00 | 9 |
| ci | 0.88 | 16 |
| pi | 0.65 | 17 |
| wild | 0.50 | 8 |

Cost was $0.15 per 1,000 skills at $0.042 per Mtok input, output free. p50
latency 499 ms, p95 1,624 ms.

This is a 100-item smoke, not a benchmark result. The split across vectors is the
thing to watch: near perfect on mixed attacks, weak on prompt injection, which is
the same instruction-level failure the MalSkillBench authors report for other
detectors. Re-run at 1,000 or full scale before quoting any of it.

Known caveats to state in any write-up:

- Model aliases move between releases. Pin an exact version.
- Jev 1.13 takes 32k tokens of state; large skills are truncated by the loader at
  30k tokens, prioritizing SKILL.md then code. `truncated` per record lets you
  report metrics split on it.
- The wild subset is narrow and dominated by one campaign. Do not present
  source-conditioned results as general.
- The taxonomy covers 9,740 identities in the second dataset but 3,944 here.

## License

Code: yours to choose. Dataset: academic research use only, per MalSkillBench.
