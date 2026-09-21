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

Reported per arm: recall and false positive rate overall, by attack vector, and
split by truncation; Bootstrap 95% intervals; Brier score; expected calibration
error; a reliability table; vector-label accuracy; p50/p95 latency; token usage;
and cost per 1,000 skills. `evaluate` fits a threshold and an isotonic calibration
map on one split and scores them on another, so neither is circular.

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
.venv/bin/jev-skillbench run --arm jev --per-class 50
.venv/bin/jev-skillbench run --arm llm --ids-from results/<run>/jev.jsonl
.venv/bin/jev-skillbench score --records results/<run>
.venv/bin/jev-skillbench evaluate --records results/<run>
.venv/bin/jev-skillbench report --records results/<run>
```

Two Jev transports, chosen with `--backend`:

- `sdk` talks to `api.typesafe.ai` and needs `TYPESAFE_API_KEY` from
  console.typesafe.ai/keys.
- `openrouter` talks to OpenRouter's `/api/alpha/decisions` endpoint and needs
  `OPENROUTER_API_KEY` with credits. Jev is a decisions model there, not a chat
  model. `models` only works on the SDK backend.

`--backend auto` (the default) picks `sdk` when `TYPESAFE_API_KEY` is set,
otherwise `openrouter`.

## Protocol

These rules exist because an earlier run was lost to a careless delete.

- Every run writes to `results/<UTC timestamp>-<arm>/` and nothing there is
  deleted. `run_dir` selects an existing directory to resume into.
- `meta.json` in each run records the model, backend, git sha, sample size,
  truncation budget, and seed, so a result can be traced to the code that made it.
- The `llm` arm takes `--ids-from <jev run>/jev.jsonl` so both arms score the exact
  same skills with the same states and the same truncation.
- Runs append to JSONL and resume by default. Every raw per-sample record is kept,
  including the model version, token counts, reported cost, and truncation flag.
- Report bootstrap intervals with `score` and held-out calibration with
  `evaluate`. Never tune a threshold on the same split you report it on.
- Scale with `--per-class 500` for a stratified sample, or drop it for all 7,944
  items. Pin an exact model id from `models`, not the `jev-latest` alias.

## Layout

```
src/jev_skillbench/
  dataset.py    MalSkillBench loader, manifest labels, token-budgeted truncation
  questions.py  the Jev question set, the main experimental variable
  detect.py     Jev arms (SDK and OpenRouter decisions), JSONL records, resume
  llm.py        frontier LLM arm on the same questions, and the cascade policy
  metrics.py    confusion, per-vector recall, bootstrap CIs, Brier, ECE, latency, cost
  holdout.py    held-out threshold tuning and isotonic calibration
  report.py     markdown tables and charts
  cli.py        fetch, stats, models, run, cascade, score, evaluate, report
tests/
```

## Results

Smoke run, 100 skills (50 malicious, 50 benign), `seed 0`. Model
`typesafe/jev-1.13-20260917`. Artifacts in `results/20260921-jev-smoke/`. See that
directory's `meta.json`: this run predates the token-budget loader, so treat its
truncation behavior as unverified even though no record flagged as truncated.

| arm | model | n | recall | FPR | precision | Brier | ECE |
|---|---|---|---|---|---|---|---|
| jev | typesafe/jev-1.13-20260917 | 100 | 0.76 | 0.00 | 1.00 | 0.091 | 0.135 |

Bootstrap 95% intervals at threshold 0.5: recall [0.64, 0.88], FPR [0.00, 0.00],
Brier [0.053, 0.139], ECE [0.091, 0.193].

Recall by attack vector. Treat these as directions, not findings: n is 8 to 17.

| vector | recall | n | Wilson 95% |
|---|---|---|---|
| mixed | 1.00 | 9 | [0.70, 1.00] |
| ci | 0.88 | 16 | [0.64, 0.97] |
| pi | 0.65 | 17 | [0.41, 0.83] |
| wild | 0.50 | 8 | [0.22, 0.78] |

The finding worth pursuing is calibration, not the vector split. Jev is
underconfident on this domain: every score above 0.2 was malicious (44 samples),
and the highest benign score was 0.16. At threshold 0.5 recall is 0.76; in-sample
at 0.2 it is 0.88 at FPR 0.00. On a 50/50 held-out split, `evaluate` picks 0.08
for a 0.05 FPR target and gets recall 0.92 at FPR 0.08, up from 0.80 at 0.5, and
isotonic calibration cuts Brier 0.074 to 0.063 and ECE 0.116 to 0.070. So the
0.5 cutoff does leave recall on the table, and the gain is not free once measured
out of sample. Headline to test at scale: Jev detects malicious skills well, but
its probabilities need recalibrating for this domain.

Cost was $0.15 per 1,000 skills at $0.042 per Mtok input, output free. Full
7,944 skills is about $1.25. p50 latency 499 ms, p95 1,624 ms.

Known caveats to state in any write-up:

- Model aliases move between releases. Pin an exact version.
- Jev 1.13 takes 32k tokens of state; the loader truncates at 30k, prioritizing
  SKILL.md then code. Report recall split on `truncated`; if truncated skills are
  missed more often, the budget is hiding malicious code.
- n=100. Every interval above is wide. Nothing here is a benchmark result.
- The wild subset is narrow and dominated by one campaign. Do not present
  source-conditioned results as general.
- The taxonomy covers 9,740 identities in the second dataset but 3,944 here.

## License

Code: yours to choose. Dataset: academic research use only, per MalSkillBench.
