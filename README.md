# jev-skillbench

Measure whether Jev can catch malicious agent skills, on MalSkillBench.

Jev is TypeSafe's System One model. It returns typed judgments and calibrated
probabilities instead of prose. This repo asks one question with numbers: does a
semantic judgment model close the instruction-level gap where static and LLM
skill scanners fail, and what does that cost per skill?

The harness is built and unit tested. The full benchmark result is under
[Results](#results).

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

Jev bills input at $42 per billion tokens ($0.042 per million) and output is free.
The 7,944 states total 23.9M tokens, so the full `jev` run costs about $1.00. The
chat baselines bill per million tokens on both sides, so the same states cost about
$1.45 for `openai/gpt-5-nano`, $7.24 for `openai/gpt-5-mini`, and $8.75 for
`google/gemini-2.5-flash`, assuming 80 output tokens per skill. Pin the model,
measure 100 skills with `--ids-from`, then extrapolate, and put the cost gap in
the results table next to recall. Note that $2 of OpenRouter credit covers the full
Jev run but not a full chat baseline on any frontier model.

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

Three Jev transports, chosen with `--backend`:

- `sdk` talks to `api.typesafe.ai` and needs `TYPESAFE_API_KEY` from
  console.typesafe.ai/keys. This is the fast path: about 9 to 25 requests per
  second against 0.6 per second through the gateway.
- `vercel` talks to Vercel AI Gateway's TypeSafe-compatible route at
  `https://ai-gateway.vercel.sh/typesafe/v1/systemone` with model
  `typesafe-ai/jev`, and needs `AI_GATEWAY_API_KEY` or `VERCEL_API_KEY`. The free
  tier is rate limited per model, so expect heavy 429s at concurrency above 1.
- `openrouter` talks to OpenRouter's `/api/alpha/decisions` endpoint and needs
  `OPENROUTER_API_KEY` with purchased credits.

`--backend auto` (the default) prefers `vercel`, then `sdk`, then `openrouter`,
based on which keys are present.

## Protocol

These rules exist because an earlier run was lost to a careless delete.

- Every run writes to `results/<UTC timestamp>-<arm>/` and nothing there is
  deleted. `run_dir` selects an existing directory to resume into.
- Runs that produced no data, for example a run blocked on credits, move to
  `results/_failed/`. They are kept on disk but not published, and re-running the
  same directory resumes them once the blocker clears.
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
  detect.py     Jev arms (SDK, Vercel gateway, OpenRouter), JSONL records, resume
  llm.py        frontier LLM arm on the same questions, and the cascade policy
  metrics.py    confusion, per-vector recall, bootstrap CIs, Brier, ECE, latency, cost
  holdout.py    held-out threshold tuning and isotonic calibration
  report.py     markdown tables and charts
  cli.py        fetch, stats, models, run, cascade, score, evaluate, report
tests/
```

## Results

Full benchmark run: all 7,944 skills (3,944 malicious, 4,000 benign), model
`jev-1.13.0`, threshold 0.5, one TypeSafe request per skill. Artifacts in
`results/20260921T095913Z-jev/` (raw `jev.jsonl`, `summary.json`, `holdout.json`,
`report.md`, charts) with the run configuration in `meta.json`.

| arm | model | n | recall | FPR | precision | F1 | Brier | ECE |
|---|---|---|---|---|---|---|---|---|
| jev | jev-1.13.0 | 7,907 | 0.755 | 0.0008 | 0.999 | 0.860 | 0.096 | 0.126 |

Bootstrap 95% intervals at threshold 0.5: recall [0.742, 0.770], FPR [0.000,
0.002], Brier [0.090, 0.102], ECE [0.120, 0.133].

Recall by attack vector, and vector-label accuracy 0.776:

| vector | recall | n |
|---|---|---|
| ci | 0.914 | 1,346 |
| mixed | 0.905 | 568 |
| pi | 0.715 | 1,300 |
| wild | 0.416 | 726 |

At the default 0.5 cutoff, 35 benign skills out of 4,000 are flagged and 968
malicious skills are missed. The wild subset is the weak spot, which lines up with
what the MalSkillBench authors report for other detectors.

The main finding is calibration. Jev is underconfident on this domain: almost
nothing benign scores above 0.2, so the 0.5 cutoff discards recall. On a held-out
split stratified by label, split, and attack vector:

| operating point | recall | FPR |
|---|---|---|
| default 0.5 | 0.763 | 0.001 |
| tuned 0.09 | 0.916 | 0.049 |

Isotonic calibration fit on one half and scored on the other cuts ECE from 0.123
to 0.010 and Brier from 0.093 to 0.049. So Jev detects malicious skills well and
its probabilities need recalibrating for this domain. The recall gain at the tuned
threshold costs about 5% FPR, so the operating point is a policy choice, not a
free win.

Cost was $1.38 for the full set, $0.174 per 1,000 skills at $0.042 per Mtok input
with output free. p50 latency 391 ms, p95 669 ms.

Known caveats to state in any write-up:

- 37 of 7,944 requests (0.5%) failed with `max_tokens_exceeded`: 33 benign and 4
  wild skills whose state plus JSON wrapper exceeded Jev's 32k context. They are
  excluded from the metrics. The default budget is now 28k with headroom, so a
  fresh run does not hit this.
- Truncation is a real confound, not a footnote: recall is 0.571 on the 84
  truncated skills in the scored set versus 0.756 on the intact ones. n is small,
  so the interval is wide, but the direction is consistent with the budget hiding
  malicious code.
- Model aliases move between releases. Pin an exact version, as this run does.
- The wild subset is narrow and dominated by one campaign. Do not present
  source-conditioned results as general.
- No baseline has run yet. The `llm` arm and the cascade are built but unrun, so
  no claim here compares Jev to another detector.
- The taxonomy covers 9,740 identities in the second dataset but 3,944 here.
- The earlier 100-skill smoke is kept in `results/20260921-jev-smoke/` for
  provenance only; do not quote it.

## Reproducing

```
.venv/bin/jev-skillbench run --arm jev --backend sdk --concurrency 8
.venv/bin/jev-skillbench run --arm llm --ids-from results/<run>/jev.jsonl --model <pinned-model>
.venv/bin/jev-skillbench score    --records results/<run>
.venv/bin/jev-skillbench evaluate --records results/<run>
.venv/bin/jev-skillbench report   --records results/<run>
```

## License

Code: yours to choose. Dataset: academic research use only, per MalSkillBench.
