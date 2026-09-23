# jev-skillbench

Measure whether Jev can catch malicious agent skills, on MalSkillBench.

Jev is TypeSafe's System One model. It returns typed judgments and calibrated
probabilities instead of prose. This repo asks one question with numbers: does a
semantic judgment model close the instruction-level gap where static and LLM
skill scanners fail, and what does that cost per skill?

Short answer, following TypeSafe's own verify-and-escalate pattern: Jev settles
83% of skills on its own, and sending only the uncertain rest to an LLM reaches
94% recall at 0.8% false positive rate. Details under [Results](#results).

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
3. `claude`, Claude through `claude -p` with tools and user settings stripped,
   same questions.
4. `cascade`, Jev triage with an LLM only on the ambiguous band.
5. MalSkillBench's published baselines, cited, not rerun.

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

`--backend auto` (the default) prefers `sdk`, then `vercel`, then `openrouter`,
based on which keys are present. `sdk` is the fast path, so it is tried first.

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

### Cascade: Jev triages, an LLM checks only the uncertain band

TypeSafe's docs describe this pattern directly: "send uncertain or failing cases
to a person or reasoning model" (`typesafe-ai/skills`,
`skills/typesafe-ai/SKILL.md`, lines 83 to 86). Here it is on malicious skills.

Jev scores every skill. At or above 0.5 the skill is flagged, below 0.05 it
passes, and only the band in between goes to an LLM. The rule for whether the
cascade was worth building was frozen before the band run: the LLM had to catch
at least 30 of the 100 in-band malicious skills while flagging at most 7 of the
71 in-band benign ones. Both band models pass.

Measured on a 1,000-skill sample stratified by label, split, and vector
(`results/samples/strat1000.jsonl`, 498 malicious, 502 benign). The band is 171
skills (17.1%).

| operating point | recall | FPR | pi | wild | cost per 1k skills |
|---|---|---|---|---|---|
| Jev @0.5 | 0.755 | 0.000 | 0.689 | 0.444 | $0.18 |
| Jev @0.09 (held-out tuned) | 0.906 | 0.040 | | | $0.18 |
| Jev + gemini-2.5-flash on the band | 0.898 [0.869, 0.924] | 0.008 [0.002, 0.017] | 0.787 | 0.859 | about $0.49 |
| Jev + Claude Opus 5 on the band | 0.944 [0.921, 0.964] | 0.008 [0.002, 0.017] | 0.902 | 0.902 | about $19.70 |

In the band, Gemini caught 71 of 100 malicious skills and Opus caught 94; both
flagged 4 of 71 benign. With the cheap model, the cascade matches the tuned
threshold's recall at a fifth of its false positive rate. Opus adds about 4.6
recall points, almost all on pi and wild skills. Wild recall goes from 0.444 on
Jev alone to 0.86 to 0.90, the largest gain of any vector.

Cost provenance: Jev's cost is what the API reported. The Claude figure is the
subscription-equivalent cost `claude -p` reports ($0.114 per band skill), not
money billed. The Gemini figure is estimated from measured tokens at $0.30 and
$2.50 per Mtok, because the Vercel gateway does not return a cost.

Artifacts: `results/cascade-claude-low/cascade.json`,
`results/cascade-gemini/cascade.json`, band records in `results/claude-low/`
and `results/band-gemini-flash/`, and the pre-registered rule in
`results/claude-low/BAND_RESULT.md`.

Checks on the cascade:

- The 0.05 cutoff was read off the full-run reliability curve, which includes
  the 1,000 sample. On the 6,907 skills outside the sample, 3.9% of malicious
  skills score below 0.05 (4.4% in the sample) and the band is 19.1% of skills
  (17.1% in the sample), so the cutoff is not tuned to the sample.
- Those sub-0.05 malicious skills (22 in the sample: 15 pi, 7 wild) never reach
  the LLM, which caps cascade recall near 0.96.
- Jev scores vary a little between identical requests. Two fresh passes over the
  sample (`results/repeat-strat1000-r1/`, `-r2/`) on 963 comparable skills: 64%
  of scores identical, mean absolute difference 0.005, largest 0.08, and 5 to 6
  skills crossing 0.5. Re-scoring the cascade on those passes gives recall 0.930
  to 0.932 against 0.942, a lower bound, since 14 to 16 skills that moved into
  the band have no LLM verdict and count as passes.
- Claude Code routed some calls to secondary models (opus-4-8, haiku); each
  record lists the models that took part. Two Opus refusals and one Gemini parse
  failure count as passes.

### Jev alone, full set

Full benchmark run: all 7,944 skills (3,944 malicious, 4,000 benign), model
`jev-1.13.0`, threshold 0.5, one TypeSafe request per skill. Artifacts in
`results/20260921T095913Z-jev/` (raw `jev.jsonl`, `summary.json`, `holdout.json`,
`report.md`, charts) with the run configuration in `meta.json`.

| arm | model | n | recall | FPR | precision | F1 | Brier | ECE |
|---|---|---|---|---|---|---|---|---|
| jev | jev-1.13.0 | 7,907 | 0.755 | 0.0008 | 0.999 | 0.860 | 0.096 | 0.126 |

Bootstrap 95% intervals at threshold 0.5: recall [0.742, 0.770], FPR [0.000,
0.002], Brier [0.090, 0.102], ECE [0.120, 0.133].

Recall by attack vector, at the default cutoff and at the tuned 0.09 threshold
(tuned on the held-out half; both columns scored on the full set). Vector-label
accuracy is 0.776.

| vector | n | recall @0.5 | recall @0.09 | truncated |
|---|---|---|---|---|
| ci | 1,346 | 0.914 | 0.993 | 2 |
| mixed | 568 | 0.905 | 1.000 | 0 |
| pi | 1,300 | 0.715 | 0.884 | 1 |
| wild | 726 | 0.416 | 0.730 | 4 |

At the default 0.5 cutoff, 3 benign skills out of 4,000 are flagged and 964
malicious skills are missed. The wild subset is the weak spot, and it is not a
truncation artifact: wild skills truncate 4 of 726 (0.6%) and are smaller than
average (1,859 state tokens versus 2,834 for ci). 77 of the 84 truncated skills
are benign. Wild recall improves to 0.730 at the tuned threshold but stays the
lowest by a wide margin, so the weakness is in the ranking, not only the
calibration. That lines up with what the MalSkillBench authors report: real-world
malware is where detectors diverge.

The default 0.5 cutoff is conservative for this domain: almost nothing benign
scores above 0.2. TypeSafe's docs say to evaluate thresholds on your own data and
to validate calibration in the target domain (`SKILL.md`, lines 132 to 133 and
143), so that is what `evaluate` does. On a held-out split stratified by label,
split, and attack vector:

| operating point | recall | FPR |
|---|---|---|
| default 0.5 | 0.763 | 0.001 |
| tuned 0.09 | 0.916 | 0.049 |

Isotonic calibration fit on one half and scored on the other cuts ECE from 0.123
to 0.010 and Brier from 0.093 to 0.049. The ranking is strong and a
domain-specific threshold recovers most of the recall. The gain costs about 5%
FPR, so the operating point is a policy choice, not a free win, and the cascade
above gets similar recall without that cost.

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
- The LLMs only ever see the uncertain band, so nothing here is a head-to-head
  between Jev and an LLM. Full-set LLM baselines are MalSkillBench's published
  numbers, cited, not rerun.
- Cascade numbers come from a 1,000-skill sample, not the full set.
- On 2026-09-23, 21 of the 1,000 sample requests to `api.typesafe.ai` were
  blocked by the edge firewall with a 403, 6 of them benign skills, and stayed
  blocked on a serial retry. The same skills went through on 2026-09-21. The
  repeat-run comparison excludes them.
- The repeat passes used the current 28k state budget; the original run and both
  band runs used 30k. The repeat comparison uses only skills untruncated in both.
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
.venv/bin/jev-skillbench cascade  --jev-records results/samples/strat1000.jsonl \
    --llm-records results/claude-low/claude.jsonl --t-low 0.05 --t-high 0.5 \
    --run-dir results/cascade-claude-low
```

`cascade --llm-records` scores existing band records offline without new calls.
Without it, `cascade --model <id>` calls the LLM on the band first.

## Related work

From the awesome-jev catalog, checked 2026-09-23. None benchmark malicious agent
skills.

- `jev-sec-bench`: prompt injection and vulnerable code, not skills.
- `shade-arena-jev-monitor`: Jev as a runtime monitor for agent sabotage.
- `jev-phishing-bench`, `jev-secret-detection`: security classification in
  other domains.
- `jev-calibration-audit`: calibration measured across domains, with results
  that differ in direction by domain. This repo adds a security domain with
  intervals.
- `jev-calibrate`: held-out threshold tuning against your own labels, the same
  method as `evaluate`.
- `triagedy`: security alert triage with Jev and policy kept in code.
- `jev-guard`, `is-malicious`: tools that scan skills or code with Jev. The
  numbers here may help pick their thresholds.

## License

Code and result records: MIT, see [LICENSE](LICENSE). The records hold skill
ids, labels, and scores, not skill contents.

The MalSkillBench dataset is not included and stays under its own terms:
academic research use only. `fetch` downloads it separately.
