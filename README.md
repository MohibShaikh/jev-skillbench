# jev-skillbench

Measure whether Jev can catch malicious agent skills, on MalSkillBench.

Jev is TypeSafe's System One model. It returns typed judgments and calibrated
probabilities instead of prose. This repo asks one question with numbers: does a
semantic judgment model close the instruction-level gap where static and LLM
skill scanners fail, and what does that cost per skill?

Short answer, following TypeSafe's own verify-and-escalate pattern: Jev settles
83% of skills on its own, and sending only the uncertain rest to an LLM reaches
95% recall at 0.8% false positive rate. Running Haiku 5.5 on every skill instead
gets similar recall to its cascade but flags 4.6% of benign skills against 1.0%.
Details under [Results](#results).

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
The 7,944 states hold 23.8M tokens of file content, but the full `jev` run billed
32.8M input tokens once the JSON wrapper and questions are counted, so it cost
$1.38. The chat baselines bill per million tokens on both sides. A pre-run
estimate from file content alone put the same states at about $1.45 for
`openai/gpt-5-nano`, $7.24 for `openai/gpt-5-mini`, and $8.75 for
`google/gemini-2.5-flash` at 80 output tokens per skill; treat those as lower
bounds, since they leave out the prompt and wrapper. Pin the model,
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
- The `llm` arm takes `--ids-from <jev run>/jev.jsonl` so both arms score the same
  skills. States are rebuilt with the current preprocessing settings, so pass the
  Jev run's `--max-total-tokens` (in its `meta.json`) to get the same states and
  truncation. Every published band run used 30,000, the original run's budget.
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
71 in-band benign ones. Both band models pass, before and after the name fix
below.

Measured on a 1,000-skill sample stratified by label, split, and vector
(`results/samples/strat1000_anon.jsonl`, 498 malicious, 502 benign). The band is
174 skills (17.4%): 103 malicious, 71 benign.

| operating point | recall | FPR | pi | wild | cost per 1k skills |
|---|---|---|---|---|---|
| Jev @0.5 | 0.751 | 0.000 | 0.677 | 0.446 | $0.18 |
| Jev @0.09 (fit on overlapping data) | 0.906 | 0.040 | | | $0.18 |
| Jev + gemini-2.5-flash on the band | 0.882 [0.851, 0.908] | 0.008 [0.002, 0.017] | 0.744 | 0.859 | about $0.49 |
| Jev + Claude Opus 5 on the band | 0.946 [0.924, 0.966] | 0.008 [0.002, 0.016] | 0.909 | 0.902 | about $19.30 |
| Jev + Claude Opus 5.5 on the band | 0.920 [0.895, 0.943] | 0.002 [0.000, 0.006] | 0.896 | 0.880 | about $12.40 |
| Jev + Claude Haiku 5.5 on the band | 0.918 [0.892, 0.942] | 0.010 [0.002, 0.020] | 0.848 | 0.913 | about $0.63 |
| Claude Haiku 5.5 alone, every skill | 0.934 [0.911, 0.954] | 0.046 [0.027, 0.064] | 0.884 | 0.967 | about $2.23 |

In the band, Gemini caught 65 of 103 malicious skills and Opus caught 97; both
flagged 4 of 71 benign. With the cheap model, the cascade comes within 2.4 recall
points of the 0.09 threshold at a fifth of its false positive rate. Opus adds
about 6.4 recall points over Gemini, all on pi and wild skills. Wild recall goes
from 0.446 on Jev alone to 0.86 to 0.91, the largest gain of any vector. "Wild"
here and in the full-set table includes the 27 tool-test entries.

Opus 5.5 caught 84 and Haiku 5.5 caught 83 of the 103, flagging 1 and 5 of the
71 benign. Both ran at `--effort low` to match the Opus 5 run, below their
`medium` default. Opus 5.5 is the most conservative band model: lowest false
positive rate, 13 fewer catches than Opus 5. Haiku 5.5 matches its recall at
about a twentieth of the cost and beats Gemini by 3.6 points at a similar price.
Both score many missed malicious skills between 0.2 and 0.5, so a lower LLM
cutoff would trade false positives for recall; that cutoff was not fixed in
advance and is not reported here.

Haiku 5.5 was also run alone on all 1,000 sample skills with the same settings
(`results/anon-haiku-5-5-all/claude.jsonl`; every verdict from Haiku 5.5, no
refusals or failures). It catches 465 of 498 malicious skills against the
cascade's 457 and flags 23 of 502 benign skills against 5. The recall intervals
overlap; the false positive intervals do not. Of the 15 malicious skills only
Haiku alone catches, 12 score below 0.05 on Jev and never reach the band, so
most of the recall gap is the 0.05 cutoff, not the model. Jev's sub-0.05 pass
also removes 12 of Haiku's 23 false alarms. The other 11 were in the band,
where the separate band run flagged 5: two Haiku calls on the same band skill
disagree on 15 of 174. Running Haiku on every skill takes 1,000 calls instead
of 174 and costs about 3.5 times as much, at a median 5.6 s per skill.

The 0.09 row is not a held-out result for this sample: 963 of the 1,000 sample
skills, including all 502 benign ones, fall in the half the threshold was fit
on. The held-out figure is in the full-set section below.

Cost provenance: Jev's cost is input tokens times $0.042 per Mtok, computed in
`detect.py`. The Claude figure is the subscription-equivalent cost `claude -p`
reports (about $0.11 per band skill), not money billed, and includes $0.23 spent
on the two refused calls. Opus 5.5 and Haiku 5.5 are the same kind of figure;
Opus 5.5 includes $0.33 spent on refused attempts. The Gemini figure is estimated from measured tokens at
$0.30 and $2.50 per Mtok, because the Vercel gateway does not return a cost,
and counts only the final attempt per skill.

Artifacts: `results/cascade-anon-claude/cascade.json`,
`results/cascade-anon-gemini/cascade.json`, band records in
`results/anon-band-claude/merged.jsonl` and `results/anon-band-gemini/merged.jsonl`,
`results/cascade-anon-{opus-5-5,haiku-5-5}/` with band records in
`results/anon-band-{opus-5-5,haiku-5-5}/claude.jsonl`, Haiku alone in
`results/anon-haiku-5-5-all/claude.jsonl`, and the pre-registered rule in `results/claude-low/BAND_RESULT.md`. The
pre-fix cascade is kept in `results/cascade-claude-low/` and
`results/cascade-gemini/`.

#### Skill names leaked the label, now fixed

MalSkillBench names generated skills with their gold label, for example
`1k-cross-platform__CI_B4`, and the first runs sent that name to every detector
as `skill.name`. 1,466 of the 3,214 generated skills carry the suffix; no benign
skill does. Since policy 4, `display_name` in `dataset.py` strips the
`__<VECTOR>_B<n>` segment before a state is built, and a scan of all 7,944
states finds no label token left. Those 1,466 skills were re-scored with Jev
(`results/anon-jev-labelled/`, $0.23), and the 21 of them now in the sample band
were re-run with both band models (`results/anon-band-*/`).

What the leak was worth, measured on the same skills:

- Jev: recall at 0.5 on the 1,466 went from 0.872 to 0.869 (7 skills gained, 11
  lost, mean absolute score change 0.008, close to run-to-run noise).
  Vector-label accuracy dropped from 0.785 to 0.755, so the name helped label
  the vector more than it helped detection.
- Opus: flagged 18 of the 18 previously-banded skills with and without the label.
- Gemini: flagged 18 of 18 with the label and 11 of 18 without. A control re-run
  with the labels put back flagged 21 of 21
  (`results/anon-band-gemini-control/`), so the drop comes from the name, not
  from noise. Gemini's pre-fix cascade recall of 0.898 was inflated; 0.882 is the
  clean figure.

Checks on the cascade:

- The 0.05 cutoff was read off the full-run reliability curve, which includes
  the 1,000 sample. On the 6,907 skills outside the sample, 3.9% of malicious
  skills score below 0.05 (4.2% in the sample) and the band is 19.1% of skills
  (17.4% in the sample), so the cutoff is not tuned to the sample. The curve
  did include these skills, so this is a consistency check, not a held-out test.
- Those sub-0.05 malicious skills (21 in the sample: 14 pi, 7 wild) never reach
  the LLM, which caps cascade recall near 0.96.
- Jev scores vary a little between identical requests. Two fresh passes over the
  sample, taken before the name fix (`results/repeat-strat1000-r1/`, `-r2/`), on
  963 comparable skills: 64% of scores identical, mean absolute difference
  0.005, largest 0.08, and 5 to 6 skills crossing 0.5. On those same 963 skills
  the pre-fix Opus cascade scores recall 0.942; re-scored on the two passes it
  gives 0.930 to 0.932, a lower bound, since 12 to 14 skills that moved into the
  band have no LLM verdict and count as passes.
- Claude Code routed some Opus 5 calls to secondary models (opus-4-8, haiku);
  each record lists the models that took part. Every Opus 5.5 and Haiku 5.5
  verdict came from the named model. Two Opus 5 refusals, one Opus 5.5 refusal,
  and one Gemini parse failure count as passes.
- Calls that failed before reaching the model (usage limits, no tokens billed)
  were retried until every band skill had a verdict or a refusal. Only the
  latest attempt per skill is scored.

### Jev alone, full set

Full benchmark run: all 7,944 skills (3,944 malicious, 4,000 benign), model
`jev-1.13.0`, threshold 0.5, one TypeSafe request per skill. Scored records in
`results/full-anon/`: the original run `results/20260921T095913Z-jev/` with the
1,466 name-leak skills replaced by their re-score (see above). The original run
keeps its `report.md`, charts, and run configuration in `meta.json`.

| arm | model | n | recall | FPR | precision | F1 | Brier | ECE |
|---|---|---|---|---|---|---|---|---|
| jev | jev-1.13.0 | 7,907 | 0.754 | 0.0008 | 0.999 | 0.860 | 0.096 | 0.126 |

Bootstrap 95% intervals at threshold 0.5: recall [0.740, 0.768], FPR [0.000,
0.002], Brier [0.090, 0.101], ECE [0.120, 0.133].

Recall by attack vector, at the default cutoff and at the tuned 0.09 threshold
(tuned on the held-out half; both columns scored on the full set). Vector-label
accuracy is 0.762. The wild row includes the 27 tool-test entries; wild alone
is 281 of 699 at 0.5 (0.402).

| vector | n | recall @0.5 | recall @0.09 | truncated |
|---|---|---|---|---|
| ci | 1,346 | 0.912 | 0.993 | 2 |
| mixed | 568 | 0.910 | 1.000 | 0 |
| pi | 1,300 | 0.712 | 0.885 | 1 |
| wild | 726 | 0.416 | 0.730 | 4 |

At the default 0.5 cutoff, 3 benign skills out of 4,000 are flagged and 968
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
| default 0.5 | 0.761 | 0.001 |
| tuned 0.09 | 0.916 | 0.049 |

Isotonic calibration fit on one half and scored on the other cuts ECE from 0.123
to 0.010 and Brier from 0.093 to 0.049. The ranking is strong and a
domain-specific threshold recovers most of the recall. The gain costs about 5%
FPR, so the operating point is a policy choice, not a free win, and the cascade
above gets similar recall without that cost.

Cost was $1.38 for the full set, $0.174 per 1,000 skills at $0.042 per Mtok input
with output free. p50 latency 391 ms, p95 669 ms, measured on the original run.

Known caveats to state in any write-up:

- 37 of 7,944 requests (0.5%) failed with `max_tokens_exceeded`: 33 benign and 4
  wild skills whose state plus JSON wrapper exceeded Jev's 32k context. They are
  excluded from the metrics. The default budget is now 28k with headroom, so a
  fresh run does not hit this.
- Truncation is a real confound, not a footnote: recall is 0.571 on the 84
  truncated skills in the scored set versus 0.755 on the intact ones. n is small,
  so the interval is wide, but the direction is consistent with the budget hiding
  malicious code.
- Model aliases move between releases. Pin an exact version, as this run does.
- The wild subset is narrow and dominated by one campaign. Do not present
  source-conditioned results as general.
- The only LLM run on every skill is Haiku 5.5, on the 1,000-skill sample; the
  other LLMs saw only the band. Full-set LLM baselines are MalSkillBench's
  published numbers, cited, not rerun.
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
.venv/bin/jev-skillbench cascade  --jev-records results/samples/strat1000_anon.jsonl \
    --llm-records results/anon-band-claude/merged.jsonl --t-low 0.05 --t-high 0.5 \
    --run-dir results/cascade-anon-claude
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
