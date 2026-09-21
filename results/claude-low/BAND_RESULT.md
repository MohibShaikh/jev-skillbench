# Band rescue test: Claude Opus 5 through Claude Code

Pre-registered rule (frozen before the run): cascade is worth building if the LLM
catches >=30 of the 100 in-band malicious while flagging <=7 of the 71 in-band
benign. Thresholds fixed at t_low=0.05, t_high=0.5.

Band: 171 items from a 1,000-skill stratified sample, Jev score in [0.05, 0.5).
Model: claude-opus-5 via `claude -p`, effort low, tools and user settings stripped.
Result: caught 94/98 evaluated (94/100 counting 2 refusals as misses), flagged 4/71.
Rule passed. Cost $19.56 subscription-equivalent, ~$0.114 per band skill.

Failures: 31 transient `exit 1` (usage limit), all recovered on retry; 2 refusals.
Harness routes across models (opus-5 dominant, secondary opus-4-8 and haiku).
