# Results: jev (jev-1.13.0)

Threshold 0.5.

## Overall

| arm | model | threshold | recall | fpr | precision | f1 | brier | ece |
|---|---|---|---|---|---|---|---|---|
| jev | jev-1.13.0 | 0.500 | 0.755 | 0.001 | 0.999 | 0.860 | 0.096 | 0.126 |

## Bootstrap intervals

| metric | point | 95% CI |
|---|---|---|
| recall | 0.755 | [0.742, 0.770] |
| fpr | 0.001 | [0.000, 0.002] |
| brier | 0.096 | [0.090, 0.102] |
| ece | 0.126 | [0.120, 0.133] |

## Recall by attack vector

| arm | threshold | ci | pi | mixed | wild | n |
|---|---|---|---|---|---|---|
| jev | 0.500 | 0.914 (1230/1346) | 0.715 (930/1300) | 0.905 (514/568) | 0.416 (302/726) | 7907 |

## Truncation split

| group | n | recall | FPR | precision |
|---|---|---|---|---|
| truncated | 84 | 0.571 | 0.000 | 1.000 |
| intact | 7823 | 0.756 | 0.001 | 0.999 |

## Calibration

| bin | n | mean confidence | empirical rate | gap |
|---|---|---|---|---|
| 0.0-0.1 | 4206 | 0.032 | 0.093 | -0.061 |
| 0.1-0.2 | 346 | 0.140 | 0.645 | -0.504 |
| 0.2-0.3 | 126 | 0.234 | 0.873 | -0.639 |
| 0.3-0.4 | 120 | 0.349 | 0.942 | -0.593 |
| 0.4-0.5 | 130 | 0.444 | 0.969 | -0.525 |
| 0.5-0.6 | 146 | 0.547 | 0.986 | -0.439 |
| 0.6-0.7 | 163 | 0.649 | 0.994 | -0.345 |
| 0.7-0.8 | 269 | 0.747 | 1.000 | -0.253 |
| 0.8-0.9 | 502 | 0.852 | 1.000 | -0.148 |
| 0.9-1.0 | 1899 | 0.956 | 1.000 | -0.044 |

Brier: 0.096  
ECE: 0.126

## Latency and cost

p50 391.1 ms, p95 668.9 ms, cost per 1k skills 0.1742

## Held-out calibration

Fit n=3955, eval n=3952, target FPR 0.05.

| operating point | recall | FPR | precision |
|---|---|---|---|
| default 0.5 | 0.763 | 0.001 | 0.999 |
| tuned 0.090 | 0.916 | 0.049 | 0.949 |

Brier raw 0.093 to isotonic 0.049. ECE raw 0.123 to isotonic 0.010.
