# BPF Verifier AI Repair Evaluation Results

Generated: 2026-06-05T04:55:16+00:00

## Solver Calls

- Runs: 800
- Successful API responses: 777
- Status counts: api_error=2, invalid_response=3, missing=1, ok=777, timeout=17
- Solver API cost: $24.3916
- Mean solver cost per response: $0.03139
- Median solver cost per response: $0.01724
- P95 solver cost per response: $0.13321
- Input tokens: 956,263
- Output tokens: 1,450,774
- Reasoning tokens: 637,281
- Median wall time: 18932 ms
- P95 wall time: 153894 ms

## Graded Repair Quality

- Graded answers: 777
- Successes: 755
- Success rate: 97.2%
- Mean score: 3.75 / 4
- Median score: 4.00 / 4
- Grader cost: $0.0000 (local rule-based Codex grading)

## Legacy Vs Diagnostic

| Variant | Responses | Solver cost | Output tokens | Reasoning tokens | Median wall ms | Graded answers | Success rate | Mean score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| diagnostic | 390 | $11.2223 | 664,096 | 297,070 | 18468 | 390 | 97.2% | 3.79 |
| legacy | 387 | $13.1693 | 786,678 | 340,211 | 19816 | 387 | 97.2% | 3.70 |

## Cost And Effort By Model Profile

| Profile | Variant | Responses | Cost | Median cost | Output tokens | Reasoning tokens | Median wall ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `anthropic-haiku-4.5-default` | diagnostic | 20 | $0.0872 | $0.00390 | 11,352 | 0 | 4994 |
| `anthropic-haiku-4.5-default` | legacy | 20 | $0.0812 | $0.00365 | 11,620 | 0 | 5043 |
| `anthropic-opus-4.8-high` | diagnostic | 20 | $0.8195 | $0.03832 | 25,462 | 0 | 15482 |
| `anthropic-opus-4.8-high` | legacy | 20 | $1.1922 | $0.04292 | 42,162 | 0 | 17518 |
| `anthropic-opus-4.8-medium` | diagnostic | 20 | $0.8696 | $0.03387 | 27,468 | 0 | 12709 |
| `anthropic-opus-4.8-medium` | legacy | 20 | $1.0014 | $0.03335 | 34,530 | 0 | 13389 |
| `anthropic-sonnet-4.6-high` | diagnostic | 20 | $0.8243 | $0.02583 | 48,863 | 0 | 21618 |
| `anthropic-sonnet-4.6-high` | legacy | 20 | $1.1814 | $0.03065 | 74,140 | 0 | 24407 |
| `anthropic-sonnet-4.6-medium` | diagnostic | 20 | $0.2776 | $0.01025 | 12,414 | 0 | 6608 |
| `anthropic-sonnet-4.6-medium` | legacy | 20 | $0.4199 | $0.01435 | 23,370 | 0 | 12312 |
| `kimi-k2.6-no-thinking` | diagnostic | 20 | $0.1184 | $0.00391 | 23,798 | 0 | 35840 |
| `kimi-k2.6-no-thinking` | legacy | 19 | $0.1149 | $0.00423 | 24,976 | 0 | 39048 |
| `kimi-k2.6-thinking` | diagnostic | 13 | $0.2106 | $0.01753 | 49,218 | 0 | 128257 |
| `kimi-k2.6-thinking` | legacy | 11 | $0.1974 | $0.01558 | 47,676 | 0 | 138303 |
| `openai-gpt-5.3-codex-high` | diagnostic | 20 | $0.6008 | $0.02548 | 39,815 | 33,897 | 24986 |
| `openai-gpt-5.3-codex-high` | legacy | 20 | $0.5625 | $0.02709 | 37,813 | 31,618 | 27099 |
| `openai-gpt-5.3-codex-medium` | diagnostic | 20 | $0.2872 | $0.01240 | 17,541 | 11,381 | 13476 |
| `openai-gpt-5.3-codex-medium` | legacy | 20 | $0.3178 | $0.01338 | 20,334 | 13,746 | 13616 |
| `openai-gpt-5.5-high` | diagnostic | 20 | $2.3561 | $0.08618 | 74,402 | 65,185 | 56784 |
| `openai-gpt-5.5-high` | legacy | 19 | $2.6130 | $0.14327 | 84,041 | 75,369 | 98065 |
| `openai-gpt-5.5-low` | diagnostic | 20 | $0.6863 | $0.03251 | 18,743 | 8,455 | 21338 |
| `openai-gpt-5.5-low` | legacy | 20 | $0.6641 | $0.03042 | 18,985 | 9,731 | 21683 |
| `openai-gpt-5.5-medium` | diagnostic | 19 | $1.3532 | $0.05458 | 41,125 | 31,800 | 37404 |
| `openai-gpt-5.5-medium` | legacy | 20 | $1.6016 | $0.07590 | 50,236 | 41,004 | 56096 |
| `openai-gpt-5.5-none` | diagnostic | 20 | $0.4571 | $0.02280 | 11,102 | 0 | 10414 |
| `openai-gpt-5.5-none` | legacy | 20 | $0.4163 | $0.01835 | 10,727 | 0 | 10873 |
| `openrouter-claude-haiku-4.5-default` | diagnostic | 20 | $0.0857 | $0.00392 | 11,046 | 0 | 5342 |
| `openrouter-claude-haiku-4.5-default` | legacy | 20 | $0.0789 | $0.00346 | 11,155 | 0 | 5164 |
| `openrouter-claude-opus-4.8-high` | diagnostic | 20 | $1.0177 | $0.03840 | 33,391 | 2,067 | 14876 |
| `openrouter-claude-opus-4.8-high` | legacy | 20 | $1.3836 | $0.03849 | 49,816 | 3,039 | 17155 |
| `openrouter-claude-sonnet-4.6-medium` | diagnostic | 19 | $0.8569 | $0.02457 | 51,392 | 11,637 | 20392 |
| `openrouter-claude-sonnet-4.6-medium` | legacy | 19 | $1.0281 | $0.02404 | 64,543 | 15,477 | 20252 |
| `openrouter-deepseek-r1-0528` | diagnostic | 20 | $0.1451 | $0.00586 | 61,498 | 53,792 | 98270 |
| `openrouter-deepseek-r1-0528` | legacy | 20 | $0.1489 | $0.00680 | 64,628 | 57,538 | 92478 |
| `openrouter-deepseek-v3.2` | diagnostic | 19 | $0.0278 | $0.00125 | 64,232 | 58,110 | 87333 |
| `openrouter-deepseek-v3.2` | legacy | 20 | $0.0301 | $0.00145 | 74,331 | 67,766 | 98258 |
| `openrouter-glm-5.1-high` | diagnostic | 20 | $0.1130 | $0.00400 | 28,791 | 20,746 | 19312 |
| `openrouter-glm-5.1-high` | legacy | 19 | $0.1146 | $0.00387 | 32,052 | 24,923 | 30390 |
| `openrouter-qwen3-coder` | diagnostic | 20 | $0.0282 | $0.00134 | 12,443 | 0 | 7097 |
| `openrouter-qwen3-coder` | legacy | 20 | $0.0216 | $0.00096 | 9,543 | 0 | 5420 |

## By Category And Prompt Variant

| Category | Variant | Answers | Success rate | Mean score |
| --- | --- | ---: | ---: | ---: |
| Call Type Safety | diagnostic | 59 | 98.3% | 3.78 |
| Call Type Safety | legacy | 58 | 94.8% | 3.66 |
| Execution Context Safety | diagnostic | 40 | 100.0% | 4.00 |
| Execution Context Safety | legacy | 39 | 100.0% | 4.00 |
| Memory Safety | diagnostic | 40 | 100.0% | 3.58 |
| Memory Safety | legacy | 39 | 97.4% | 3.64 |
| Policy | diagnostic | 20 | 100.0% | 3.75 |
| Policy | legacy | 20 | 100.0% | 3.10 |
| Program Structure | diagnostic | 20 | 100.0% | 4.00 |
| Program Structure | legacy | 20 | 100.0% | 3.45 |
| Register Type Safety | diagnostic | 77 | 100.0% | 3.86 |
| Register Type Safety | legacy | 78 | 100.0% | 3.87 |
| Resource Lifetime Safety | diagnostic | 98 | 96.9% | 3.81 |
| Resource Lifetime Safety | legacy | 98 | 98.0% | 3.72 |
| Verifier Limit | diagnostic | 36 | 80.6% | 3.53 |
| Verifier Limit | legacy | 35 | 85.7% | 3.54 |

## By Difficulty And Prompt Variant

| Difficulty | Variant | Answers | Success rate | Mean score |
| --- | --- | ---: | ---: | ---: |
| easy | diagnostic | 117 | 99.1% | 3.91 |
| easy | legacy | 119 | 97.5% | 3.67 |
| hard | diagnostic | 136 | 93.4% | 3.79 |
| hard | legacy | 134 | 94.0% | 3.69 |
| medium | diagnostic | 137 | 99.3% | 3.69 |
| medium | legacy | 134 | 100.0% | 3.74 |

## By Model Profile And Prompt Variant

| Profile | Variant | Answers | Success rate | Mean score | Solver cost |
| --- | --- | ---: | ---: | ---: | ---: |
| `anthropic-haiku-4.5-default` | diagnostic | 20 | 90.0% | 3.70 | $0.0872 |
| `anthropic-haiku-4.5-default` | legacy | 20 | 90.0% | 3.35 | $0.0812 |
| `anthropic-opus-4.8-high` | diagnostic | 20 | 100.0% | 3.90 | $0.8195 |
| `anthropic-opus-4.8-high` | legacy | 20 | 90.0% | 3.60 | $1.1922 |
| `anthropic-opus-4.8-medium` | diagnostic | 20 | 95.0% | 3.85 | $0.8696 |
| `anthropic-opus-4.8-medium` | legacy | 20 | 95.0% | 3.80 | $1.0014 |
| `anthropic-sonnet-4.6-high` | diagnostic | 20 | 95.0% | 3.75 | $0.8243 |
| `anthropic-sonnet-4.6-high` | legacy | 20 | 100.0% | 3.75 | $1.1814 |
| `anthropic-sonnet-4.6-medium` | diagnostic | 20 | 100.0% | 3.65 | $0.2776 |
| `anthropic-sonnet-4.6-medium` | legacy | 20 | 95.0% | 3.60 | $0.4199 |
| `kimi-k2.6-no-thinking` | diagnostic | 20 | 100.0% | 3.85 | $0.1184 |
| `kimi-k2.6-no-thinking` | legacy | 19 | 100.0% | 3.84 | $0.1149 |
| `kimi-k2.6-thinking` | diagnostic | 13 | 100.0% | 3.62 | $0.2106 |
| `kimi-k2.6-thinking` | legacy | 11 | 100.0% | 3.64 | $0.1974 |
| `openai-gpt-5.3-codex-high` | diagnostic | 20 | 100.0% | 3.80 | $0.6008 |
| `openai-gpt-5.3-codex-high` | legacy | 20 | 100.0% | 3.85 | $0.5625 |
| `openai-gpt-5.3-codex-medium` | diagnostic | 20 | 95.0% | 3.80 | $0.2872 |
| `openai-gpt-5.3-codex-medium` | legacy | 20 | 100.0% | 3.75 | $0.3178 |
| `openai-gpt-5.5-high` | diagnostic | 20 | 100.0% | 3.90 | $2.3561 |
| `openai-gpt-5.5-high` | legacy | 19 | 100.0% | 3.79 | $2.6130 |
| `openai-gpt-5.5-low` | diagnostic | 20 | 100.0% | 3.90 | $0.6863 |
| `openai-gpt-5.5-low` | legacy | 20 | 100.0% | 3.75 | $0.6641 |
| `openai-gpt-5.5-medium` | diagnostic | 19 | 100.0% | 3.84 | $1.3532 |
| `openai-gpt-5.5-medium` | legacy | 20 | 100.0% | 3.75 | $1.6016 |
| `openai-gpt-5.5-none` | diagnostic | 20 | 95.0% | 3.85 | $0.4571 |
| `openai-gpt-5.5-none` | legacy | 20 | 95.0% | 3.80 | $0.4163 |
| `openrouter-claude-haiku-4.5-default` | diagnostic | 20 | 90.0% | 3.70 | $0.0857 |
| `openrouter-claude-haiku-4.5-default` | legacy | 20 | 90.0% | 3.65 | $0.0789 |
| `openrouter-claude-opus-4.8-high` | diagnostic | 20 | 100.0% | 3.90 | $1.0177 |
| `openrouter-claude-opus-4.8-high` | legacy | 20 | 95.0% | 3.70 | $1.3836 |
| `openrouter-claude-sonnet-4.6-medium` | diagnostic | 19 | 100.0% | 3.79 | $0.8569 |
| `openrouter-claude-sonnet-4.6-medium` | legacy | 19 | 100.0% | 3.74 | $1.0281 |
| `openrouter-deepseek-r1-0528` | diagnostic | 20 | 100.0% | 3.75 | $0.1451 |
| `openrouter-deepseek-r1-0528` | legacy | 20 | 95.0% | 3.65 | $0.1489 |
| `openrouter-deepseek-v3.2` | diagnostic | 19 | 100.0% | 3.79 | $0.0278 |
| `openrouter-deepseek-v3.2` | legacy | 20 | 100.0% | 3.60 | $0.0301 |
| `openrouter-glm-5.1-high` | diagnostic | 20 | 95.0% | 3.75 | $0.1130 |
| `openrouter-glm-5.1-high` | legacy | 19 | 100.0% | 3.63 | $0.1146 |
| `openrouter-qwen3-coder` | diagnostic | 20 | 90.0% | 3.65 | $0.0282 |
| `openrouter-qwen3-coder` | legacy | 20 | 100.0% | 3.75 | $0.0216 |

Detailed CSV exports are in `reports/runs.csv` and `reports/grades.csv`.
