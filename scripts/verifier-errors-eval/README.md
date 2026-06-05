# BPF Verifier Error Repair Evaluation

This directory contains a self-contained API evaluation for testing whether
improved verifier diagnostics help models repair failing BPF verifier cases
from source plus verifier log alone.

The public packets are safe to send to models:

- `public/manifest.json`
- `public/case-*/source.c`
- `public/case-*/prompt_legacy.md`
- `public/case-*/prompt_diagnostic.md`

The privileged directory is not sent to solver models:

- `privileged/cases.md`
- `privileged/answer_key.md`
- `privileged/answer_key.json`
- `privileged/api_model_matrix.md`
- `privileged/api_model_matrix.json`

## Model Set

The default `full` run set contains:

- OpenAI `gpt-5.5`: `none`, `low`, `medium`, `high`.
- OpenAI `gpt-5.3-codex`: `medium`, `high`.
- Anthropic `claude-opus-4-8`: `medium`, `high`.
- Anthropic `claude-sonnet-4-6`: `medium`, `high`.
- Anthropic `claude-haiku-4-5`: default.
- Kimi direct `kimi-k2.6`: thinking enabled and disabled.
- OpenRouter Claude comparison routes for Opus, Sonnet, and Haiku.
- OpenRouter `deepseek/deepseek-r1-0528`.
- OpenRouter `deepseek/deepseek-v3.2`.
- OpenRouter `qwen/qwen3-coder`.
- OpenRouter `z-ai/glm-5.1`.

Kimi is intentionally not repeated through OpenRouter. The older direct
`kimi-k2-thinking` route returned 404 with the local key during validation, so
the default full set uses `kimi-k2.6` thinking enabled/disabled instead.

## Metrics

The runner keeps raw provider responses and writes normalized rows. Metrics
include:

- Input tokens.
- Cached/read input tokens, when exposed.
- Cache write tokens, when exposed.
- Output tokens.
- Reasoning tokens, when exposed.
- Reasoning-content character count, when reasoning text is exposed.
- Wall time.
- Stop reason.
- Per-call computed cost.
- Provider raw usage object.
- Grader score, success flag, and feedback.

## Commands

List the selected model set:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py list-models --run-set full
```

Estimate rough input-token cost:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py estimate --run-set full
```

Run the API calls:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py run --run-set full --workers 2
```

For the final run, use a five-minute per-call timeout and enough parallelism to
exercise all providers without serializing the whole matrix:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py run --run-set full \
  --workers 64 --timeout-seconds 300
```

For smoke/debug runs only, a temporary output cap can reduce wasted spend while
checking provider payloads:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py run --run-set smoke \
  --cases case-001 --solver-max-output-tokens 4096 --timeout-seconds 300
```

Do not use that cap for the final evaluation unless the cap itself is part of
the experimental design.

Prepare local grading packets. This does not call any model API:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py grade \
  scripts/verifier-errors-eval/results/<run-dir>
```

Record local Codex grades after reviewing the packet and answer:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py record-grade \
  scripts/verifier-errors-eval/results/<run-dir> \
  --profile openai-gpt-5.5-medium --case case-001 --variant diagnostic \
  --score 4 --verdict "Identifies scalar-as-pointer destination and fixes it."
```

Produce summary files:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py summarize \
  scripts/verifier-errors-eval/results/<run-dir>
```

The key file defaults to `API_KEYS.md` in the repository root. Keys are read
locally and are never written to results.

Rerun only failed or missing rows in an existing result directory:

```sh
scripts/verifier-errors-eval/verifier_errors_eval.py run --run-set full \
  --out-dir scripts/verifier-errors-eval/results/<run-dir> \
  --only-failed --workers 4 --timeout-seconds 300
```
