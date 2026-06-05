# API Model Matrix

This is the initial API-only model set for the verifier repair evaluation.
Prices were checked on 2026-06-05 and are per 1M tokens unless noted.

The local key file advertises provider hints for OpenAI, Claude, Kimi, and
OpenRouter. Anthropic direct profiles are therefore runnable once the API runner
maps the `Claude:` label to an Anthropic API key environment variable.

## Metrics

For every `(case, variant, model profile)` call, record the metrics in
`api_eval_metrics.md`: input tokens, cached input tokens, output tokens,
reasoning/thinking tokens when exposed, reasoning-content size when only text
is exposed, wall time, stop reason, truncation, retry count, and computed cost.

## Primary Profiles

The `full` run set contains these 20 profiles. Each profile is run once against
both prompt variants for each public case unless the runner is explicitly
filtered.

| Profile | Route | Model | Effort or thinking | Input | Cached/read | Output |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `openai-gpt-5.5-none` | OpenAI Responses | `gpt-5.5` | `reasoning.effort=none` | $5.00 | $0.50 | $30.00 |
| `openai-gpt-5.5-low` | OpenAI Responses | `gpt-5.5` | `reasoning.effort=low` | $5.00 | $0.50 | $30.00 |
| `openai-gpt-5.5-medium` | OpenAI Responses | `gpt-5.5` | `reasoning.effort=medium` | $5.00 | $0.50 | $30.00 |
| `openai-gpt-5.5-high` | OpenAI Responses | `gpt-5.5` | `reasoning.effort=high` | $5.00 | $0.50 | $30.00 |
| `openai-gpt-5.5-xhigh` | OpenAI Responses | `gpt-5.5` | `reasoning.effort=xhigh` | $5.00 | $0.50 | $30.00 |
| `openai-gpt-5.3-codex-medium` | OpenAI Responses | `gpt-5.3-codex` | `reasoning.effort=medium` | $1.75 | $0.175 | $14.00 |
| `openai-gpt-5.3-codex-high` | OpenAI Responses | `gpt-5.3-codex` | `reasoning.effort=high` | $1.75 | $0.175 | $14.00 |
| `openai-gpt-5.3-codex-xhigh` | OpenAI Responses | `gpt-5.3-codex` | `reasoning.effort=xhigh` | $1.75 | $0.175 | $14.00 |
| `kimi-k2.6-thinking` | Kimi direct | `kimi-k2.6` | `thinking=enabled` | $0.95 | $0.16 | $4.00 |
| `kimi-k2.6-no-thinking` | Kimi direct | `kimi-k2.6` | `thinking=disabled` | $0.95 | $0.16 | $4.00 |
| `openrouter-claude-opus-4.8-high` | OpenRouter | `anthropic/claude-opus-4.8` | `reasoning.effort=high` | $5.00 | n/a | $25.00 |
| `openrouter-claude-sonnet-4.6-medium` | OpenRouter | `anthropic/claude-sonnet-4.6` | `reasoning.effort=medium` | $3.00 | n/a | $15.00 |
| `openrouter-claude-haiku-4.5-default` | OpenRouter | `anthropic/claude-haiku-4.5` | default | $1.00 | n/a | $5.00 |
| `openrouter-deepseek-r1-0528` | OpenRouter | `deepseek/deepseek-r1-0528` | `reasoning.effort=high` | $0.50 | n/a | $2.15 |
| `openrouter-deepseek-v3.2` | OpenRouter | `deepseek/deepseek-v3.2` | `reasoning.effort=medium` | $0.2288 | n/a | $0.3432 |
| `openrouter-qwen3-coder` | OpenRouter | `qwen/qwen3-coder` | default | $0.22 | n/a | $1.80 |
| `openrouter-glm-5.1-high` | OpenRouter | `z-ai/glm-5.1` | `reasoning.effort=high` | $0.98 | n/a | $3.08 |

## Anthropic Direct Profiles

These are present in `api_model_matrix.json` and should be runnable through the
local `Claude:` key label:

| Profile | Model | Effort | Input | Cache write 5m | Cache read | Output |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `anthropic-opus-4.8-medium` | `claude-opus-4-8` | medium + adaptive thinking | $5.00 | $6.25 | $0.50 | $25.00 |
| `anthropic-opus-4.8-high` | `claude-opus-4-8` | high + adaptive thinking | $5.00 | $6.25 | $0.50 | $25.00 |
| `anthropic-opus-4.8-xhigh` | `claude-opus-4-8` | xhigh + adaptive thinking | $5.00 | $6.25 | $0.50 | $25.00 |
| `anthropic-sonnet-4.6-medium` | `claude-sonnet-4-6` | medium + adaptive thinking | $3.00 | $3.75 | $0.30 | $15.00 |
| `anthropic-sonnet-4.6-high` | `claude-sonnet-4-6` | high + adaptive thinking | $3.00 | $3.75 | $0.30 | $15.00 |
| `anthropic-haiku-4.5-default` | `claude-haiku-4-5` | default | $1.00 | $1.25 | $0.10 | $5.00 |

## Source Notes

- OpenAI GPT-5.5 supports `none`, `low`, `medium`, `high`, and `xhigh`
  reasoning efforts. Its standard short-context price is $5 input, $0.50
  cached input, and $30 output.
- OpenAI GPT-5.3-Codex is the current Codex-optimized API model in this
  matrix. It supports `low`, `medium`, `high`, and `xhigh` reasoning efforts.
- Anthropic Opus 4.8, Sonnet 4.6, and Haiku 4.5 are the current family entries
  for the requested Opus/Sonnet/Haiku spread. Opus and Sonnet use the effort
  parameter; Haiku is kept as a default profile because effort is not
  documented for Haiku.
- Kimi direct exposes `kimi-k2.6` with `thinking` enabled by default and a
  `thinking=disabled` option. The older dedicated `kimi-k2-thinking` route
  returned 404 with the local key, so it is documented in JSON but excluded
  from the default full run set.
- OpenRouter prices and supported parameters were pulled from
  `https://openrouter.ai/api/v1/models`; they should be refreshed before a
  final benchmark run.
- Kimi is intentionally not repeated through OpenRouter; direct Kimi is the
  canonical Kimi route for this evaluation.
