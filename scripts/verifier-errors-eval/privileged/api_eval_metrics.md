# API Evaluation Metrics Plan

This file describes the metrics to capture when model APIs are used to repair
the public BPF verifier prompt packets. It is privileged because it sits next
to the answer key and model-routing notes; do not include it in model prompts.

## Goal

For each `(case, prompt_variant, model_profile)` run, capture enough data to
quantify:

- Dollar cost.
- Prompt and completion token load.
- Reasoning or thinking burden, when exposed by the provider.
- Latency and failure modes.
- Whether the final answer is useful enough to repair the verifier error.

The public prompt variants remain:

- `legacy`: source plus old verifier log.
- `diagnostic`: source plus improved verifier diagnostics.

## Per-Run Record

Each raw result row should contain:

- `run_id`: stable unique ID.
- `case_id`: public case ID, for example `case-014`.
- `variant`: `legacy` or `diagnostic`.
- `provider`: `openai`, `anthropic`, `kimi`, or `openrouter`.
- `model`: provider-native model ID.
- `profile`: model-profile ID from `api_model_matrix.json`.
- `reasoning_profile`: configured effort, thinking mode, or thinking budget.
- `prompt_sha256`: hash of the exact prompt sent to the model.
- `prompt_bytes`: byte length of the exact prompt.
- `started_at`, `finished_at`, `wall_time_ms`.
- `status`: `ok`, `api_error`, `timeout`, `rate_limited`, `truncated`, or
  `invalid_response`.
- `stop_reason`: provider-native stop reason when available.
- `retry_count`.
- `raw_response_path`: path to the redacted raw response artifact.
- `answer_text_path`: path to the extracted final answer.

## Token Metrics

Capture provider-native token counters without normalizing them away:

- `input_tokens`: prompt/input tokens.
- `cached_input_tokens`: cached prompt tokens, if exposed.
- `cache_write_input_tokens`: cache-write tokens, if exposed.
- `output_tokens`: all generated output tokens billed by the provider.
- `visible_output_tokens`: final answer tokens, if separately measurable.
- `reasoning_tokens`: reasoning/thinking tokens, if the API exposes them.
- `total_tokens`: provider total, if exposed.

Reasoning-token availability differs by provider:

- OpenAI Responses API exposes `output_tokens_details.reasoning_tokens`.
- Anthropic exposes usage tokens, and thinking blocks may be part of output
  token usage. Keep the native usage object and any thinking block metadata.
- Kimi exposes `reasoning_content` for thinking models. Count its characters
  and save the field separately; use provider usage for billing tokens.
- OpenRouter may expose reasoning tokens directly in `usage`, and its
  generation-stats endpoint can provide normalized token and cost data.

## Cost Metrics

Compute cost from the route-specific pricing in `api_model_matrix.json`:

- `input_cost_usd`.
- `cached_input_cost_usd`.
- `cache_write_cost_usd`.
- `output_cost_usd`.
- `total_cost_usd`.
- `pricing_source`.
- `pricing_checked_at`.

Reasoning tokens should not be charged separately unless the provider says so.
For OpenAI and most OpenRouter routes, reasoning tokens are counted inside
output/completion tokens. For Kimi, `reasoning_content` consumes quota and is
included in normal usage.

## Effort Proxies

Use these as rough proxies for how hard the model worked:

- `reasoning_tokens`.
- `reasoning_content_chars`.
- `output_tokens`.
- `wall_time_ms`.
- `truncated` or incomplete status.
- `retry_count`.
- `answer_chars`.
- Later grader score: exact repair, close repair, useful explanation only, or
  wrong/unhelpful.

## API Constraints

The prompt should explicitly forbid internet access, verifier access, running
commands, or inspecting hidden answer files. For API-only runs, enforce that by
not providing tools, files, browsing, or command execution. The model only gets
the public prompt text.

Grading is performed locally by Codex from saved answer packets and the
privileged answer key. No API keys should be used for grading.
