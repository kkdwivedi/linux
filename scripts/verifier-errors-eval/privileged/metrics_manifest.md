# Cost And Effort Metrics

The evaluation stores raw provider responses first and derives summaries from
those raw files. This avoids losing provider-specific usage details.

## Solver Metrics

Per solver response:

- `input_tokens`: provider-reported prompt/input tokens.
- `cached_input_tokens`: cached/read input tokens when exposed.
- `cache_write_input_tokens`: cache creation tokens when exposed.
- `output_tokens`: provider-reported generated tokens.
- `reasoning_tokens`: provider-reported reasoning/thinking tokens when exposed.
- `reasoning_content_chars`: size of exposed reasoning text when the provider
  returns reasoning as text but not as a token counter.
- `total_tokens`: provider-reported total tokens when exposed.
- `wall_time_ms`: end-to-end client wall time.
- `stop_reason`: provider-native stop reason.
- `answer_chars`: extracted final-answer size.
- `total_cost_usd`: route-specific computed cost from the model matrix.
- `raw_usage`: complete provider-native usage object.

## Local Grader Metrics

Per graded response:

- `score`: integer 0 to 4.
- `success`: true when `score >= 3`.
- `verdict`: short grader explanation.
- Grader token and cost fields are zero because grading is performed locally by
  Codex from saved answer packets, not by a paid API call.

## Derived Metrics

The summary reports:

- Totals for tokens and cost.
- Mean, median, p90, and p95 for cost, output tokens, reasoning tokens, and
  wall time.
- Success rate and mean/median score by profile, prompt variant, category, and
  difficulty.

The intended interpretation is:

- Lower input/output/reasoning tokens and lower wall time indicate less model
  effort.
- Higher success rate and score indicate better repair usefulness.
- Comparing `legacy` and `diagnostic` for the same case/model isolates the
  value of the improved verifier message.
