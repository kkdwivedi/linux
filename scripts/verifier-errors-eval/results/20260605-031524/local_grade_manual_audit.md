# Local Manual Grade Audit

Run: `20260605-031524`

This audit reviewed the local regex/rule grades for false positives. I inspected
all graded rows case-by-case through per-case answer excerpts and opened full
answers for suspicious or borderline rows. Manual overrides were appended with
`verifier_errors_eval.py record-grade`; the summary/report CSVs use the latest
grade for each `(profile, case, variant)` tuple.

## Grade Policy

- Score 4: minimal intended fix or equivalent verifier-passing patch.
- Score 3: verifier-relevant source fix that is likely useful but imprecise,
  incomplete in patch detail, or not the preferred robust form.
- Score 2: correct broad cause but concrete fix is unsafe, verifier-insufficient,
  solves the wrong task, or likely still fails.

## Post-Audit Distribution

- Graded answers: 777
- Score 4: 601
- Score 3: 154
- Score 2: 22
- Successes (`score >= 3`): 755
- Diagnostic prompts: 319 score-4, 60 score-3, 11 score-2
- Legacy prompts: 282 score-4, 94 score-3, 11 score-2

## Downgrade Classes

- Case 001, invalid cpumask destination: downgraded answers that marked the
  selftest as an expected failure instead of repairing the verifier rejection, or
  replaced the bogus pointer with an undersized stack object.
- Case 002, cpumask reference leak: downgraded a Kimi diagnostic answer whose
  reasoning found the ownership leak, but whose primary patch released
  unguarded and then used the pointer.
- Case 009, task acquire kfunc argument: downgraded direct `value->task` checks
  followed by `bpf_task_acquire(value->task)`. The robust repair loads the kptr
  once into a temporary, checks that temporary, and passes the same checked value
  to the kfunc.
- Case 013, combined stack depth: downgraded `MAX_STACK = 256` thresholds where
  the observed verifier accounting (`260 -> 544` combined bytes) indicates that
  256 is still too tight, and downgraded one patch that made the source
  out-of-bounds by changing only one buffer while keeping `MAX_STACK - 1`.
- Case 014, map-value variable offset: downgraded the off-by-one `if r3 > 48`
  bound, which leaves offset 48 reachable for a one-byte access in a 48-byte
  object.
- Case 016, socket reference leak: downgraded patches that still left a leaking
  branch, released only one mark path, or called `bpf_sk_release` on
  `sock_or_null` without proving non-NULL.
- Case 020, liveness complexity limit: downgraded fanout/depth changes that
  still exceeded the 10001 liveness budget, such as `CALLS_10`, `CALLS_20`,
  `CALLS_5` over the full depth, removing only one helper level, or reducing
  only the entry fanout.

The corrected aggregate report is in `summary.md`; the row-level current grades
are in `reports/grades.csv`.
