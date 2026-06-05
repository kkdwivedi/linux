You are given one failing eBPF verifier case.

Constraints:
- Do not use tools.
- Do not search the internet.
- Do not run the verifier.
- Do not assume access to any file other than the source and verifier log below.

Task:
Explain the verifier failure and propose the smallest source-level fix that is
likely to make the program pass verification. If a complete patch is clear,
provide it. Otherwise describe the exact edit and why it should satisfy the
verifier.

Source:
```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

int __noinline helper_a(int i)
{
	char data[8];

	if (!i)
		bpf_copy_from_user(data, sizeof(data), NULL);
	return i;
}

SEC("?syscall")
int entry(void *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	helper_a(0);
	bpf_local_irq_restore(&flags);
	return 0;
}
```

Verifier log:
```text
arg#0 reference type('UNKNOWN ') size cannot be determined: -22
0: R1=ctx() R10=fp0
; int entry(void *ctx) @ case.c:494
0: (bf) r6 = r10                      ; R6=fp0 R10=fp0
1: (07) r6 += -8                      ; R6=fp-8
; bpf_local_irq_save(&flags); @ case.c:498
2: (bf) r1 = r6                       ; R1=fp-8 R6=fp-8
3: (85) call bpf_local_irq_save#62776         ; fp-8=ffffffff refs=1
; helper_a(0); @ case.c:499
4: (b4) w1 = 0                        ; R1=0 refs=1
5: (85) call pc+4
sleepable global function helper_a() called in IRQ-disabled region

Verification failed: Execution Context Safety: Operation is not allowed in this context

Reason:
  The operation sleepable global function helper_a() cannot be used in IRQ-disabled region
  because IRQ-disabled code cannot call operations that may sleep. This path is still inside an active IRQ-disabled
  region (depth 1).

At:
  entry @ case.c:499:2
      497 | ...                                                                                   3 | (85) call bpf_local_irq_save#62776
      498 |         bpf_local_irq_save(&flags);                                                   4 | (b4) w1 = 0
  >>> 499 |         helper_a(0);                                      >>>  5 | (85) call pc+4
          |         ^-- error: sleepable global function helper_a() is not allowed in
          |             IRQ-disabled region
      500 |         bpf_local_irq_restore(&flags);                                                6 | (bf) r1 = r6
      501 |         return 0;                                                                     7 | (85) call bpf_local_irq_restore#62775

Causal path:
  entry @ case.c:498:2
      496 | ...                                                                                   1 | (07) r6 += -8
      497 | ...                                                                                   2 | (bf) r1 = r6
  >>> 498 |         bpf_local_irq_save(&flags);                                              >>>  3 | (85) call bpf_local_irq_save#62776
          |         ^-- context: entered IRQ-disabled region; depth is now 1
      499 |         helper_a(0);                                           4 | (b4) w1 = 0
      500 |         bpf_local_irq_restore(&flags);                                                5 | (85) call pc+4

Suggestion:
  Move the call outside the critical section, or use a non-sleepable function.

processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
