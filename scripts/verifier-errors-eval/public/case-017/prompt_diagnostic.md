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

SEC("?tc")
int entry(struct __sk_buff *ctx)
{
	unsigned long flags1, flags2;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_save(&flags2);
	bpf_local_irq_restore(&flags1);
	bpf_local_irq_restore(&flags2);
	return 0;
}
```

Verifier log:
```text
0: R1=ctx() R10=fp0
; int entry(struct __sk_buff *ctx) @ case.c:241
0: (bf) r6 = r10                      ; R6=fp0 R10=fp0
1: (07) r6 += -8                      ; R6=fp-8
; bpf_local_irq_save(&flags1); @ case.c:246
2: (bf) r1 = r6                       ; R1=fp-8 R6=fp-8
3: (85) call bpf_local_irq_save#62776         ; fp-8=ffffffff refs=1
4: (bf) r7 = r10                      ; R7=fp0 R10=fp0 refs=1
5: (07) r7 += -16                     ; R7=fp-16 refs=1
; bpf_local_irq_save(&flags2); @ case.c:247
6: (bf) r1 = r7                       ; R1=fp-16 R7=fp-16 refs=1
7: (85) call bpf_local_irq_save#62776         ; fp-16=ffffffff refs=1,2
; bpf_local_irq_restore(&flags1); @ case.c:248
8: (bf) r1 = r6                       ; R1=fp-8 R6=fp-8 refs=1,2
9: (85) call bpf_local_irq_restore#62775
cannot restore irq state out of order, expected id=2 acquired at insn_idx=7

Verification failed: Resource Lifetime Safety: IRQ flag restore out of order

Reason:
  IRQ-disabled regions must be restored in last-in, first-out order, but this restore does not match the currently
  active IRQ flag.

At:
  entry @ case.c:248:2
      246 |         bpf_local_irq_save(&flags1);                                                  7 | (85) call bpf_local_irq_save#62776
      247 |         bpf_local_irq_save(&flags2);                                                  8 | (bf) r1 = r6
  >>> 248 |         bpf_local_irq_restore(&flags1);                                          >>>  9 | (85) call bpf_local_irq_restore#62775
          |         ^-- error: IRQ flag restore out of order
      249 |         bpf_local_irq_restore(&flags2);                                              10 | (bf) r1 = r7
      250 |         return 0;                                                                    11 | (85) call bpf_local_irq_restore#62775

Suggestion:
  Restore nested IRQ flags in the reverse order they were saved.

processed 10 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
```
