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
3: (85) call bpf_local_irq_save#62664         ; fp-8=ffffffff refs=1
; helper_a(0); @ case.c:499
4: (b4) w1 = 0                        ; R1=0 refs=1
5: (85) call pc+4
sleepable global function helper_a() called in IRQ-disabled region
processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
