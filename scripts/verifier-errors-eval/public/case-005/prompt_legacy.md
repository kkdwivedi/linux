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

SEC("?fentry.s/sys_getpgid")
int entry(void *ctx)
{
	u32 data;

	bpf_preempt_disable();
	bpf_copy_from_user(&data, sizeof(data), NULL);
	bpf_preempt_enable();
	return 0;
}
```

Verifier log:
```text
arg#0 reference type('UNKNOWN ') size cannot be determined: -22
0: R1=ctx() R10=fp0
; bpf_preempt_disable(); @ case.c:112
0: (85) call bpf_preempt_disable#63228        ;
1: (bf) r1 = r10                      ; R1=fp0 R10=fp0
2: (07) r1 += -4                      ; R1=fp-4
; bpf_copy_from_user(&data, sizeof(data), NULL); @ case.c:113
3: (b4) w2 = 4                        ; R2=4
4: (b7) r3 = 0                        ; R3=0
5: (85) call bpf_copy_from_user#148
sleepable helper bpf_copy_from_user#148 in non-preemptible region
processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
