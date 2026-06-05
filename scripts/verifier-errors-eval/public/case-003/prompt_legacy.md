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

SEC("socket")
__naked void entry(void)
{
	asm volatile ("					\
	*(u64*)(r10 - 8) = r1;				\
	r0 = 0x23;					\
	*(u8*)(r10 - 7) = r0;				\
	r0 = *(u64*)(r10 - 8);				\
	r0 = *(u64*)(r0 + 8);				\
	exit;						\
"	::: __clobber_all);
}
```

Verifier log:
```text
0: R1=ctx() R10=fp0
; asm volatile ("					\ @ case.c:128
0: (7b) *(u64 *)(r10 -8) = r1         ; R1=ctx() R10=fp0 fp-8=ctx()
1: (b7) r0 = 35                       ; R0=35
2: (73) *(u8 *)(r10 -7) = r0          ; R0=35 R10=fp0 fp-8=mmmmmmmm
3: (79) r0 = *(u64 *)(r10 -8)         ; R0=scalar() R10=fp0 fp-8=mmmmmmmm
4: (79) r0 = *(u64 *)(r0 +8)
R0 invalid mem access 'scalar'
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
