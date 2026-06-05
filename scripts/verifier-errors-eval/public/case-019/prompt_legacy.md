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
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint")
__naked void entry(void)
{
	asm volatile ("					\
	r1 = 0;						\
	call helper_a;					\
	exit;						\
"	::: __clobber_all);
}

static __naked __noinline __attribute__((used))
void helper_a(void)
{
	asm volatile ("					\
	r1 += 1;					\
	r0 = r1;					\
	if r1 < 4 goto l0_%=;				\
	exit;						\
l0_%=:	call helper_a;					\
	exit;						\
"	::: __clobber_all);
}
```

Verifier log:
```text
recursive call from helper_a() to helper_a()
processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
