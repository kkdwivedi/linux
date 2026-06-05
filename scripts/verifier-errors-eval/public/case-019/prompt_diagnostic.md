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

Verification failed: Program Structure: Recursive subprogram call

Reason:
  This bpf2bpf call would make the subprogram call graph recursive. The verifier requires a finite, acyclic call graph
  so it can bound stack depth and analysis.

At:
  helper_a @ case.c:154:2
      152 | ...                                                                                  5 | (a5) if r1 < 0x4 goto pc+1
      153 | ...                                                                                  6 | (95) exit
  >>> 154 |         asm volatile ("                                 \                        >>> 7 | (85) call pc-5
          |         ^-- error: recursive subprogram call
      155 | ...                                                                                  8 | (95) exit
      156 | ...

Suggestion:
  Rewrite the recursion as an explicit bounded loop, or split the logic so subprogram calls do not form a cycle.

processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
