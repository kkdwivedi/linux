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

struct bpf_res_spin_lock lock_a __hidden SEC(".data.A");
struct bpf_res_spin_lock lock_b __hidden SEC(".data.B");

SEC("?tc")
int entry(struct __sk_buff *ctx)
{
	if (bpf_res_spin_lock(&lock_a))
		return 0;
	if (bpf_res_spin_lock(&lock_b)) {
		bpf_res_spin_unlock(&lock_a);
		return 0;
	}
	bpf_res_spin_unlock(&lock_a);
	bpf_res_spin_unlock(&lock_b);
	return 0;
}
```

Verifier log:
```text
0: R1=ctx() R10=fp0
; if (bpf_res_spin_lock(&lock_a)) @ case.c:181
0: (18) r1 = 0xffff888105e0be00       ; R1=map_value(map=.data.OO1,ks=4,vs=4)
2: (85) call bpf_res_spin_lock#63558          ; R0=0
3: (56) if w0 != 0x0 goto pc+11       ; R0=0
; if (bpf_res_spin_lock(&lock_b)) { @ case.c:183
4: (18) r1 = 0xffff888105e0c200       ; R1=map_value(map=.data.OO2,ks=4,vs=4)
6: (85) call bpf_res_spin_lock#63558          ; R0=0
7: (bc) w6 = w0                       ; R0=0 R6=0
8: (18) r1 = 0xffff888105e0be00       ; R1=map_value(map=.data.OO1,ks=4,vs=4)
10: (85) call bpf_res_spin_unlock#63560
bpf_res_spin_unlock cannot be out of order

Verification failed: Resource Lifetime Safety: Unlock out of order

Reason:
  Locks must be released in last-in, first-out order, but this unlock does not match the currently active lock.

At:
  entry @ case.c:183:6
      181 |         if (bpf_res_spin_lock(&lock_a))                                                8 | (18) r1 = 0xffff888105e0be00
      182 | ...
  >>> 183 |         if (bpf_res_spin_lock(&lock_b)) {                                         >>> 10 | (85) call bpf_res_spin_unlock#63560
          |         ^-- error: unlock out of order
      184 | ...                                                                                  11 | (56) if w6 != 0x0 goto pc+3
      185 | ...                                                                                  12 | (18) r1 = 0xffff888105e0c200

Suggestion:
  Release nested locks in the reverse order they were acquired.

processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
