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

__attribute__((noinline))
int helper_a(struct __sk_buff *skb)
{
	return skb->len;
}

int helper_c(int val, struct __sk_buff *skb);

__attribute__((noinline))
int helper_b(int val, struct __sk_buff *skb)
{
	return helper_a(skb) + helper_c(val, skb + 1);
}

__attribute__((noinline))
int helper_c(int val, struct __sk_buff *skb)
{
	return skb->ifindex * val;
}

SEC("tc")
int entry(struct __sk_buff *skb)
{
	return helper_a(skb) + helper_b(2, skb) + helper_c(3, skb);
}
```

Verifier log:
```text
Func#1 ('helper_a') is safe for any args that match its prototype
Validating helper_b() func#2...
16: R1=scalar() R2=ctx() R10=fp0
; int helper_b(int val, struct __sk_buff *skb) @ case.c:17
16: (bf) r6 = r2                      ; R2=ctx() R6=ctx()
17: (bc) w7 = w1                      ; R1=scalar() R7=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
; return helper_a(skb) + helper_c(val, skb + 1);  @ case.c:19
18: (bf) r1 = r6                      ; R1=ctx() R6=ctx()
19: (85) call pc-6
Func#1 ('helper_a') is global and assumed valid.
20: R0=scalar()
20: (bc) w8 = w0                      ; R0=scalar() R8=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
21: (07) r6 += 192                    ; R6=ctx(imm=192)
22: (bc) w1 = w7                      ; R1=scalar(id=2,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R7=scalar(id=2,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
23: (bf) r2 = r6                      ; R2=ctx(imm=192)
24: (85) call pc+2
dereference of modified ctx ptr R2 off=192 disallowed
Caller passes invalid args into func#3 ('helper_c')
processed 25 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 0
```
