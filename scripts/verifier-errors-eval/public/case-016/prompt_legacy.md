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

SEC("tc")
__naked void entry(void)
{
	asm volatile ("					\
	r2 = *(u32*)(r1 + %[data]);			\
	r3 = *(u32*)(r1 + %[data_end]);			\
	r0 = r2;					\
	r0 += 16;					\
	if r0 <= r3 goto l0_%=;				\
	exit;						\
l0_%=:	r6 = *(u32*)(r2 + %[mark]);			\
	r2 = 0;						\
	*(u32*)(r10 -8) = r2;				\
	*(u64*)(r10 -16) = r2;				\
	*(u64*)(r10 -24) = r2;				\
	*(u64*)(r10 -32) = r2;				\
	*(u64*)(r10 -40) = r2;				\
	*(u64*)(r10 -48) = r2;				\
	r2 = r10;					\
	r2 += -48;					\
	r3 = 36;					\
	r4 = 0;						\
	r5 = 0;						\
	call %[bpf_sk_lookup_tcp];			\
	if r6 == 0 goto l1_%=;				\
	exit;						\
l1_%=:	if r0 == 0 goto l2_%=;				\
	r1 = r0;					\
	call %[bpf_sk_release];				\
l2_%=:	exit;						\
"	:
	: __imm(bpf_sk_lookup_tcp),
	  __imm(bpf_sk_release),
	  __imm_const(data, offsetof(struct __sk_buff, data)),
	  __imm_const(data_end, offsetof(struct __sk_buff, data_end)),
	  __imm_const(mark, offsetof(struct __sk_buff, mark))
	: __clobber_all);
}
```

Verifier log:
```text
0: R1=ctx() R10=fp0
; asm volatile ("					\ @ case.c:486
0: (61) r2 = *(u32 *)(r1 +76)         ; R1=ctx() R2=pkt(r=0)
1: (61) r3 = *(u32 *)(r1 +80)         ; R1=ctx() R3=pkt_end()
2: (bf) r0 = r2                       ; R0=pkt(r=0) R2=pkt(r=0)
3: (07) r0 += 16                      ; R0=pkt(r=0,imm=16)
4: (bd) if r0 <= r3 goto pc+1 6: R1=ctx() R2=pkt(r=16) R10=fp0
6: (61) r6 = *(u32 *)(r2 +8)          ; R2=pkt(r=16) R6=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
7: (b7) r2 = 0                        ; R2=0
8: (63) *(u32 *)(r10 -8) = r2         ; R2=0 R10=fp0 fp-8=????0
9: (7b) *(u64 *)(r10 -16) = r2        ; R2=0 R10=fp0 fp-16=0
10: (7b) *(u64 *)(r10 -24) = r2       ; R2=0 R10=fp0 fp-24=0
11: (7b) *(u64 *)(r10 -32) = r2       ; R2=0 R10=fp0 fp-32=0
12: (7b) *(u64 *)(r10 -40) = r2       ; R2=0 R10=fp0 fp-40=0
13: (7b) *(u64 *)(r10 -48) = r2       ; R2=0 R10=fp0 fp-48=0
14: (bf) r2 = r10                     ; R2=fp0 R10=fp0
15: (07) r2 += -48                    ; R2=fp-48
16: (b7) r3 = 36                      ; R3=36
17: (b7) r4 = 0                       ; R4=0
18: (b7) r5 = 0                       ; R5=0
19: (85) call bpf_sk_lookup_tcp#84    ; R0=sock_or_null(id=2) refs=2
20: (15) if r6 == 0x0 goto pc+1       ; R6=scalar(smin=umin=umin32=1,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) refs=2
21: (95) exit
Unreleased reference id=2 alloc_insn=19
BPF_EXIT instruction in main prog would lead to reference leak
processed 22 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
```
