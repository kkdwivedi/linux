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

struct value {
	__u32 offset;
	__u8 data[44];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, struct value);
} map_a SEC(".maps");

SEC("tracepoint")
__naked void entry(void)
{
	asm volatile ("					\
	r2 = r10;					\
	r2 += -8;					\
	r1 = 0;						\
	*(u64*)(r2 + 0) = r1;				\
	r1 = %[map_a] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = r0;					\
	r3 = *(u32*)(r0 + 0);				\
	r1 += r3;					\
	r2 = 1;						\
	r3 = 0;						\
	call %[bpf_probe_read_kernel];			\
l0_%=:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_probe_read_kernel),
	  __imm_addr(map_a)
	: __clobber_all);
}
```

Verifier log:
```text
0: R1=ctx() R10=fp0
; asm volatile ("					\ @ case.c:627
0: (bf) r2 = r10                      ; R2=fp0 R10=fp0
1: (07) r2 += -8                      ; R2=fp-8
2: (b7) r1 = 0                        ; R1=0
3: (7b) *(u64 *)(r2 +0) = r1          ; R1=0 R2=fp-8 fp-8=0
4: (18) r1 = 0xffff888106ef7000       ; R1=map_ptr(map=map_a,ks=8,vs=48)
6: (85) call bpf_map_lookup_elem#1    ; R0=map_value_or_null(id=1,map=map_a,ks=8,vs=48)
7: (15) if r0 == 0x0 goto pc+6        ; R0=map_value(id=1,map=map_a,ks=8,vs=48)
8: (bf) r1 = r0                       ; R0=map_value(id=1,map=map_a,ks=8,vs=48) R1=map_value(id=1,map=map_a,ks=8,vs=48)
9: (61) r3 = *(u32 *)(r0 +0)          ; R0=map_value(id=1,map=map_a,ks=8,vs=48) R3=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
10: (0f) r1 += r3                     ; R1=map_value(id=1,map=map_a,ks=8,vs=48,smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R3=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
11: (b7) r2 = 1                       ; R2=1
12: (b7) r3 = 0                       ; R3=0
13: (85) call bpf_probe_read_kernel#113
R1 unbounded memory access, make sure to bounds check any such access
processed 13 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```
