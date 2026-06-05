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
