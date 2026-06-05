#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("kprobe")
__naked void entry(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_coarse_ns];		\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_ktime_get_coarse_ns)
	: __clobber_all);
}
