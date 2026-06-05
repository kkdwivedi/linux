#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__noinline long helper_b(struct __sk_buff *sk, __u32 len)
{
	return bpf_skb_pull_data(sk, len);
}

__noinline long helper_a(struct __sk_buff *sk, __u32 len)
{
	return helper_b(sk, len);
}

SEC("tc")
int entry(struct __sk_buff *sk)
{
	int *p = (void *)(long)sk->data;

	if ((void *)(p + 1) > (void *)(long)sk->data_end)
		return TCX_DROP;
	helper_a(sk, 0);
	*p = 42;
	return TCX_PASS;
}
