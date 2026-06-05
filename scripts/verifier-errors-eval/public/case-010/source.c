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
