#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_STACK 260

static __attribute__((noinline))
int helper_a(int val, struct __sk_buff *skb)
{
	asm volatile ("");
	return skb->len;
}

__attribute__((noinline))
int helper_b(struct __sk_buff *skb)
{
	volatile char buf[MAX_STACK] = {};
	__sink(buf[MAX_STACK - 1]);
	return helper_a(0, skb) + skb->len;
}

int helper_d(int val, struct __sk_buff *skb, int arg);

__attribute__((noinline))
int helper_c(int val, struct __sk_buff *skb)
{
	volatile char buf[MAX_STACK] = {};
	__sink(buf[MAX_STACK - 1]);
	return helper_b(skb) + helper_d(val, skb, 1);
}

__attribute__((noinline))
int helper_d(int val, struct __sk_buff *skb, int arg)
{
	volatile char buf[MAX_STACK] = {};
	__sink(buf[MAX_STACK - 1]);
	return skb->ifindex * val * arg;
}

SEC("tc")
int entry(struct __sk_buff *skb)
{
	return helper_a(1, skb) + helper_b(skb) + helper_c(2, skb) + helper_d(3, skb, 4);
}
